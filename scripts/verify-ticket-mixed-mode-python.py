#!/usr/bin/env python3
"""Independent oracle for the real mixed-mode CLI differential."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path


def load_base_oracle():
    path = Path(__file__).with_name("verify-ticket-utxo-python.py")
    spec = importlib.util.spec_from_file_location("ticket_base_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ticket = load_base_oracle()
VerificationError = ticket.VerificationError


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def rendered_sha(value):
    encoded = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    return hashlib.sha256(encoded).hexdigest()


def classify(kinds, outcome_count):
    kinds = set(kinds)
    if "execute" in kinds:
        return "TICKETED_EXECUTION"
    if outcome_count and kinds.intersection({"transfer", "revoke"}):
        return "MIXED_LEGACY_OUTCOME_WITH_MUTATION"
    if outcome_count:
        return "LEGACY_OUTCOME_WITHOUT_EXECUTE"
    if "revoke" in kinds:
        return "REVOKED_WITHOUT_EXECUTION"
    if kinds == {"mint"}:
        return "MINTED_WITHOUT_EXECUTION"
    return "OTHER_NO_EXECUTION"


def classify_state(state):
    derived = ticket.validate_outer(state)
    require(derived is not None, "expected v5 state")
    kinds = [tx["kind"]["kind"] for tx in derived["transactions"].values()]
    return classify(kinds, len(state["receipts"]) + len(state["dead_letters"])), derived


def self_test():
    base = ticket.self_test()
    known = [
        (["mint"], 0, "MINTED_WITHOUT_EXECUTION"),
        (["mint", "execute"], 2, "TICKETED_EXECUTION"),
        (["mint", "transfer"], 2, "MIXED_LEGACY_OUTCOME_WITH_MUTATION"),
        (["mint", "revoke"], 0, "REVOKED_WITHOUT_EXECUTION"),
        (["mint"], 2, "LEGACY_OUTCOME_WITHOUT_EXECUTE"),
    ]
    for kinds, outcomes, expected in known:
        require(classify(kinds, outcomes) == expected, "mixed classification known answer")
    return {"base": base, "mixed_known_answers": len(known)}


def case_map(report):
    cases = {case["name"]: case for case in report["cases"]}
    require(len(cases) == len(report["cases"]), "duplicate case")
    return cases


def verify_report(report):
    require(report["schema_version"] == "asfa-ticket-mixed-mode-differential/v1", "schema")
    require(report["result_status"] == "EXECUTED_AWAITING_INDEPENDENT_ORACLE", "runner claimed verdict")
    for key, expected in ticket.FIXED.items():
        require(report["source"][key] == expected, f"fixture drift: {key}")
    cases = case_map(report)
    require(set(cases) == {
        "legacy_v4_control", "mixed_transfer_self", "mixed_revoke",
        "standalone_mutations", "mint_setup",
    }, "case set")
    binary_hashes = {
        "old": report["source"]["old_binary_sha256"],
        "new": report["source"]["new_binary_sha256"],
    }
    for case in cases.values():
        for step in case["steps"]:
            require(step["binary_sha256"] == binary_hashes[step["role"]], "step binary identity")

    legacy = cases["legacy_v4_control"]
    for role in ["old", "new"]:
        item = legacy["observations"][role]
        require(item["state_sha256"] == ticket.FIXED["fixed_state_sha256"], "legacy state")
        require(item["plan_sha256"] == ticket.FIXED["fixed_plan_sha256"], "legacy plan")
        require(item["execution_sha256"] == ticket.FIXED["fixed_execution_sha256"], "legacy report")
        require(item["state_matches_fixture"] and item["plan_matches_fixture"] and item["execution_matches_fixture"], "legacy comparison")

    mint = cases["mint_setup"]
    require(mint["old_state"] == mint["new_state"], "mint states differ")
    mint_class, _ = classify_state(mint["new_state"])
    require(mint_class == "MINTED_WITHOUT_EXECUTION", "mint class")

    for name, mutation in [("mixed_transfer_self", "transfer"), ("mixed_revoke", "revoke")]:
        case = cases[name]
        old_state = case["old_mixed_state"]
        require(rendered_sha(old_state) == case["old_mixed_state_sha256"], "old mixed state hash")
        old_class, old_derived = classify_state(old_state)
        require(old_class == "MIXED_LEGACY_OUTCOME_WITH_MUTATION", "old history is not mixed")
        kinds = [tx["kind"]["kind"] for tx in old_derived["transactions"].values()]
        require(mutation in kinds and "execute" not in kinds, "old transaction kinds")
        require(len(old_state["receipts"]) == 2 and len(old_state["dead_letters"]) == 5, "old outcomes")
        recovery = case["old_recovery"]
        require(recovery["exit_code"] == 2 and recovery["outputs_absent"], "old recovery accepted")
        require(recovery["state_unchanged"] and recovery["state_sha256_after_recovery"] == case["old_mixed_state_sha256"], "old recovery state")
        expected_error = "missing or conflicting outcome" if mutation == "transfer" else "not live"
        require(expected_error in recovery["stderr"], "old recovery rejected for wrong reason")
        adoption = case["old_timestamp_matched_adoption"]
        if mutation == "transfer":
            require(adoption is not None and adoption["exit_code"] == 0, "timestamp anomaly missing")
            adopted_class, adopted = classify_state(adoption["final_state"])
            require(adopted_class == "TICKETED_EXECUTION", "adoption did not append Execute")
            require(ticket.transaction_counts(adopted) == {"mint": 1, "transfer": 1, "execute": 1, "revoke": 0}, "adoption counts")
        else:
            require(adoption is None, "revoke unexpectedly adopted outcomes")
            root_id = next(t["ticket_id"] for t in old_derived["tickets"].values() if t["body"]["kind"] == "control")
            require(root_id in old_derived["spent"], "revoke root remains unspent")

        rejection = case["new_rejection"]
        require(rejection["exit_code"] == 2 and rejection["outputs_absent"], "fixed mixed call accepted")
        require("cannot be combined with --execute-wave" in rejection["stderr"], "fixed rejection reason")
        require(rendered_sha(rejection["rejected_state"]) == rejection["state_sha256"], "rejected state hash")
        require(rejection["rejected_state"] == mint["new_state"], "fixed rejection changed Mint state")
        rejected_class, _ = classify_state(rejection["rejected_state"])
        require(rejected_class == "MINTED_WITHOUT_EXECUTION", "rejected state class")

        normal_class, normal = classify_state(case["new_normal_state"])
        require(normal_class == "TICKETED_EXECUTION", "normal ticketed execution failed semantically")
        require(ticket.transaction_counts(normal) == {"mint": 1, "transfer": 0, "execute": 1, "revoke": 0}, "normal counts")
        require(len(case["new_normal_state"]["receipts"]) == 2 and len(case["new_normal_state"]["dead_letters"]) == 5, "normal outcomes")
        require(rendered_sha(case["new_normal_state"]) == case["new_normal_state_sha256"], "normal state hash")
        require(case["new_replay_state_sha256"] == case["new_normal_state_sha256"], "replay mutated state")
        replay = case["new_replay_operation"]
        require(replay["replayed"] and replay["transaction"] is None, "replay transaction")

    standalone_class, standalone = classify_state(cases["standalone_mutations"]["final_state"])
    require(standalone_class == "REVOKED_WITHOUT_EXECUTION", "standalone mutation class")
    require(ticket.transaction_counts(standalone) == {"mint": 1, "transfer": 1, "execute": 0, "revoke": 1}, "standalone counts")
    return {
        "case_count": len(cases),
        "process_steps": sum(len(case["steps"]) for case in cases.values()),
        "old_mixed_histories": 2,
        "fixed_rejections": 2,
        "timestamp_matched_transfer_adoption": "CONFIRMED_ANOMALY_NOT_PERMANENT_LOSS",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    parser.add_argument("--out")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test_result = self_test()
    if not args.report:
        print(json.dumps({"self_test": "PASS", **self_test_result}))
        return
    report = ticket.load(args.report)
    forged = copy.deepcopy(report)
    cases = case_map(forged)
    forged_case = cases["mixed_transfer_self"]
    replacement = copy.deepcopy(cases["mixed_transfer_self"]["new_normal_state"])
    forged_case["old_mixed_state"] = replacement
    forged_case["old_mixed_state_sha256"] = rendered_sha(replacement)
    forged_case["old_recovery"]["state_sha256_after_recovery"] = rendered_sha(replacement)
    try:
        verify_report(forged)
        raise VerificationError("forged real report accepted")
    except VerificationError as error:
        require("old history is not mixed" in str(error), "forged report rejected for wrong reason")
    result = verify_report(report)
    output = {
        "schema_version": "asfa-ticket-mixed-mode-consistency/v1",
        "verdict": "PASS",
        "self_test": self_test_result,
        "forged_real_report": "REJECTED_BEFORE_ACCEPTANCE",
        "differential_report_sha256": hashlib.sha256(Path(args.report).read_bytes()).hexdigest(),
        **result,
        "boundary": "Independent local CLI composition and snapshot-history oracle. Legacy execution without ticket mutation remains supported; no authentication, consensus, ZK, CI, federation, or distributed exactly-once claim.",
    }
    rendered = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
