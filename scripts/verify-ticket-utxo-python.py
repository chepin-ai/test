#!/usr/bin/env python3
"""Independent task-ticket ledger and real-CLI differential oracle."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

TICKET_DOMAIN = "asfa.task-ticket.id.v1"
TX_DOMAIN = "asfa.task-ticket-transaction.id.v1"
TICKET_LEDGER_DOMAIN = "asfa.task-ticket-ledger.digest.v1"
INPUT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-INPUT/V1\n"
OUTPUT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-OUTPUT/V1\n"
RECEIPT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-RECEIPT/V1\n"
DEAD_DOMAIN = b"ASFA-OS-XI/QFOS-DEAD-LETTER/V1\n"
FIXED = {
    "pre_state_sha256": "702ec095d0c529d654c9d5585efada2fd8885b40b2a67e03b8a23b014449bd7a",
    "fixed_plan_sha256": "cdc6cd33bcc3e155dfab134759dc0c603a3a9f740f490b63ab642f7462fdf718",
    "fixed_state_sha256": "ceafc719fd670a0b418afefb7230fa040494756b853e5d382eb4f7aebec202a5",
    "fixed_execution_sha256": "5b394e59c96fcf6762bca8ac4f6322c86ec3cdf8b9f909fcb74acf5693df72de",
}
FIXED_PLAN_HASH = "f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a"


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise VerificationError(f"non-finite number: {value}")


def load(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    reject_floats(value)
    return value


def reject_floats(value):
    if isinstance(value, float):
        raise VerificationError("floating point is outside the profile")
    if isinstance(value, list):
        for item in value:
            reject_floats(item)
    elif isinstance(value, dict):
        for item in value.values():
            reject_floats(item)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def sorted_value(value):
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False))


def digest(domain, projection):
    if isinstance(domain, str):
        domain = domain.encode()
    return hashlib.sha256(domain + compact(projection)).hexdigest()


def sorted_digest(domain, projection):
    encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(domain + encoded).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def job_projection(job):
    result = {
        "session": job["session"],
        "id": job["id"],
        "action": job["action"],
        "payload": sorted_value(job["payload"]),
    }
    if job.get("expires_epoch") is not None:
        result["expires_epoch"] = job["expires_epoch"]
    return result


def body_projection(body):
    if body["kind"] == "control":
        return {"kind": "control", "nonce": body["nonce"], "plan_hash": body["plan_hash"]}
    if body["kind"] == "execute":
        return {"kind": "execute", "job": job_projection(body["job"]), "plan_hash": body["plan_hash"]}
    raise VerificationError("unknown ticket body")


def ticket_projection(ticket):
    return {
        "parent_id": ticket["parent_id"],
        "root_id": ticket["root_id"],
        "recipient": ticket["recipient"],
        "body": body_projection(ticket["body"]),
        "created_at_epoch": ticket["created_at_epoch"],
        "sequence": ticket["sequence"],
    }


def full_ticket_projection(ticket):
    return {
        "ticket_id": ticket["ticket_id"],
        **ticket_projection(ticket),
    }


def kind_projection(kind):
    if kind["kind"] == "execute":
        return {"kind": "execute", "plan_hash": kind["plan_hash"]}
    if kind["kind"] in {"mint", "transfer", "revoke"}:
        return {"kind": kind["kind"]}
    raise VerificationError("unknown transaction kind")


def tx_projection(transaction):
    return {
        "actor": transaction["actor"],
        "kind": kind_projection(transaction["kind"]),
        "inputs": transaction["inputs"],
        "outputs": transaction["outputs"],
        "created_at_epoch": transaction["created_at_epoch"],
    }


def full_tx_projection(transaction):
    return {"transaction_id": transaction["transaction_id"], **tx_projection(transaction)}


def ticket_id(ticket):
    return digest(TICKET_DOMAIN, ticket_projection(ticket))


def transaction_id(transaction):
    return digest(TX_DOMAIN, tx_projection(transaction))


def ticket_snapshot_projection(snapshot):
    return {
        "schema_version": snapshot["schema_version"],
        "network_name": snapshot["network_name"],
        "policy_hash": snapshot["policy_hash"],
        "root_ticket_limit": snapshot["root_ticket_limit"],
        "tickets": [full_ticket_projection(t) for t in sorted(snapshot["tickets"], key=lambda t: t["ticket_id"])],
        "transactions": [full_tx_projection(t) for t in sorted(snapshot["transactions"], key=lambda t: t["transaction_id"])],
    }


def ticket_ledger_digest(snapshot):
    return digest(TICKET_LEDGER_DOMAIN, ticket_snapshot_projection(snapshot))


def validate_ticket_snapshot(snapshot):
    require(snapshot["schema_version"] == "asfa-task-ticket-ledger/v1", "ticket schema")
    require(snapshot["network_name"].strip() and valid_hash(snapshot["policy_hash"]), "ticket registry binding")
    limit = snapshot["root_ticket_limit"]
    require(1 <= limit <= 64, "root limit")
    require(len(snapshot["tickets"]) <= 4096 and len(snapshot["transactions"]) <= 16384, "ticket capacity")
    tickets = {}
    for ticket in snapshot["tickets"]:
        identifier = ticket["ticket_id"]
        require(identifier not in tickets, "duplicate ticket id")
        require(ticket_id(ticket) == identifier, f"ticket id mismatch: {identifier}")
        require(ticket["recipient"].strip() and valid_hash(ticket["body"]["plan_hash"]), "ticket recipient/plan")
        tickets[identifier] = ticket
    transactions = {}
    for transaction in snapshot["transactions"]:
        identifier = transaction["transaction_id"]
        require(identifier not in transactions, "duplicate transaction id")
        require(transaction_id(transaction) == identifier, f"transaction id mismatch: {identifier}")
        require(transaction["actor"].strip(), "empty transaction actor")
        require(len(set(transaction["inputs"])) == len(transaction["inputs"]), "duplicate tx input")
        require(len(set(transaction["outputs"])) == len(transaction["outputs"]), "duplicate tx output")
        transactions[identifier] = transaction

    job_roots = {}
    job_bases = {}
    root_sequences = {}
    for ticket in tickets.values():
        body = ticket["body"]
        root_key = ticket["root_id"] or ticket["ticket_id"]
        root_sequences.setdefault(root_key, []).append(ticket["sequence"])
        if body["kind"] == "control":
            require(ticket["parent_id"] is None and ticket["root_id"] is None and ticket["sequence"] == 0, "control shape")
            require(body["nonce"].strip(), "empty root nonce")
            continue
        require(ticket["parent_id"] is not None and ticket["root_id"] is not None and ticket["sequence"] > 0, "execute lineage")
        root = tickets.get(ticket["root_id"])
        parent = tickets.get(ticket["parent_id"])
        require(root is not None and root["body"]["kind"] == "control", "missing root")
        require(root["body"]["plan_hash"] == body["plan_hash"], "root plan mismatch")
        require(parent is not None and parent["sequence"] < ticket["sequence"], "parent sequence")
        require(parent["created_at_epoch"] <= ticket["created_at_epoch"], "parent timestamp")
        job = body["job"]
        require(job["session"].strip() and job["id"].strip(), "empty job")
        key = (job["session"], job["id"])
        if key in job_roots:
            require(job_roots[key] == ticket["root_id"], "job appears in multiple roots")
        job_roots[key] = ticket["root_id"]
        if ticket["parent_id"] == ticket["root_id"]:
            job_bases[key] = job_bases.get(key, 0) + 1
        else:
            require(parent["body"]["kind"] == "execute" and parent["body"]["job"] == job, "cross-job parent")
    require(set(job_bases) == set(job_roots) and all(count == 1 for count in job_bases.values()), "job must have one mint base")
    for root, sequences in root_sequences.items():
        require(sorted(sequences) == list(range(len(sequences))), f"non-contiguous root: {root}")
        require(len(sequences) <= limit, "root budget")

    spent = {}
    created = {}
    for transaction in transactions.values():
        for identifier in transaction["inputs"]:
            require(identifier in tickets, "missing tx input")
            require(identifier not in spent, "double spend")
            require(tickets[identifier]["created_at_epoch"] <= transaction["created_at_epoch"], "tx predates input")
            spent[identifier] = transaction["transaction_id"]
        for identifier in transaction["outputs"]:
            require(identifier in tickets, "missing tx output")
            require(identifier not in created, "output created twice")
            require(tickets[identifier]["created_at_epoch"] == transaction["created_at_epoch"], "output timestamp")
            created[identifier] = transaction["transaction_id"]
        kind = transaction["kind"]["kind"]
        if kind == "mint":
            require(not transaction["inputs"] and len(transaction["outputs"]) >= 2, "mint shape")
            root = tickets[transaction["outputs"][0]]
            require(root["body"]["kind"] == "control" and root["recipient"] == transaction["actor"], "mint controller")
            for index, identifier in enumerate(transaction["outputs"][1:], 1):
                ticket = tickets[identifier]
                require(ticket["body"]["kind"] == "execute", "mint output kind")
                require(ticket["parent_id"] == root["ticket_id"] and ticket["root_id"] == root["ticket_id"], "mint lineage")
                require(ticket["sequence"] == index and ticket["body"]["plan_hash"] == root["body"]["plan_hash"], "mint sequence/plan")
            require(len(transaction["outputs"]) <= limit, "mint budget")
        elif kind == "transfer":
            require(len(transaction["inputs"]) == 1 and len(transaction["outputs"]) == 1, "transfer shape")
            parent = tickets[transaction["inputs"][0]]
            child = tickets[transaction["outputs"][0]]
            require(parent["body"]["kind"] == child["body"]["kind"] == "execute", "transfer kinds")
            require(parent["recipient"] == transaction["actor"], "transfer actor")
            require(child["parent_id"] == parent["ticket_id"] and child["root_id"] == parent["root_id"], "transfer lineage")
            require(child["body"]["job"] == parent["body"]["job"] and child["body"]["plan_hash"] == parent["body"]["plan_hash"], "transfer binding")
            require(child["sequence"] > parent["sequence"], "transfer sequence")
        elif kind == "execute":
            require(valid_hash(transaction["kind"]["plan_hash"]) and transaction["inputs"] and not transaction["outputs"], "execute shape")
            for identifier in transaction["inputs"]:
                ticket = tickets[identifier]
                require(ticket["body"]["kind"] == "execute", "execute control input")
                require(ticket["recipient"] == transaction["actor"], "execute recipient")
                require(ticket["body"]["plan_hash"] == transaction["kind"]["plan_hash"], "execute plan")
        elif kind == "revoke":
            require(len(transaction["inputs"]) == 1 and not transaction["outputs"], "revoke shape")
            root = tickets[transaction["inputs"][0]]
            require(root["body"]["kind"] == "control" and root["root_id"] is None, "revoke non-root")
            require(root["recipient"] == transaction["actor"], "revoke actor")
        else:
            raise VerificationError("unknown transaction")
    for transaction in transactions.values():
        if transaction["kind"]["kind"] not in {"transfer", "execute"}:
            continue
        for identifier in transaction["inputs"]:
            root_id = tickets[identifier]["root_id"]
            require(root_id is not None, "descendant lacks root")
            revoke_id = spent.get(root_id)
            if revoke_id is not None:
                require(
                    transactions[revoke_id]["created_at_epoch"] > transaction["created_at_epoch"],
                    "descendant transaction at or after root revocation",
                )
    require(set(created) == set(tickets), "ticket without creating transaction")
    return {"tickets": tickets, "transactions": transactions, "spent": spent, "root_sequences": root_sequences}


def without(document, field):
    return {key: value for key, value in document.items() if key != field}


def input_digest(job):
    return sorted_digest(INPUT_DOMAIN, {
        "session": job["session"], "id": job["id"], "action": job["action"],
        "payload": job["payload"], "expires_epoch": job.get("expires_epoch"),
    })


def validate_outer(state):
    schema = state["schema_version"]
    if schema == "asfa-directive-ledger/v4":
        require("tickets" not in state, "v4 contains tickets")
        derived = None
    elif schema == "asfa-directive-ledger/v5":
        require(state.get("tickets") is not None, "v5 lacks tickets")
        derived = validate_ticket_snapshot(state["tickets"])
        require(state["tickets"]["network_name"] == state["network_name"], "inner network mismatch")
        require(state["tickets"]["policy_hash"] == state["policy_hash"], "inner policy mismatch")
        require(state["tickets"]["tickets"], "empty v5 ticket ledger")
    else:
        raise VerificationError("outer schema")
    pending = set()
    for entry in state["directives"]:
        key = (entry["session"], entry["directive"]["id"])
        require(key not in pending, "duplicate pending")
        pending.add(key)
    consumed = set()
    for entry in state["consumed"]:
        key = (entry["session"], entry["id"])
        require(key not in consumed and key not in pending, "consumed duplicate/overlap")
        consumed.add(key)
    receipts = {}
    for receipt in state["receipts"]:
        key = (receipt["session"], receipt["id"])
        require(key not in receipts and key in consumed, "receipt key")
        require(receipt["output_hash"] == sorted_digest(OUTPUT_DOMAIN, receipt["output"]), "output hash")
        require(receipt["receipt_hash"] == sorted_digest(RECEIPT_DOMAIN, without(receipt, "receipt_hash")), "receipt hash")
        receipts[key] = receipt
    dead = {}
    for letter in state["dead_letters"]:
        key = (letter["session"], letter["id"])
        require(key not in dead and key in consumed and key not in receipts, "dead letter key/conflict")
        require(letter["dead_letter_hash"] == sorted_digest(DEAD_DOMAIN, without(letter, "dead_letter_hash")), "dead hash")
        dead[key] = letter
    if derived:
        for transaction in derived["transactions"].values():
            if transaction["kind"]["kind"] != "execute":
                continue
            for identifier in transaction["inputs"]:
                job = derived["tickets"][identifier]["body"]["job"]
                key = (job["session"], job["id"])
                require(key in consumed, "execute lacks tombstone")
                expected_input = input_digest(job)
                r = receipts.get(key)
                d = dead.get(key)
                rmatch = r is not None and r["action"] == job["action"] and r["plan_hash"] == transaction["kind"]["plan_hash"] and r["input_hash"] == expected_input and r["executed_at_epoch"] == transaction["created_at_epoch"]
                dmatch = d is not None and d["action"] == job["action"] and d["plan_hash"] == transaction["kind"]["plan_hash"] and d["input_hash"] == expected_input and d["failed_at_epoch"] == transaction["created_at_epoch"]
                require(rmatch != dmatch, "execute outcome missing or conflicting")
    return derived


def transaction_counts(derived):
    counts = {"mint": 0, "transfer": 0, "execute": 0, "revoke": 0}
    for transaction in derived["transactions"].values():
        counts[transaction["kind"]["kind"]] += 1
    return counts


def case_map(report):
    cases = {case["name"]: case for case in report["cases"]}
    require(len(cases) == len(report["cases"]), "duplicate case")
    return cases


def verify_report(report):
    require(report["schema_version"] == "asfa-ticket-utxo-differential/v1", "differential schema")
    require(report["result_status"] == "EXECUTED_AWAITING_INDEPENDENT_ORACLE", "runner claimed final verdict")
    for key, expected in FIXED.items():
        require(report["source"][key] == expected, f"fixture anchor drift: {key}")
    cases = case_map(report)
    require(set(cases) == {
        "legacy_v4_control", "mint_execute_replay", "old_binary_boundaries", "missing_ticket",
        "transfer_lineage", "root_revocation", "root_budget_20_21", "instruction_data_isolation",
        "corrupt_snapshot_rejection",
    }, "case set")

    legacy = cases["legacy_v4_control"]
    for label in ["old", "new"]:
        observation = legacy["observations"][label]
        require(observation["state_sha256"] == FIXED["fixed_state_sha256"], f"{label} legacy state")
        require(observation["plan_sha256"] == FIXED["fixed_plan_sha256"], f"{label} legacy plan")
        require(observation["execution_sha256"] == FIXED["fixed_execution_sha256"], f"{label} legacy execution")
        require(observation["state_matches_fixture"] and observation["plan_matches_fixture"] and observation["execution_matches_fixture"], "legacy byte comparison")
    derived = validate_outer(legacy["final_state"])
    require(derived is None and len(legacy["final_state"]["consumed"]) == 7, "legacy final shape")

    happy = cases["mint_execute_replay"]
    mint_derived = validate_outer(happy["mint_state"])
    final = validate_outer(happy["final_state"])
    require(transaction_counts(mint_derived) == {"mint": 1, "transfer": 0, "execute": 0, "revoke": 0}, "mint history")
    require(transaction_counts(final) == {"mint": 1, "transfer": 0, "execute": 1, "revoke": 0}, "happy history")
    require(len(final["tickets"]) == 8 and len(happy["final_state"]["consumed"]) == 7, "happy counts")
    require(len(happy["final_state"]["receipts"]) == 2 and len(happy["final_state"]["dead_letters"]) == 5, "happy outcomes")
    execute = [t for t in final["transactions"].values() if t["kind"]["kind"] == "execute"][0]
    require(execute["actor"] == "alice" and execute["kind"]["plan_hash"] == FIXED_PLAN_HASH and len(execute["inputs"]) == 7, "execute binding")
    require(happy["execution_sha256"] == FIXED["fixed_execution_sha256"], "ticketed execution fixture")
    replay = happy["replay_operation"]
    require(replay["replayed"] and replay["transaction"] is None and replay["transaction_count"] == 2, "replay operation")
    require(replay["ticket_ledger_hash"] == ticket_ledger_digest(happy["final_state"]["tickets"]), "replay ledger digest")
    require(happy["wrong_replay_outputs_absent"], "wrong replay outputs")
    require([s["exit_code"] for s in happy["steps"]] == [0, 2, 0, 0, 2, 2], "happy exit sequence")

    old = cases["old_binary_boundaries"]
    require([s["exit_code"] for s in old["steps"]] == [2, 2], "old binary accepted new boundary")
    missing = cases["missing_ticket"]
    require(validate_outer(missing["final_state"]) is None and len(missing["final_state"]["directives"]) == 7, "missing ticket state")
    require(missing["steps"][0]["exit_code"] == 2 and "unknown ticket" in missing["steps"][0]["stderr"], "missing ticket error")

    transfer = cases["transfer_lineage"]
    transferred = validate_outer(transfer["final_state"])
    require(len(transferred["tickets"]) == 15, "transfer ticket count")
    require(transaction_counts(transferred) == {"mint": 1, "transfer": 7, "execute": 1, "revoke": 0}, "transfer history")
    for job_id, ids in transfer["transfer_ids"].items():
        parent_tx = transferred["transactions"][transferred["spent"][ids["parent_id"]]]
        require(parent_tx["kind"]["kind"] == "transfer" and parent_tx["actor"] == "alice", "parent transfer")
        require(parent_tx["outputs"] == [ids["child_id"]], "transfer child")
        require(transferred["tickets"][ids["child_id"]]["body"]["job"]["id"] == job_id, "child job")
    execute = [t for t in transferred["transactions"].values() if t["kind"]["kind"] == "execute"][0]
    require(execute["actor"] == "bob", "transferred executor")

    revoked_case = cases["root_revocation"]
    revoked = validate_outer(revoked_case["final_state"])
    require(transaction_counts(revoked) == {"mint": 1, "transfer": 0, "execute": 0, "revoke": 1}, "revoke history")
    require(revoked["spent"][revoked_case["root_id"]] in revoked["transactions"], "root not spent")
    require(len(revoked_case["final_state"]["directives"]) == 7 and not revoked_case["final_state"]["receipts"], "revoke executed work")
    for ticket in revoked["tickets"].values():
        require(ticket["ticket_id"] in revoked["spent"] or ticket["root_id"] == revoked_case["root_id"], "live descendant after revoke")

    budget_case = cases["root_budget_20_21"]
    budget = validate_outer(budget_case["final_state"])
    require(len(budget["tickets"]) == 20 and transaction_counts(budget) == {"mint": 1, "transfer": 12, "execute": 0, "revoke": 0}, "budget counts")
    require(budget_case["steps"][-1]["exit_code"] == 2 and "budget exceeded" in budget_case["steps"][-1]["stderr"], "21st ticket accepted")
    require(budget_case["failed_tip_id"] not in budget["spent"], "failed budget consumed parent")

    prompt = cases["instruction_data_isolation"]
    prompt_derived = validate_outer(prompt["final_state"])
    require(transaction_counts(prompt_derived)["execute"] == 1 and not prompt["sentinel_exists"], "prompt dispatch")
    receipts = prompt["final_state"]["receipts"]
    require(len(receipts) == 1 and receipts[0]["action"] == "engine.sha256", "prompt action changed")
    require(receipts[0]["output"]["sha256"] == prompt["expected_sha256"] == hashlib.sha256(prompt["text"].encode()).hexdigest(), "prompt data hash")

    corrupt = cases["corrupt_snapshot_rejection"]
    require(set(corrupt["observations"]) == {
        "missing_execution_outcome", "forged_ticket_id", "v4_with_tickets", "post_revoke_execution",
    }, "corrupt case set")
    require(all(step["exit_code"] == 2 for step in corrupt["steps"]), "corrupt snapshot accepted")
    require(all(not item["report_created"] for item in corrupt["observations"].values()), "corrupt snapshot report")
    for label, item in corrupt["observations"].items():
        try:
            validate_outer(item["snapshot"])
        except VerificationError:
            pass
        else:
            raise VerificationError(f"independent oracle accepted corrupt snapshot: {label}")
    require("root revocation" in corrupt["steps"][-1]["stderr"], "post-revoke execution rejected for wrong reason")
    return {"case_count": len(cases), "process_steps": sum(len(case["steps"]) for case in cases.values())}


def synthetic_mint():
    plan_hash = "11" * 32
    root = {"ticket_id": "", "parent_id": None, "root_id": None, "recipient": "root", "body": {"kind": "control", "nonce": "known", "plan_hash": plan_hash}, "created_at_epoch": 7, "sequence": 0}
    root["ticket_id"] = ticket_id(root)
    work = {"ticket_id": "", "parent_id": root["ticket_id"], "root_id": root["ticket_id"], "recipient": "alice", "body": {"kind": "execute", "job": {"session": "s", "id": "j", "action": "engine.sum", "payload": {"values": [1, 2]}}, "plan_hash": plan_hash}, "created_at_epoch": 7, "sequence": 1}
    work["ticket_id"] = ticket_id(work)
    mint = {"transaction_id": "", "actor": "root", "kind": {"kind": "mint"}, "inputs": [], "outputs": [root["ticket_id"], work["ticket_id"]], "created_at_epoch": 7}
    mint["transaction_id"] = transaction_id(mint)
    snapshot = {"schema_version": "asfa-task-ticket-ledger/v1", "network_name": "n", "policy_hash": "22" * 32, "root_ticket_limit": 20, "tickets": sorted([root, work], key=lambda t: t["ticket_id"]), "transactions": [mint]}
    return snapshot


def self_test():
    known = {"ticket_id": "", "parent_id": None, "root_id": None, "recipient": "root", "body": {"kind": "control", "nonce": "known", "plan_hash": "00" * 32}, "created_at_epoch": 1, "sequence": 0}
    require(ticket_id(known) == "377ea67d18d4b3388dd5cc0aa49787f48af09e87af325dc386459fa80be7b489", "known ticket answer")
    known_tx = {"transaction_id": "", "actor": "root", "kind": {"kind": "mint"}, "inputs": [], "outputs": [ticket_id(known)], "created_at_epoch": 1}
    require(transaction_id(known_tx) == "67f89fb0fddc63456b31c6b5c002092e80cb51e04dcf41c35ab80d52c2a477d4", "known transaction answer")
    require(hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "known SHA-256 answer")
    valid = synthetic_mint()
    validate_ticket_snapshot(valid)
    forged = copy.deepcopy(valid)
    forged["tickets"][0]["recipient"] = "mallory"
    try:
        validate_ticket_snapshot(forged)
        raise VerificationError("forged recipient accepted")
    except VerificationError as error:
        require("ticket id mismatch" in str(error), "wrong forged-recipient rejection")
    double_base = copy.deepcopy(valid)
    root = next(t for t in double_base["tickets"] if t["body"]["kind"] == "control")
    work = next(t for t in double_base["tickets"] if t["body"]["kind"] == "execute")
    second = copy.deepcopy(work)
    second["sequence"] = 2
    second["ticket_id"] = ticket_id(second)
    double_base["tickets"].append(second)
    double_base["transactions"][0]["outputs"].append(second["ticket_id"])
    double_base["transactions"][0]["transaction_id"] = transaction_id(double_base["transactions"][0])
    try:
        validate_ticket_snapshot(double_base)
        raise VerificationError("self-consistent double base accepted")
    except VerificationError as error:
        require("one mint base" in str(error), "wrong double-base rejection")
    double_spend = copy.deepcopy(valid)
    work_id = next(t["ticket_id"] for t in double_spend["tickets"] if t["body"]["kind"] == "execute")
    for now in [8, 9]:
        tx = {"transaction_id": "", "actor": "alice", "kind": {"kind": "execute", "plan_hash": "11" * 32}, "inputs": [work_id], "outputs": [], "created_at_epoch": now}
        tx["transaction_id"] = transaction_id(tx)
        double_spend["transactions"].append(tx)
    try:
        validate_ticket_snapshot(double_spend)
        raise VerificationError("double spend accepted")
    except VerificationError as error:
        require("double spend" in str(error), "wrong double-spend rejection")
    post_revoke = copy.deepcopy(valid)
    root_id = next(t["ticket_id"] for t in post_revoke["tickets"] if t["body"]["kind"] == "control")
    work_id = next(t["ticket_id"] for t in post_revoke["tickets"] if t["body"]["kind"] == "execute")
    execute = {"transaction_id": "", "actor": "alice", "kind": {"kind": "execute", "plan_hash": "11" * 32}, "inputs": [work_id], "outputs": [], "created_at_epoch": 8}
    execute["transaction_id"] = transaction_id(execute)
    revoke = {"transaction_id": "", "actor": "root", "kind": {"kind": "revoke"}, "inputs": [root_id], "outputs": [], "created_at_epoch": 7}
    revoke["transaction_id"] = transaction_id(revoke)
    post_revoke["transactions"].extend([execute, revoke])
    try:
        validate_ticket_snapshot(post_revoke)
        raise VerificationError("post-revoke execution accepted")
    except VerificationError as error:
        require("root revocation" in str(error), "wrong post-revoke rejection")
    return {"known_answers": 3, "synthetic_valid": 1, "synthetic_rejections": 4}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    parser.add_argument("--state")
    parser.add_argument("--out")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test_result = self_test()
    if args.report and args.state:
        raise VerificationError("--report and --state are mutually exclusive")
    if args.state:
        state = load(args.state)
        forged_state = copy.deepcopy(state)
        forged_state["tickets"]["tickets"][0]["recipient"] = "mallory"
        try:
            validate_outer(forged_state)
            raise VerificationError("forged state accepted")
        except VerificationError as error:
            require("ticket id mismatch" in str(error), "forged state rejected for wrong reason")
        derived = validate_outer(state)
        require(derived is not None, "expected a v5 ticket state")
        require(transaction_counts(derived) == {"mint": 1, "transfer": 0, "execute": 1, "revoke": 0}, "state history")
        require(len(derived["tickets"]) == 8 and len(state["consumed"]) == 7, "state counts")
        output = {"schema_version": "asfa-ticket-state-verdict/v1", "verdict": "PASS", "ticket_ledger_hash": ticket_ledger_digest(state["tickets"]), "self_test": self_test_result}
        rendered = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return
    if not args.report:
        print(json.dumps({"self_test": "PASS", **self_test_result}))
        return
    report = load(args.report)
    forged_report = copy.deepcopy(report)
    happy = next(case for case in forged_report["cases"] if case["name"] == "mint_execute_replay")
    happy["final_state"]["tickets"]["tickets"][0]["recipient"] = "mallory"
    try:
        verify_report(forged_report)
        raise VerificationError("forged real report accepted")
    except VerificationError as error:
        require("ticket id mismatch" in str(error), "forged real report rejected for wrong reason")
    result = verify_report(report)
    report_sha = hashlib.sha256(Path(args.report).read_bytes()).hexdigest()
    output = {
        "schema_version": "asfa-ticket-utxo-consistency/v1",
        "verdict": "PASS",
        "self_test": self_test_result,
        "forged_real_report": "REJECTED_BEFORE_ACCEPTANCE",
        "differential_report_sha256": report_sha,
        **result,
        "boundary": "Independent integrity and local authorization oracle; not publisher authentication, consensus, ZK, or distributed exactly-once proof.",
    }
    rendered = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
