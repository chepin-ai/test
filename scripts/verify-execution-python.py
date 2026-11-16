#!/usr/bin/env python3
"""Independent qfos-exec-v1 execution and persistence oracle.

No Rust digest or output is trusted as a known answer. Built-ins and failure
classes are recomputed from the original plan. The oracle checks integrity and
local idempotent persistence, not publisher authentication, distributed
exactly-once execution, canonical QF-OS compatibility, or QIOS compatibility.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

LEDGER_DOMAIN = b"ASFA-OS-XI/DIRECTIVE-LEDGER-SNAPSHOT/V1\n"
PLAN_DOMAIN = b"ASFA-OS-XI/QFOS-WAVE-PLAN/V1\n"
POLICY_DOMAIN = b"ASFA-OS-XI/REGISTRY-POLICY/V1\n"
INPUT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-INPUT/V1\n"
OUTPUT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-OUTPUT/V1\n"
RECEIPT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-RECEIPT/V1\n"
DEAD_DOMAIN = b"ASFA-OS-XI/QFOS-DEAD-LETTER/V1\n"
REPORT_DOMAIN = b"ASFA-OS-XI/QFOS-EXECUTION-REPORT/V1\n"
DISPATCHER = "dispatcher/qfos-exec-v1"
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
UINT64_MAX = 2**64 - 1
SUM_MAX_VALUES = 1024
SHA256_MAX_UTF8_BYTES = 1024 * 1024


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    raise VerificationError(f"non-finite number is outside the profile: {value}")


def load_json(path):
    value = json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    reject_floats(value)
    return value


def reject_floats(value):
    if isinstance(value, float):
        raise VerificationError("floating point is outside the execution profile")
    if isinstance(value, list):
        for item in value:
            reject_floats(item)
    elif isinstance(value, dict):
        for item in value.values():
            reject_floats(item)


def canonical_bytes(value):
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise VerificationError(f"cannot canonicalize execution value: {error}") from error


def digest(domain, value):
    return hashlib.sha256(domain + canonical_bytes(value)).hexdigest()


def without(document, field):
    return {key: value for key, value in document.items() if key != field}


def input_digest(job):
    return digest(
        INPUT_DOMAIN,
        {
            "session": job["session"],
            "id": job["id"],
            "action": job["action"],
            "payload": job["payload"],
            "expires_epoch": job.get("expires_epoch"),
        },
    )


def refresh_receipt(receipt):
    receipt["output_hash"] = digest(OUTPUT_DOMAIN, receipt["output"])
    receipt["receipt_hash"] = digest(RECEIPT_DOMAIN, without(receipt, "receipt_hash"))


def refresh_dead_letter(dead):
    dead["dead_letter_hash"] = digest(DEAD_DOMAIN, without(dead, "dead_letter_hash"))


def refresh_report(report):
    report["execution_hash"] = digest(REPORT_DOMAIN, without(report, "execution_hash"))


def policy_digest(registry):
    sessions = {}
    for name, session in sorted(registry["sessions"].items()):
        sessions[name] = {
            "url": session["url"],
            "canonical_url": session.get("canonical_url", session["url"]),
            "trust": session.get("trust", "unsigned-hash-chain"),
            "allow_insecure_http": session.get("allow_insecure_http", False),
            "allow_file": session.get("allow_file", False),
        }
    return digest(
        POLICY_DOMAIN,
        {
            "schema_version": registry["schema_version"],
            "network_name": registry["network_name"],
            "trust_model": registry["trust_model"],
            "sessions": sessions,
        },
    )


def is_i64(value):
    return type(value) is int and INT64_MIN <= value <= INT64_MAX


def is_u64(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


def expected_outcome(job, at_epoch):
    """Return (engine, success_output_or_None, failure_code_or_None)."""
    expires = job.get("expires_epoch")
    if expires is not None and expires <= at_epoch:
        return DISPATCHER, None, "expired"
    action = job["action"]
    payload = job["payload"]
    if action == "engine.sum":
        engine = "builtin.sum/qfos-exec-v1"
        if (
            not isinstance(payload, dict)
            or set(payload) != {"values"}
            or not isinstance(payload["values"], list)
            or not all(is_i64(value) for value in payload["values"])
        ):
            return engine, None, "invalid_payload"
        values = payload["values"]
        if len(values) > SUM_MAX_VALUES:
            return engine, None, "input_limit"
        total = 0
        for value in values:
            total += value
            if not INT64_MIN <= total <= INT64_MAX:
                return engine, None, "arithmetic_overflow"
        return engine, {"count": len(values), "sum": total}, None
    if action == "engine.sha256":
        engine = "builtin.sha256/qfos-exec-v1"
        if (
            not isinstance(payload, dict)
            or set(payload) != {"text"}
            or not isinstance(payload["text"], str)
        ):
            return engine, None, "invalid_payload"
        try:
            raw = payload["text"].encode("utf-8")
        except UnicodeEncodeError:
            return engine, None, "invalid_payload"
        if len(raw) > SHA256_MAX_UTF8_BYTES:
            return engine, None, "input_limit"
        return engine, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, None
    return DISPATCHER, None, "unknown_action"


def indexed(records, label):
    result = {}
    for record in records:
        require(isinstance(record, dict), f"{label} record must be an object")
        key = (record.get("session"), record.get("id"))
        require(all(isinstance(part, str) and part for part in key), f"invalid {label} key")
        require(key not in result, f"duplicate {label}: {key}")
        result[key] = record
    return result


def verify_common(outcome, job, plan, input_hash):
    require(outcome["session"] == job["session"], "outcome session mismatch")
    require(outcome["id"] == job["id"], "outcome id mismatch")
    require(outcome["action"] == job["action"], "outcome action mismatch")
    require(outcome["plan_hash"] == plan["plan_hash"], "outcome plan binding mismatch")
    require(outcome["input_hash"] == input_hash, "outcome input binding mismatch")


def verify_execution(registry, pre_snapshot, snapshot, plan, report, closed_world=False):
    expected_policy = policy_digest(registry)
    require(snapshot["schema_version"] == "asfa-directive-ledger/v4", "snapshot is not v4")
    require(snapshot["network_name"] == registry["network_name"], "snapshot network mismatch")
    require(snapshot["policy_hash"] == expected_policy, "snapshot policy mismatch")
    require(plan["schema_version"] == "qfos-wave-plan/v1", "plan schema mismatch")
    require(plan["mode"] == "plan-only-no-execution", "plan mode mismatch")
    require(plan["network_name"] == registry["network_name"], "plan network mismatch")
    require(plan["policy_hash"] == expected_policy, "plan policy mismatch")
    require(plan["plan_hash"] == digest(PLAN_DOMAIN, without(plan, "plan_hash")), "plan_hash mismatch")
    if pre_snapshot is not None:
        require(pre_snapshot["schema_version"] == "asfa-directive-ledger/v4", "pre-snapshot is not v4")
        expected_ledger = digest(LEDGER_DOMAIN, pre_snapshot)
        require(plan["ledger_hash"] == expected_ledger, "plan ledger binding mismatch")

    jobs = plan["jobs"]
    keys = [(job["session"], job["id"]) for job in jobs]
    require(len(set(keys)) == len(keys), "duplicate planned job")
    require(report["schema_version"] == "qfos-wave-execution/v1", "execution schema mismatch")
    require(report["profile"] == "qfos-exec-v1", "execution profile mismatch")
    require(report["network_name"] == plan["network_name"], "execution network mismatch")
    require(report["policy_hash"] == expected_policy, "execution policy mismatch")
    require(report["plan_hash"] == plan["plan_hash"], "execution plan binding mismatch")
    require(is_u64(report["executed_at_epoch"]), "invalid execution epoch")
    results = report["results"]
    require([(item.get("session"), item.get("id")) for item in results] == keys,
            "execution results do not match planned order and keys")

    receipts = indexed(snapshot["receipts"], "receipt")
    dead_letters = indexed(snapshot["dead_letters"], "dead letter")
    consumed_records = indexed(snapshot["consumed"], "consumed")
    consumed = set(consumed_records)
    pending = {
        (entry["session"], entry["directive"]["id"])
        for entry in snapshot["directives"]
    }
    require(not (consumed & pending), "consumed key remains pending")
    if closed_world:
        require(consumed == set(keys), "closed-world consumed set mismatch")
        require(set(receipts) | set(dead_letters) == set(keys), "closed-world outcome set mismatch")

    status_counts = {
        "succeeded": 0,
        "dead_lettered": 0,
        "skipped_succeeded": 0,
        "skipped_dead_lettered": 0,
    }
    for key, job, result in zip(keys, jobs, results):
        require(key in consumed, f"planned key is not consumed: {key}")
        require(key not in pending, f"executed key remains pending: {key}")
        require((key in receipts) != (key in dead_letters), f"outcome is not unique: {key}")
        status = result["status"]
        require(status in status_counts, f"unknown execution status: {status}")
        status_counts[status] += 1
        expected_input = input_digest(job)
        if status in ("succeeded", "skipped_succeeded"):
            require(key in receipts, f"missing success receipt: {key}")
            require(result.get("dead_letter") is None, f"success carries dead letter: {key}")
            receipt = receipts[key]
            require(result.get("receipt") == receipt, f"report receipt differs from snapshot: {key}")
            verify_common(receipt, job, plan, expected_input)
            require(is_u64(receipt["executed_at_epoch"]), f"invalid receipt epoch: {key}")
            engine, output, failure = expected_outcome(job, receipt["executed_at_epoch"])
            require(failure is None, f"success should be {failure}: {key}")
            require(receipt["engine"] == engine, f"receipt engine mismatch: {key}")
            require(receipt["output"] == output, f"recomputed built-in output mismatch: {key}")
            require(receipt["output_hash"] == digest(OUTPUT_DOMAIN, receipt["output"]),
                    f"output_hash mismatch: {key}")
            require(receipt["receipt_hash"] == digest(RECEIPT_DOMAIN, without(receipt, "receipt_hash")),
                    f"receipt_hash mismatch: {key}")
        else:
            require(key in dead_letters, f"missing dead letter: {key}")
            require(result.get("receipt") is None, f"dead result carries receipt: {key}")
            dead = dead_letters[key]
            require(result.get("dead_letter") == dead, f"report dead letter differs from snapshot: {key}")
            verify_common(dead, job, plan, expected_input)
            require(is_u64(dead["failed_at_epoch"]), f"invalid dead-letter epoch: {key}")
            engine, output, failure = expected_outcome(job, dead["failed_at_epoch"])
            require(output is None and failure is not None, f"dead job should succeed: {key}")
            require(dead["engine"] == engine, f"dead-letter engine mismatch: {key}")
            require(dead["code"] == failure, f"recomputed failure class mismatch: {key}")
            require(isinstance(dead["message"], str) and dead["message"], f"empty failure message: {key}")
            require(dead["dead_letter_hash"] == digest(DEAD_DOMAIN, without(dead, "dead_letter_hash")),
                    f"dead_letter_hash mismatch: {key}")

    expected_summary = {"offered": len(jobs), **status_counts}
    require(report["summary"] == expected_summary, "execution summary mismatch")
    require(report["execution_hash"] == digest(REPORT_DOMAIN, without(report, "execution_hash")),
            "execution_hash mismatch")
    return {
        "jobs": len(jobs),
        "receipts": len(receipts),
        "dead_letters": len(dead_letters),
        "execution_hash": report["execution_hash"],
    }


def expect_rejection(label, callback):
    try:
        callback()
    except (VerificationError, KeyError, TypeError, ValueError) as error:
        return {"case": label, "verdict": "rejected", "reason": str(error)}
    raise VerificationError(f"self-test was not rejected: {label}")


def self_tests(registry, pre_snapshot, snapshot, plan, report, closed_world):
    tests = []
    changed_plan = copy.deepcopy(plan)
    changed_plan["jobs"][0]["payload"] = {"values": [0]}
    tests.append(expect_rejection(
        "changed_plan_content",
        lambda: verify_execution(registry, pre_snapshot, snapshot, changed_plan, report, closed_world),
    ))

    changed_snapshot = copy.deepcopy(snapshot)
    changed_report = copy.deepcopy(report)
    success_index = next(i for i, item in enumerate(snapshot["receipts"])
                         if item["action"] == "engine.sum")
    key = (snapshot["receipts"][success_index]["session"], snapshot["receipts"][success_index]["id"])
    result_index = next(i for i, item in enumerate(report["results"])
                        if (item["session"], item["id"]) == key)
    for document, index in ((changed_snapshot["receipts"], success_index),
                            (changed_report["results"][result_index]["receipt"], None)):
        target = document[index] if index is not None else document
        target["output"]["sum"] = -1
        refresh_receipt(target)
    refresh_report(changed_report)
    tests.append(expect_rejection(
        "rehashed_false_sum_output",
        lambda: verify_execution(registry, pre_snapshot, changed_snapshot, plan, changed_report, closed_world),
    ))

    changed_snapshot = copy.deepcopy(snapshot)
    changed_report = copy.deepcopy(report)
    dead_index = next(i for i, item in enumerate(snapshot["dead_letters"])
                      if item["code"] == "unknown_action")
    key = (snapshot["dead_letters"][dead_index]["session"], snapshot["dead_letters"][dead_index]["id"])
    result_index = next(i for i, item in enumerate(report["results"])
                        if (item["session"], item["id"]) == key)
    for document, index in ((changed_snapshot["dead_letters"], dead_index),
                            (changed_report["results"][result_index]["dead_letter"], None)):
        target = document[index] if index is not None else document
        target["code"] = "invalid_payload"
        refresh_dead_letter(target)
    refresh_report(changed_report)
    tests.append(expect_rejection(
        "rehashed_false_failure_class",
        lambda: verify_execution(registry, pre_snapshot, changed_snapshot, plan, changed_report, closed_world),
    ))

    changed_report = copy.deepcopy(report)
    success_result = next(item for item in changed_report["results"] if item["status"] == "succeeded")
    success_result["status"] = "dead_lettered"
    refresh_report(changed_report)
    tests.append(expect_rejection(
        "rehashed_inconsistent_report_result",
        lambda: verify_execution(registry, pre_snapshot, snapshot, plan, changed_report, closed_world),
    ))

    changed_report = copy.deepcopy(report)
    changed_report["execution_hash"] = "0" * 64
    tests.append(expect_rejection(
        "changed_report_hash",
        lambda: verify_execution(registry, pre_snapshot, snapshot, plan, changed_report, closed_world),
    ))
    return tests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", default="config/sessions.execution.json")
    parser.add_argument("--pre-snapshot", default="fixtures/qfos-exec-pre-state.json")
    parser.add_argument("--snapshot", default="fixtures/qfos-exec-state.json")
    parser.add_argument("--plan", default="fixtures/qfos-exec-plan.json")
    parser.add_argument("--report", default="fixtures/qfos-exec-report.json")
    parser.add_argument("--closed-world", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--expect-plan-hash")
    parser.add_argument("--expect-execution-hash")
    args = parser.parse_args()
    registry = load_json(args.registry)
    pre_snapshot = load_json(args.pre_snapshot) if args.pre_snapshot else None
    snapshot = load_json(args.snapshot)
    plan = load_json(args.plan)
    report = load_json(args.report)
    result = verify_execution(registry, pre_snapshot, snapshot, plan, report, args.closed_world)
    if args.expect_plan_hash:
        require(plan["plan_hash"] == args.expect_plan_hash, "plan known-answer mismatch")
    if args.expect_execution_hash:
        require(report["execution_hash"] == args.expect_execution_hash,
                "execution known-answer mismatch")
    count = 0
    if args.self_test:
        tests = self_tests(registry, pre_snapshot, snapshot, plan, report, args.closed_world)
        count = len(tests)
    print(
        f"execution_oracle=PASS plan_hash={plan['plan_hash']} "
        f"execution_hash={result['execution_hash']} jobs={result['jobs']} "
        f"receipts={result['receipts']} dead_letters={result['dead_letters']} self_tests={count}"
    )


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"independent execution oracle: {error}") from error
