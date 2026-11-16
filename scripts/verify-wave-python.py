#!/usr/bin/env python3
"""Independent QF-OS wave oracle over snapshot and registry source documents.

Profile: qfos-wave-v1/no-floats/non-jcs. This verifies deterministic plan-only
consistency, not publisher authentication, execution, or a formal proof of engine
behavior. Execution outcomes are checked by verify-execution-python.py.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

LEDGER_DOMAIN = b"ASFA-OS-XI/DIRECTIVE-LEDGER-SNAPSHOT/V1\n"
PLAN_DOMAIN = b"ASFA-OS-XI/QFOS-WAVE-PLAN/V1\n"
POLICY_DOMAIN = b"ASFA-OS-XI/REGISTRY-POLICY/V1\n"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def reject_floats(value):
    if isinstance(value, float):
        raise ValueError("floating point is outside the wave oracle profile")
    if isinstance(value, list):
        for item in value:
            reject_floats(item)
    elif isinstance(value, dict):
        for item in value.values():
            reject_floats(item)


def load_json(path):
    value = json.loads(
        Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )
    reject_floats(value)
    return value


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


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
    projection = {
        "schema_version": registry["schema_version"],
        "network_name": registry["network_name"],
        "trust_model": registry["trust_model"],
        "sessions": sessions,
    }
    return hashlib.sha256(POLICY_DOMAIN + canonical_bytes(projection)).hexdigest()


def job(session, directive):
    result = {
        "session": session,
        "id": directive["id"],
        "action": directive["action"],
        "payload": directive["payload"],
    }
    if directive.get("expires_epoch") is not None:
        result["expires_epoch"] = directive["expires_epoch"]
    return result


def rebuild(registry, snapshot, plan):
    assert snapshot["schema_version"] == "asfa-directive-ledger/v4"
    assert snapshot["network_name"] == registry["network_name"]
    expected_policy = policy_digest(registry)
    assert snapshot["policy_hash"] == expected_policy, "snapshot policy mismatch"
    assert plan["policy_hash"] == expected_policy, "plan policy mismatch"

    groups = {}
    for entry in snapshot["directives"]:
        session = entry["session"]
        directive = entry["directive"]
        assert directive["from"] == session
        target = plan["target"]
        expires = directive.get("expires_epoch")
        expired = expires is not None and expires <= plan["generated_at_epoch"]
        if directive["to"] in (target, "*") and not expired:
            groups.setdefault(session, []).append(directive)
    groups = {session: sorted(items, key=lambda item: item["id"]) for session, items in sorted(groups.items())}

    jobs = []
    selected = set()
    admitted = {session: 0 for session in groups}
    offsets = {session: 0 for session in groups}
    while len(jobs) < plan["max_jobs"]:
        progressed = False
        for session, directives in groups.items():
            if len(jobs) >= plan["max_jobs"]:
                break
            offset = offsets[session]
            if offset >= len(directives) or admitted[session] >= plan["max_per_source"]:
                continue
            directive = directives[offset]
            offsets[session] += 1
            admitted[session] += 1
            selected.add((session, directive["id"]))
            jobs.append(job(session, directive))
            progressed = True
        if not progressed:
            break

    sources = []
    for session, directives in groups.items():
        deferred_wave_quota = 0
        deferred_source_quota = 0
        for directive in directives:
            if (session, directive["id"]) in selected:
                continue
            if admitted[session] >= plan["max_per_source"]:
                deferred_source_quota += 1
            else:
                deferred_wave_quota += 1
        sources.append({
            "session": session,
            "offered": len(directives),
            "admitted": admitted[session],
            "deferred_wave_quota": deferred_wave_quota,
            "deferred_source_quota": deferred_source_quota,
        })

    expected = {
        "schema_version": "qfos-wave-plan/v1",
        "mode": "plan-only-no-execution",
        "network_name": registry["network_name"],
        "policy_hash": expected_policy,
        "ledger_hash": hashlib.sha256(LEDGER_DOMAIN + canonical_bytes(snapshot)).hexdigest(),
        "target": plan["target"],
        "generated_at_epoch": plan["generated_at_epoch"],
        "max_jobs": plan["max_jobs"],
        "max_per_source": plan["max_per_source"],
        "jobs": jobs,
        "deferred": sum(item["deferred_wave_quota"] + item["deferred_source_quota"] for item in sources),
        "sources": sources,
    }
    expected["plan_hash"] = hashlib.sha256(PLAN_DOMAIN + canonical_bytes(expected)).hexdigest()
    assert expected == plan, "wave plan does not match independent reconstruction"
    return expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", default="config/sessions.wave.json")
    parser.add_argument("--snapshot", default="fixtures/qfos-wave-state.json")
    parser.add_argument("--plan", default="fixtures/qfos-wave-plan.json")
    parser.add_argument("--expect-plan-hash")
    args = parser.parse_args()
    registry = load_json(args.registry)
    snapshot = load_json(args.snapshot)
    plan = load_json(args.plan)
    expected = rebuild(registry, snapshot, plan)
    if args.expect_plan_hash:
        assert plan["plan_hash"] == args.expect_plan_hash, "known-answer hash mismatch"

    changed_job = copy.deepcopy(plan)
    changed_job["jobs"][0]["action"] = "engine.attacker"
    try:
        rebuild(registry, snapshot, changed_job)
        raise AssertionError("tampered wave job passed independent reconstruction")
    except AssertionError as error:
        assert "independent reconstruction" in str(error)

    changed_state = copy.deepcopy(snapshot)
    changed_state["directives"][0]["directive"]["action"] = "engine.attacker"
    try:
        rebuild(registry, changed_state, plan)
        raise AssertionError("modified ledger binding passed independent reconstruction")
    except AssertionError as error:
        assert "independent reconstruction" in str(error)

    print(
        f"wave_oracle=PASS plan_hash={plan['plan_hash']} "
        f"jobs={len(plan['jobs'])} deferred={plan['deferred']} self_tests=2"
    )


if __name__ == "__main__":
    main()
