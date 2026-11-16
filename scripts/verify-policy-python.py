#!/usr/bin/env python3
"""Independent registry-policy oracle; no Rust output is used to derive the digest."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

DOMAIN = b"ASFA-OS-XI/REGISTRY-POLICY/V1\n"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )


def projection(registry):
    sessions = {}
    for name, session in sorted(registry["sessions"].items()):
        sessions[name] = {
            "url": session["url"],
            "canonical_url": session.get("canonical_url", session["url"]),
            "trust": session.get("trust", "unsigned-hash-chain"),
            "allow_insecure_http": session.get("allow_insecure_http", False),
            "allow_file": session.get("allow_file", False),
        }
    return {
        "schema_version": registry["schema_version"],
        "network_name": registry["network_name"],
        "trust_model": registry["trust_model"],
        "sessions": sessions,
    }


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def policy_digest(registry):
    return hashlib.sha256(DOMAIN + canonical_bytes(projection(registry))).hexdigest()


def verify_fixture(path):
    fixture = load_json(path)
    registry = fixture["registry"]
    rebuilt = projection(registry)
    assert rebuilt == fixture["projection"], "policy projection mismatch"
    digest = policy_digest(registry)
    assert digest == fixture["expected_policy_sha256"], "policy known-answer mismatch"

    descriptive = copy.deepcopy(registry)
    for session in descriptive["sessions"].values():
        session["role"] = "changed description"
        session["note"] = "still outside the security projection"
    assert policy_digest(descriptive) == digest, "role/note entered policy digest"

    explicit_default = copy.deepcopy(registry)
    session = explicit_default["sessions"]["beta"]
    session["canonical_url"] = session["url"]
    assert policy_digest(explicit_default) == digest, "explicit default changed digest"

    changed_url = copy.deepcopy(registry)
    changed_url["sessions"]["alpha"]["url"] = "https://attacker.example/outbox.json"
    assert policy_digest(changed_url) != digest, "URL mutation escaped policy digest"
    return digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", default="fixtures/policy-oracle.json")
    parser.add_argument("--registry")
    parser.add_argument("--snapshot")
    args = parser.parse_args()
    if (args.registry is None) != (args.snapshot is None):
        parser.error("--registry and --snapshot must be used together")

    digest = verify_fixture(args.fixture)
    print(f"policy_oracle=PASS digest={digest} self_tests=3")
    if args.registry:
        registry = load_json(args.registry)
        snapshot = load_json(args.snapshot)
        assert snapshot["schema_version"] == "asfa-directive-ledger/v4"
        assert snapshot["network_name"] == registry["network_name"]
        expected = policy_digest(registry)
        assert snapshot.get("policy_hash") == expected, "live snapshot policy mismatch"
        print(f"live_policy=PASS digest={expected}")


if __name__ == "__main__":
    main()
