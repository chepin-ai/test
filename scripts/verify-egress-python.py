#!/usr/bin/env python3
"""Independent known-answer oracle for the bridge poller egress boundary."""

import argparse
import copy
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/egress-address-cases.json"

V4_RULES = [
    ("0.0.0.0/8", "unspecified_or_this_network"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "shared"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "ietf_protocol"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "transition"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
]
V6_RULES = [
    ("64:ff9b::/96", "nat64"),
    ("64:ff9b:1::/48", "nat64"),
    ("100::/64", "discard"),
    ("2001:2::/48", "benchmarking"),
    ("2001::/23", "transition_or_ietf"),
    ("2001:db8::/32", "documentation"),
    ("3fff::/20", "documentation"),
    ("2002::/16", "transition"),
    ("fc00::/7", "unique_local"),
    ("fe80::/10", "link_local"),
    ("ff00::/8", "multicast"),
]
V4_RULES = [(ipaddress.ip_network(net), label) for net, label in V4_RULES]
V6_RULES = [(ipaddress.ip_network(net), label) for net, label in V6_RULES]


def classify(value):
    ip = ipaddress.ip_address(value)
    if ip.version == 4:
        for network, label in V4_RULES:
            if ip in network:
                return label
        return "public"
    if ip.is_unspecified:
        return "unspecified"
    if ip.ipv4_mapped is not None:
        return "ipv4_mapped"
    if ip.is_loopback:
        return "loopback"
    for network, label in V6_RULES:
        if ip in network:
            return label
    if ip not in ipaddress.ip_network("2000::/3"):
        return "non_global_unicast"
    return "public"


def verify_cases():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == "asfa-egress-address-cases/v1"
    assert len(fixture["cases"]) >= 40
    for case in fixture["cases"]:
        actual = classify(case["ip"])
        assert actual == case["class"], (case, actual)
        assert (actual == "public") == case["public"], (case, actual)
    return len(fixture["cases"])


def verify_blocked_report(report, hits):
    assert hits == 0, f"blocked destination received {hits} TCP connection(s)"
    assert report["summary"] == {"total": 1, "verified": 0, "failed": 1}
    assert len(report["records"]) == 1
    record = report["records"][0]
    assert record["session"] == "node"
    status = record["status"]
    assert status["kind"] == "blocked_egress", status
    assert "non-public egress blocked" in status["message"], status
    assert "loopback" in status["message"], status


def known_answer_report():
    return {
        "summary": {"total": 1, "verified": 0, "failed": 1},
        "records": [{
            "session": "node",
            "url": "http://127.0.0.1:9/outbox",
            "fetched_at_epoch": 100,
            "status": {
                "kind": "blocked_egress",
                "message": "non-public egress blocked: 127.0.0.1 (loopback)",
            },
        }],
    }


def self_test():
    count = verify_cases()
    original = json.loads(FIXTURE.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(original)
    tampered["cases"][0]["public"] = False
    try:
        for case in tampered["cases"]:
            actual = classify(case["ip"])
            assert actual == case["class"]
            assert (actual == "public") == case["public"]
        raise AssertionError("tampered public answer was accepted")
    except AssertionError as error:
        assert "tampered public answer was accepted" not in str(error)

    report = known_answer_report()
    verify_blocked_report(copy.deepcopy(report), 0)
    rejected = []
    for name, mutate, hits in [
        ("wrong_status", lambda r: r["records"][0]["status"].update(kind="transport"), 0),
        ("false_verified_summary", lambda r: r["summary"].update(verified=1), 0),
        ("actual_connection", lambda r: None, 1),
        ("extra_record", lambda r: r["records"].append(copy.deepcopy(r["records"][0])), 0),
    ]:
        candidate = copy.deepcopy(report)
        mutate(candidate)
        try:
            verify_blocked_report(candidate, hits)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError(f"self-test mutation accepted: {name}")
    assert rejected == ["wrong_status", "false_verified_summary", "actual_connection", "extra_record"]
    return count, rejected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--hits", type=int)
    args = parser.parse_args()
    if args.self_test:
        count, rejected = self_test()
        print(f"egress oracle self-test: PASS cases={count} rejected={','.join(rejected)}")
        return
    if args.report is None or args.hits is None:
        parser.error("--report and --hits are required unless --self-test is used")
    count = verify_cases()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    verify_blocked_report(report, args.hits)
    print(f"egress report: PASS cases={count} hits={args.hits} kind=blocked_egress")


if __name__ == "__main__":
    main()
