#!/usr/bin/env python3
"""Independent transport, ledger and non-promotion oracle for a QI-OS wave."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

WAVE_ID = "WAVE-QI-LEAN-FED-20261123-01"
GENESIS = "0" * 64
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}


class Reject(Exception):
    pass


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def title_for(order: dict) -> str:
    return f"[QI-OS] {order['wave_id']} · {order['target']} 全院协商／野问浪涌"


def body_for(order: dict) -> str:
    return "QI-OS-WORKORDER-V1\n" + canonical(order)


def valid_issue_number(value) -> bool:
    return type(value) is int and value >= 1


def verify_ledger(path: Path) -> dict:
    entries = []
    if path.exists():
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(keepends=True), 1):
            if not line.strip():
                raise Reject(f"EMPTY_LINE:{line_no}")
            entry = json.loads(line)
            if line != canonical(entry) + "\n":
                raise Reject(f"NONCANONICAL_LINE:{line_no}")
            entries.append(entry)
    previous = GENESIS
    for expected, entry in enumerate(entries, 1):
        if set(entry) != {"seq", "prev", "kind", "body", "recorded_at", "hash"}:
            raise Reject(f"BAD_SHAPE:{expected}")
        if entry["seq"] != expected or entry["prev"] != previous:
            raise Reject(f"CHAIN_BREAK:{expected}")
        sealed = dict(entry)
        claimed = sealed.pop("hash")
        if digest(sealed) != claimed:
            raise Reject(f"HASH_MISMATCH:{expected}")
        previous = claimed
    return {"entries": len(entries), "tip": previous}


def api_json(repo: str, path: str, token: str | None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "asfa-qios-independent-oracle"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}{path}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise Reject(f"GitHub {repo}{path}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise Reject(f"GitHub {repo}{path}: {exc.reason}") from exc


def comments(repo: str, number: int, token: str | None) -> list[dict]:
    result = []
    for page in range(1, 11):
        batch = api_json(repo, f"/issues/{number}/comments?per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise Reject("comment response is not a list")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise Reject("comment pagination limit exceeded")


def self_test() -> dict:
    order = {"schema": "qi-workorder/v1", "id": "WO-X", "loop_id": "LOOP-X", "wave_id": WAVE_ID,
             "from": "qi-os", "target": "usrm", "action": "negotiate-grand-cycle", "params": {},
             "delivery": {"transport": "github-issue", "repo": "chepin-ai/vci-usrm", "state": "PENDING"}}
    if not body_for(order).startswith("QI-OS-WORKORDER-V1\n{") or title_for(order) != f"[QI-OS] {WAVE_ID} · usrm 全院协商／野问浪涌":
        raise Reject("workorder known answer")
    if valid_issue_number(True) or valid_issue_number(1.0) or not valid_issue_number(1):
        raise Reject("issue-number type boundary")
    first = {"seq": 1, "prev": GENESIS, "kind": "known", "body": {"x": 1}, "recorded_at": "t"}
    first["hash"] = digest(first)
    second = {"seq": 2, "prev": first["hash"], "kind": "known", "body": {"x": 2}, "recorded_at": "t2"}
    second["hash"] = digest(second)
    path = Path(os.environ.get("TMPDIR", "/tmp")) / f"asfa-qios-oracle-self-{os.getpid()}.jsonl"
    path.write_text(canonical(first) + "\n" + canonical(second) + "\n")
    try:
        if verify_ledger(path)["entries"] != 2:
            raise Reject("synthetic valid ledger")
        path.write_text(path.read_text().replace('"x":2', '"x":3'))
        try:
            verify_ledger(path)
            raise Reject("tampered ledger accepted")
        except Reject as exc:
            if "tampered ledger accepted" in str(exc):
                raise
    finally:
        path.unlink(missing_ok=True)
    return {"known_answers": 3, "synthetic_valid": 1, "synthetic_rejections": 2}


def verify(root: Path, token: str | None, network: bool) -> dict:
    result_path = root / "runtime/federation-wave-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("schema") != "qi-federation-wave-result/v1":
        raise Reject("wave result schema")
    deliveries = result.get("deliveries", [])
    if len(deliveries) != 14:
        raise Reject(f"expected 14 deliveries, got {len(deliveries)}")
    ledger = verify_ledger(root / "runtime/ledger.jsonl")
    checked = []
    poll_by_id = {poll.get("workorder_id"): poll for poll in result.get("polls", [])}
    for delivery in deliveries:
        order_id = delivery.get("workorder_id")
        order_path = root / "runtime/outbox" / f"{order_id}.json"
        order = json.loads(order_path.read_text(encoding="utf-8"))
        if order.get("wave_id") != WAVE_ID:
            raise Reject(f"wave id mismatch: {order_id}")
        if delivery.get("state") != "DELIVERED" or not valid_issue_number(delivery.get("issue_number")):
            raise Reject(f"delivery is not independently checkable: {order_id}")
        repo = order["delivery"]["repo"]
        if delivery.get("repo") != repo:
            raise Reject(f"delivery repo mismatch: {order_id}")
        if network:
            issue = api_json(repo, f"/issues/{delivery['issue_number']}", token)
            if issue.get("title") != title_for(order) or issue.get("body") != body_for(order):
                raise Reject(f"issue byte mismatch: {order_id}")
            if (issue.get("user") or {}).get("login") != "chepin-qi":
                raise Reject(f"unexpected wave actor: {order_id}")
            valid_answers = 0
            for comment in comments(repo, delivery["issue_number"], token):
                body = comment.get("body") or ""
                if not body.startswith("QI-OS-ANSWER-V1\n"):
                    continue
                if comment.get("author_association") not in TRUSTED:
                    continue
                try:
                    payload = json.loads(body.split("\n", 1)[1])
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and payload.get("kind") == "answer":
                    valid_answers += 1
            if poll_by_id.get(order_id, {}).get("answers") != valid_answers:
                raise Reject(f"answer count changed or mismatched after QI-OS poll: {order_id}")
        checked.append(order_id)
    status = result.get("status", {})
    research_verdict = status.get("verdict")
    promotion = status.get("promotion")
    if promotion or research_verdict == "PASS":
        pending = status.get("open_items", [])
        if pending or "no-independent-crosscheck-observed" in status.get("negative", []):
            raise Reject("promotion with unresolved answer/crosscheck debt")
    polls = result.get("polls", [])
    protocol_answers = sum(poll.get("answers", 0) for poll in polls)
    adjudications = [item for poll in polls for item in poll.get("adjudications", [])]
    unique_accepted = sum(not item.get("errors") and item.get("verdict") in {"PASS", "OPEN"}
                          for item in adjudications)
    duplicate_rejections = sum("ANSWER_IMMUTABLE" in item.get("errors", [])
                               for item in adjudications)
    if protocol_answers == 0 and research_verdict != "OPEN":
        raise Reject("zero-answer wave is not OPEN")
    if protocol_answers == 0 and promotion:
        raise Reject("zero-answer promotion")
    return {"oracle_verdict": "PASS", "research_verdict": research_verdict,
            "promotion": promotion, "deliveries_checked": len(checked),
            "protocol_answers_seen": protocol_answers,
            "unique_answers_accepted": unique_accepted,
            "duplicate_answer_rejections": duplicate_rejections,
            "ledger": ledger,
            "evidence_status": "DELIVERED_NOT_CONSENSUS" if unique_accepted == 0 else "ANSWERS_REQUIRE_CROSSCHECK"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--token-env", default="GH_PAT_QI_FULL")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        base = self_test()
        if args.self_test and not args.root:
            result = {"schema": "asfa-qios-wave-oracle/v1", "self_test": base, "oracle_verdict": "PASS"}
        else:
            if not args.root:
                raise Reject("--root is required")
            token = os.environ.get(args.token_env)
            if not args.offline and not token:
                raise Reject(f"AUTH_UNAVAILABLE:{args.token_env}")
            verdict = verify(args.root.resolve(), token, not args.offline)
            result = {"schema": "asfa-qios-wave-oracle/v1", "self_test": base, **verdict,
                      "network_readback": not args.offline,
                      "boundary": "Transport and ledger verification only. Research consensus remains separate and cannot be promoted without answers and independent crosschecks."}
        text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            args.out.write_text(text)
        print(text, end="")
        return 0
    except (Reject, OSError, json.JSONDecodeError) as exc:
        print(f"oracle rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
