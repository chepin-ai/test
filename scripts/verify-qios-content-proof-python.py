#!/usr/bin/env python3
"""Independent receipt, binding, coverage and artifact oracle for QI-OS content proofs."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys


class Reject(Exception):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def proof_id(receipt: dict) -> str:
    unsigned = {k: v for k, v in receipt.items() if k != "proof_id"}
    return digest({"schema": "qi-content-proof-id/v1", "receipt": unsigned})


def validate_binding(loop: dict, peer: str, receipt: dict, source_commit: str) -> str:
    if receipt.get("schema") != "qi-lean-content-proof/v1" or \
            receipt.get("method") != "clean-archive-lake-build-independent-oracle" or \
            receipt.get("evidence_grade") != "FORMAL_R1" or receipt.get("oracle_verdict") != "PASS":
        raise Reject("receipt semantics")
    if receipt.get("proof_id") != proof_id(receipt):
        raise Reject("proof id")
    if receipt.get("source_commit") != source_commit or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise Reject("source commit")
    for field in ("capsule_sha256", "report_sha256", "oracle_report_sha256", "verifier_sha256",
                  "subject_answer_digest", "subject_crosscheck_digest"):
        if not isinstance(receipt.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[field]):
            raise Reject("hash shape: " + field)
    answer = loop.get("answers", {}).get(peer)
    cross = loop.get("crosschecks", {}).get(peer)
    if not answer or not cross or answer["answer"].get("verdict") != "PASS" or cross.get("verdict") != "PASS":
        raise Reject("answer/crosscheck prerequisites")
    if receipt["subject_answer_digest"] != digest(answer["answer"]) or \
            receipt["subject_answer_digest"] != answer["answer_digest"]:
        raise Reject("answer binding")
    if receipt["subject_crosscheck_digest"] != cross.get("crosscheck_digest"):
        raise Reject("crosscheck binding")
    if receipt["verifier_principal"] != cross.get("identity", {}).get("principal"):
        raise Reject("verifier principal")
    coverage = receipt.get("question_coverage")
    required = loop.get("content_required", [])
    if not isinstance(coverage, list) or not coverage or coverage != sorted(set(coverage)) or \
            not set(coverage) <= set(required):
        raise Reject("question coverage")
    return "PASS" if set(required) <= set(coverage) else "OPEN"


def synthetic_loop(receipt: dict | None = None) -> tuple[dict, str, dict]:
    answer = {"verdict": "PASS", "claims": [], "artifacts": [], "open_items": []}
    cross_body = {"loop_id": "L", "role": "crosscheck", "target_peer": "p",
                  "verdict": "PASS", "subject_answer_digest": digest(answer)}
    loop = {"content_required": ["Q1"], "answers": {"p": {"answer": answer, "answer_digest": digest(answer)}},
            "crosschecks": {"p": {"verdict": "PASS", "identity": {"principal": "local:TOWER"},
                                  "crosscheck_digest": digest(cross_body)}},
            "content_proofs": {"p": [receipt] if receipt else []}}
    base = {"schema": "qi-lean-content-proof/v1", "question_coverage": ["Q1"],
            "method": "clean-archive-lake-build-independent-oracle", "evidence_grade": "FORMAL_R1",
            "source_commit": "1" * 40, "capsule_sha256": "a" * 64, "report_sha256": "b" * 64,
            "oracle_report_sha256": "c" * 64, "verifier_sha256": "d" * 64,
            "verifier_principal": "local:TOWER", "subject_answer_digest": digest(answer),
            "subject_crosscheck_digest": digest(cross_body), "oracle_verdict": "PASS"}
    base["proof_id"] = proof_id(base)
    return loop, "p", base


def self_test() -> dict:
    loop, peer, receipt = synthetic_loop()
    if validate_binding(loop, peer, receipt, "1" * 40) != "PASS":
        raise Reject("synthetic valid")
    rejected = 0
    for field in ("proof_id", "subject_answer_digest", "subject_crosscheck_digest", "verifier_principal"):
        forged = copy.deepcopy(receipt)
        forged[field] = "0" * 64 if field != "verifier_principal" else "local:OTHER"
        try:
            validate_binding(loop, peer, forged, "1" * 40)
        except Reject:
            rejected += 1
    if rejected != 4:
        raise Reject("synthetic rejection coverage")
    return {"synthetic_valid": 1, "synthetic_rejections": rejected}


def verify(work: Path) -> dict:
    integration = load(work / "integration-result.json")
    if integration.get("schema") != "asfa-qios-content-proof-integration/v1":
        raise Reject("integration schema")
    generation_dir = work / "generation"
    generation = load(generation_dir / "generation-result.json")
    receipt_path = generation_dir / "content-proof.json"
    receipt = load(receipt_path)
    if receipt_path.read_bytes() != canonical(receipt) + b"\n" or generation.get("receipt") != receipt:
        raise Reject("receipt canonical bytes or generation binding")
    source_commit = integration["source_commit"]
    loops = load(work / "scoped-qios" / "runtime" / "loops.json")["loops"]
    loop_id = integration["loop_id"]
    peer = integration["peer"]
    loop = loops[loop_id]
    expected_scoped = validate_binding(loop, peer, receipt, source_commit)
    if expected_scoped != "PASS" or integration.get("scoped_verdict_after_real_proof") != "PASS" or \
            loop.get("verdict") != "PASS" or loop.get("promotion") is not True:
        raise Reject("scoped proof did not close exactly its question")
    if receipt not in loop.get("content_proofs", {}).get(peer, []):
        raise Reject("recorded receipt missing")
    report_path = generation_dir / "evidence" / "report.json"
    oracle_path = generation_dir / "evidence" / "oracle.json"
    report = load(report_path)
    oracle = load(oracle_path)
    if report.get("source_commit") != source_commit or report["capsule"].get("source_commit") != source_commit:
        raise Reject("report source commit")
    if receipt["report_sha256"] != sha(report_path) or receipt["oracle_report_sha256"] != sha(oracle_path) or \
            receipt["capsule_sha256"] != digest(report["capsule"]) or oracle.get("verdict") != "PASS" or \
            oracle.get("report_sha256") != sha(report_path):
        raise Reject("artifact hashes")
    if receipt["verifier_sha256"] != sha(Path(__file__).with_name("verify-lean-federation-python.py")):
        raise Reject("trusted verifier identity")
    other_open = [item for item in loops.values() if item.get("loop_id") != loop_id and item.get("verdict") != "PASS"]
    if not other_open or integration.get("global_verdict") != "OPEN" or integration.get("global_open_items") < 1:
        raise Reject("scoped PASS leaked into global PASS")
    if "CONTENT_PROOF_IMMUTABLE" not in integration.get("duplicate_rejection", []) or \
            not integration.get("forged_rejection"):
        raise Reject("negative controls missing")
    return {"oracle_verdict": "PASS", "proof_id": receipt["proof_id"],
            "scoped_verdict": "PASS", "global_verdict": "OPEN",
            "source_commit": source_commit, "question_coverage": receipt["question_coverage"],
            "artifact_hashes": 4, "boundary": "Independent receipt and artifact verification; scoped FORMAL_R1 only, no R2 or global research promotion."}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration-work", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        base = self_test()
        if args.self_test and not args.integration_work:
            result = {"schema": "asfa-qios-content-proof-oracle/v1", "self_test": base, "oracle_verdict": "PASS"}
        else:
            if not args.integration_work:
                raise Reject("--integration-work is required")
            result = {"schema": "asfa-qios-content-proof-oracle/v1", "self_test": base,
                      **verify(args.integration_work.resolve())}
        text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            args.out.write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except (Reject, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"content-proof oracle rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
