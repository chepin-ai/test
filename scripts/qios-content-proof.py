#!/usr/bin/env python3
"""Generate a QI-OS content receipt only after a clean Lean rebuild and oracle PASS."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

SCHEMA = "qi-lean-content-proof/v1"
METHOD = "clean-archive-lake-build-independent-oracle"


class ProofError(Exception):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def run(argv: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=900, check=False)
    log.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        raise ProofError(f"process failed ({completed.returncode}); see {log}")


def archive_source(repo: Path, commit: str, work: Path) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProofError("source commit must be a full lowercase Git SHA")
    checked = subprocess.run(["git", "rev-parse", f"{commit}^{{commit}}"], cwd=repo,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if checked.returncode != 0 or checked.stdout.strip() != commit:
        raise ProofError("source commit is not present in the repository")
    archive = work / "source.tar"
    run(["git", "archive", "--format=tar", "--output", str(archive), commit], repo,
        work / "git-archive.log")
    source = work / "source"
    source.mkdir()
    with tarfile.open(archive, "r:") as handle:
        handle.extractall(source, filter="data")
    for relative in ("lean/lean-toolchain", "federation/lean-anchors.json", "federation/registry-seed.json"):
        if not (source / relative).is_file():
            raise ProofError(f"clean archive is missing {relative}")
    return source


def loop_binding(root: Path, loop_id: str, peer: str, principal: str) -> tuple[dict, dict, dict]:
    loops = load(root / "runtime" / "loops.json")["loops"]
    loop = loops.get(loop_id)
    if not isinstance(loop, dict):
        raise ProofError("unknown loop")
    answer = loop.get("answers", {}).get(peer)
    cross = loop.get("crosschecks", {}).get(peer)
    if not answer or not cross or answer["answer"].get("verdict") != "PASS" or cross.get("verdict") != "PASS":
        raise ProofError("PASS answer and PASS crosscheck are prerequisites, not sufficient proof")
    if cross.get("identity", {}).get("principal") != principal:
        raise ProofError("verifier principal does not match the authenticated crosscheck")
    if not cross.get("crosscheck_digest"):
        raise ProofError("crosscheck predates content-proof binding")
    return loop, answer, cross


def generate(args: argparse.Namespace) -> dict:
    repo = args.repo.resolve()
    root = args.root.resolve()
    work = args.work_dir.resolve()
    if work.exists():
        raise ProofError("work directory must not exist; no intermediate reuse")
    work.mkdir(parents=True)
    loop, answer, cross = loop_binding(root, args.loop_id, args.peer, args.principal)
    required = loop.get("content_required")
    if required is None:
        order = load(root / "runtime" / "outbox" / f"{loop['workorder_id']}.json")
        required = [q["id"] for q in order["params"]["questions"]]
    coverage = sorted(set(args.question_id))
    if not coverage or not set(coverage) <= set(required):
        raise ProofError("question coverage is empty, unknown, or outside the loop")
    source = archive_source(repo, args.commit, work)
    trusted_runner = Path(__file__).with_name("lean-federation.py").resolve()
    trusted_oracle = Path(__file__).with_name("verify-lean-federation-python.py").resolve()
    evidence = work / "evidence"
    env = os.environ.copy()
    run([sys.executable, str(trusted_runner), "run", "--repo", str(source),
         "--source-commit", args.commit, "--work-dir", str(evidence)], source,
        work / "trusted-runner-process.log", env)
    run([sys.executable, str(trusted_oracle), "--report", str(evidence / "report.json"),
         "--repo", str(source), "--require-commit", "--out", str(evidence / "oracle.json")],
        source, work / "trusted-oracle-process.log", env)
    report_path = evidence / "report.json"
    oracle_path = evidence / "oracle.json"
    report = load(report_path)
    oracle = load(oracle_path)
    capsule = report["capsule"]
    if oracle.get("verdict") != "PASS" or report.get("source_commit") != args.commit or \
            capsule.get("source_commit") != args.commit or capsule.get("evidence", {}).get("level") != "FORMAL_R1":
        raise ProofError("content evidence did not establish scoped FORMAL_R1")
    receipt = {
        "schema": SCHEMA,
        "question_coverage": coverage,
        "method": METHOD,
        "evidence_grade": "FORMAL_R1",
        "source_commit": args.commit,
        "capsule_sha256": digest(capsule),
        "report_sha256": sha(report_path),
        "oracle_report_sha256": sha(oracle_path),
        "verifier_sha256": sha(trusted_oracle),
        "verifier_principal": args.principal,
        "subject_answer_digest": digest(answer["answer"]),
        "subject_crosscheck_digest": cross["crosscheck_digest"],
        "oracle_verdict": "PASS",
    }
    if receipt["subject_answer_digest"] != answer["answer_digest"]:
        raise ProofError("stored answer digest diverges from canonical answer")
    receipt["proof_id"] = digest({"schema": "qi-content-proof-id/v1", "receipt": receipt})
    proof_path = work / "content-proof.json"
    proof_path.write_bytes(canonical(receipt) + b"\n")
    result = {"schema": "asfa-qios-content-proof-generation/v1", "receipt": receipt,
              "report": str(report_path), "oracle": str(oracle_path),
              "clean_archive": True, "recorded": False}
    if args.record:
        sys.path.insert(0, str(root))
        from qios.kernel import QiKernel  # noqa: E402
        adjudicated = QiKernel(root, allow_local=True).record_content_proof(
            args.loop_id, args.peer, copy.deepcopy(receipt), principal=args.principal)
        if adjudicated.get("verdict") == "FAIL":
            raise ProofError("content receipt rejected: " + ";".join(adjudicated.get("errors", [])))
        result["recorded"] = True
        result["adjudication"] = adjudicated
    (work / "generation-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--loop-id", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--question-id", action="append", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    try:
        result = generate(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ProofError, OSError, KeyError, ValueError, subprocess.TimeoutExpired, tarfile.TarError) as exc:
        print(f"content proof rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
