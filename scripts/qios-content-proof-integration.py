#!/usr/bin/env python3
"""End-to-end scoped QI-OS content-proof integration using a real Lean rebuild."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter-work", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    if work.exists():
        raise SystemExit("integration work directory must not exist")
    work.mkdir(parents=True)
    root = work / "scoped-qios"
    shutil.copytree(args.adapter_work.resolve(), root,
                    ignore=shutil.ignore_patterns("runtime", "__pycache__", "*.log"))
    wild_path = root / "config" / "wildq.json"
    wild = load(wild_path)
    lean = [q for q in wild["questions"] if q["id"] == "WQ-QI-LEAN-FED-01"]
    if len(lean) != 1:
        raise SystemExit("exactly one Lean wild question is required")
    save(wild_path, {"schema": "qi-wildq/v1", "questions": lean})
    sys.path.insert(0, str(root))
    from qios.canon import digest  # noqa: E402
    from qios.envelope import make_event  # noqa: E402
    from qios.kernel import QiKernel  # noqa: E402
    kernel = QiKernel(root, allow_local=True)
    kernel.activate(wave_id="WAVE-CONTENT-PROOF-INTEGRATION")
    loop_id = sorted(kernel._loops()["loops"])[0]
    loop = kernel._loops()["loops"][loop_id]
    peer = loop["peer"]
    kernel.record_delivery(loop["workorder_id"], {
        "state": "DELIVERED", "repo": "example/line", "issue_number": 1,
        "issue_url": "https://example.invalid/1"})
    answer = {"loop_id": loop_id, "role": "answer", "verdict": "PASS",
              "claims": ["WQ-QI-LEAN-FED-01"], "artifacts": [], "open_items": []}
    first = kernel.ingest(make_event(peer, "answer", "answer", answer, mode="local"))
    current = kernel._loops()["loops"][loop_id]
    cross = {"loop_id": loop_id, "role": "crosscheck", "target_peer": peer,
             "verdict": "PASS", "subject_answer_digest": current["answers"][peer]["answer_digest"]}
    second = kernel.ingest(make_event("tower", "answer", "cross", cross,
                                      mode="local", credential_ref="TOWER"))
    if first["verdict"] != "OPEN" or second["verdict"] != "OPEN" or \
            f"content-proof:{peer}" not in second["open_items"]:
        raise SystemExit("double-PASS content gate did not remain OPEN")
    generation_work = work / "generation"
    generator = Path(__file__).with_name("qios-content-proof.py").resolve()
    completed = subprocess.run([
        sys.executable, str(generator), "--repo", str(args.repo.resolve()), "--commit", args.commit,
        "--root", str(root), "--loop-id", loop_id, "--peer", peer,
        "--principal", "local:TOWER", "--question-id", "WQ-QI-LEAN-FED-01",
        "--work-dir", str(generation_work), "--record"], cwd=args.repo.resolve(), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200, check=False)
    (work / "generator.log").write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        raise SystemExit(f"real content-proof generation failed; see {work / 'generator.log'}")
    generation = load(generation_work / "generation-result.json")
    adjudication = generation["adjudication"]
    scoped = QiKernel(root, allow_local=True)._loops()["loops"][loop_id]
    global_status = QiKernel(root, allow_local=True).status()
    if adjudication["verdict"] != "PASS" or not scoped["promotion"] or \
            scoped["content_required"] != ["WQ-QI-LEAN-FED-01"] or \
            global_status["verdict"] != "OPEN":
        raise SystemExit("scoped PASS/global OPEN boundary failed")
    receipt = generation["receipt"]
    duplicate = QiKernel(root, allow_local=True).record_content_proof(
        loop_id, peer, copy.deepcopy(receipt), principal="local:TOWER")
    forged = copy.deepcopy(receipt)
    forged["oracle_verdict"] = "OPEN"
    forged_result = QiKernel(root, allow_local=True).record_content_proof(
        loop_id, peer, forged, principal="local:TOWER")
    if "CONTENT_PROOF_IMMUTABLE" not in duplicate["errors"] or forged_result["verdict"] != "FAIL":
        raise SystemExit("content-proof replay/forgery negative controls failed")
    result = {
        "schema": "asfa-qios-content-proof-integration/v1",
        "source_commit": args.commit,
        "loop_id": loop_id,
        "peer": peer,
        "double_pass_without_proof": second["verdict"],
        "scoped_verdict_after_real_proof": adjudication["verdict"],
        "scoped_question_coverage": scoped["content_required"],
        "global_verdict": global_status["verdict"],
        "global_open_items": len(global_status["open_items"]),
        "proof_id": receipt["proof_id"],
        "proof_path": str(generation_work / "content-proof.json"),
        "report_path": str(generation_work / "evidence" / "report.json"),
        "oracle_path": str(generation_work / "evidence" / "oracle.json"),
        "duplicate_rejection": duplicate["errors"],
        "forged_rejection": forged_result["errors"],
        "boundary": "Real clean-archive Lean FORMAL_R1 proof for one scoped Lean question only. Other wild questions and the global wave remain OPEN; no R2 or multi-kernel claim."
    }
    save(work / "integration-result.json", result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
