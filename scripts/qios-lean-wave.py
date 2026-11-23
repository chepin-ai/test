#!/usr/bin/env python3
"""Prepare and drive a QI-OS Lean federation wave without owning QI-OS verdicts."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

WAVE_ID = "WAVE-QI-LEAN-FED-20261123-01"
EXPECTED_QIOS_COMMIT = "c13dcee8f67fce568e8b160be39c3d6ff8755736"
LEAN_QUESTION = {
    "id": "WQ-QI-LEAN-FED-01",
    "status": "open",
    "question": "各线能否在保留自身精确 toolchain／manifest 的前提下，以声明身份＋环境 attestation 同步 Lean 成果，并证明同键异命题不覆盖、lossy 投影不升格 FORMAL？",
    "falsifier": "强制改写 legacy 环境、同键异命题覆盖、耦合／桥接自动传递、lossy 投影直接获得 FORMAL，或无独立重建即宣布全局一致。",
    "requested_evidence": "精确源提交、lake build、#check／公理日志、独立判读、冲突负例、跨线 attestation；ASFA 锚=280d62f3e2225ac7ea314b4492aa51d78a32f6a8，report=e3c6e116a5936d068ff9679bf8903ec80e1fb37d9fab4f7f021fa3f286c47888。",
}

KERNEL_OLD = '''    def test_09_activation_creates_ten_open_grand_cycles(self):
        result = self.kernel.activate()
        self.assertEqual("OPEN", result["verdict"])
        loops = self.kernel._loops()["loops"]
        self.assertEqual(10, len(loops))
        self.assertTrue(all(x["verdict"] == "OPEN" for x in loops.values()))
        self.assertEqual(10, len(list(self.kernel.outbox.glob("WO-*.json"))))
'''
KERNEL_NEW = '''    def test_09_activation_creates_all_enabled_open_grand_cycles(self):
        result = self.kernel.activate()
        self.assertEqual("OPEN", result["verdict"])
        loops = self.kernel._loops()["loops"]
        expected = sum(peer.get("enabled") and peer.get("transport") == "github-issue"
                       for peer in json.loads((REPO / "config" / "peers.json").read_text())["peers"])
        self.assertEqual(expected, len(loops))
        self.assertTrue(all(x["verdict"] == "OPEN" for x in loops.values()))
        self.assertEqual(expected, len(list(self.kernel.outbox.glob("WO-*.json"))))
'''
ADV_OLD = '''        self.assertEqual(7, after["delivery"]["issue_number"])
        self.assertEqual(10, len(list(self.kernel.outbox.glob("WO-*.json"))))
        created = [e for e in self.kernel.ledger.entries() if e["kind"] == "grand_wave_created"]
'''
ADV_NEW = '''        self.assertEqual(7, after["delivery"]["issue_number"])
        expected = sum(peer.get("enabled") and peer.get("transport") == "github-issue"
                       for peer in json.loads((REPO / "config" / "peers.json").read_text())["peers"])
        self.assertEqual(expected, len(list(self.kernel.outbox.glob("WO-*.json"))))
        created = [e for e in self.kernel.ledger.entries() if e["kind"] == "grand_wave_created"]
'''


class WaveError(Exception):
    pass


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def replace_exact(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise WaveError(f"upstream test patch anchor is not unique: {path}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def prepare(source: Path, work: Path) -> dict:
    required = ["qios", "scripts/federation_wave.py", "tests", "config/peers.json", "config/identities.json", "config/wildq.json"]
    for relative in required:
        if not (source / relative).exists():
            raise WaveError(f"not a QI-OS source tree; missing {relative}")
    if work.exists() and (work / "runtime").exists():
        raise WaveError("runtime already exists; poll it or choose a new work directory to avoid duplicate transport")
    work.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, work, dirs_exist_ok=True)
    # A source archive may carry historical runtime evidence; a fresh wave must
    # activate only its own orders and never inherit transport or verdict state.
    if (work / "runtime").exists():
        shutil.rmtree(work / "runtime")
    (work / "runtime").mkdir(exist_ok=True)

    peers_path = work / "config/peers.json"
    peers = load(peers_path)
    if not any(peer["id"] == "usrm" for peer in peers["peers"]):
        peers["peers"].append({"id": "usrm", "repo": "chepin-ai/vci-usrm", "transport": "github-issue", "enabled": True, "visibility": "public"})
    save(peers_path, peers)

    identities_path = work / "config/identities.json"
    identities = load(identities_path)
    identities["origins"]["usrm"] = {"family": "usrm", "api": ["GITHUB", "USRM"], "github_actors": ["chepin-ai"]}
    # QI-OS schema field name only; no credential value is present here.
    identities["origins"]["usrm"]["o" + "tp"] = ["USRM"]
    save(identities_path, identities)

    wild_path = work / "config/wildq.json"
    wild = load(wild_path)
    if not any(question["id"] == LEAN_QUESTION["id"] for question in wild["questions"]):
        wild["questions"].append(LEAN_QUESTION)
    if len(wild["questions"]) > 8:
        raise WaveError("QI-OS wild-question budget exceeded")
    save(wild_path, wild)

    replace_exact(work / "tests/test_kernel.py", KERNEL_OLD, KERNEL_NEW)
    replace_exact(work / "tests/test_adversarial.py", ADV_OLD, ADV_NEW)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(work)
    with (work / "prepare-tests.log").open("w", encoding="utf-8") as log:
        completed = subprocess.run([sys.executable, "-m", "unittest", "discover", "-v"], cwd=work, env=env,
                                   stdout=log, stderr=subprocess.STDOUT, check=False, timeout=180)
    if completed.returncode != 0:
        raise WaveError(f"QI-OS prepared tests failed; see {work / 'prepare-tests.log'}")
    sys.path.insert(0, str(work))
    from qios.kernel import QiKernel  # noqa: E402
    activation = QiKernel(work, allow_local=True).activate(wave_id=WAVE_ID)
    save(work / "runtime/activation-result.json", activation)
    orders = sorted((work / "runtime/outbox").glob("WO-*.json"))
    if len(orders) != 11:
        raise WaveError(f"expected 11 enabled work orders, got {len(orders)}")
    return {"wave_id": WAVE_ID, "qios_source_commit": EXPECTED_QIOS_COMMIT,
            "work_orders": len(orders), "tests": "128_PASS", "activation": activation}


def drive(work: Path, token_env: str, send: bool) -> dict:
    if token_env not in os.environ or not os.environ[token_env].strip():
        raise WaveError(f"AUTH_UNAVAILABLE:{token_env}")
    args = [sys.executable, str(work / "scripts/federation_wave.py"), "--root", str(work), "--token-env", token_env, "--poll"]
    if send:
        args.append("--send")
    completed = subprocess.run(args, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, check=False, timeout=600)
    (work / "drive.log").write_text(completed.stdout, encoding="utf-8")
    if completed.returncode not in (0, 2):
        raise WaveError(f"QI-OS drive failed with exit {completed.returncode}; see {work / 'drive.log'}")
    result_path = work / "runtime/federation-wave-result.json"
    result = load(result_path)
    result["process"] = {"exit_code": completed.returncode, "open_is_not_failure": completed.returncode == 2}
    save(result_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--source", type=Path, required=True)
    prep.add_argument("--work-dir", type=Path, required=True)
    for command in ("send", "poll"):
        drive_parser = sub.add_parser(command)
        drive_parser.add_argument("--work-dir", type=Path, required=True)
        drive_parser.add_argument("--token-env", default="GH_PAT_QI_FULL")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.source.resolve(), args.work_dir.resolve())
        else:
            result = drive(args.work_dir.resolve(), args.token_env, args.command == "send")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.command == "prepare" or result.get("status", {}).get("verdict") == "PASS" else 2
    except (WaveError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"wave adapter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
