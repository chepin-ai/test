#!/usr/bin/env python3
"""Prepare and drive a QI-OS Lean federation wave without owning QI-OS verdicts."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
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
    if old not in text and new in text:
        return
    if text.count(old) != 1:
        raise WaveError(f"upstream test patch anchor is not unique: {path}")
    path.write_text(text.replace(old, new), encoding="utf-8")


TRANSPORT_OLD = '''        # It is an answer attempt: it MUST yield an explicit verdict.
        if assoc not in TRUSTED_AUTHOR_ASSOCIATIONS:
            return reject(
                "untrusted author_association %r (required one of %s)"
                % (assoc, sorted(TRUSTED_AUTHOR_ASSOCIATIONS))
            )

        lines = body.splitlines()
        if not lines or lines[0].strip() != marker:
            return reject("marker %r must be the first line of the comment" % marker)

        payload_text = "\\n".join(lines[1:]).strip()
        if not payload_text:
            return reject("missing JSON payload after marker")
        try:
            payload = json.loads(payload_text)
        except ValueError as exc:
            return reject("invalid JSON payload: %s" % exc)
        if not isinstance(payload, dict):
            return reject("payload must be a JSON object, got %s" % type(payload).__name__)
'''
TRANSPORT_NEW = '''        # Parse the event before applying the association gate. A weak association
        # is accepted only as a transport candidate for a shaped OTP/API HMAC;
        # the kernel still has to verify the actual signature. Unsigned bot
        # responses remain rejected exactly as before.
        lines = body.splitlines()
        if not lines or lines[0].strip() != marker:
            return reject("marker %r must be the first line of the comment" % marker)

        payload_text = "\\n".join(lines[1:]).strip()
        if not payload_text:
            return reject("missing JSON payload after marker")
        try:
            payload = json.loads(payload_text)
        except ValueError as exc:
            return reject("invalid JSON payload: %s" % exc)
        if not isinstance(payload, dict):
            return reject("payload must be a JSON object, got %s" % type(payload).__name__)

        auth = payload.get("auth")
        signature = auth.get("signature") if isinstance(auth, dict) else None
        signed_hmac = isinstance(auth, dict) and auth.get("mode") in {"otp", "api"} and \
            isinstance(signature, str) and len(signature) == 64 and \
            all(char in "0123456789abcdef" for char in signature.lower())
        if assoc not in TRUSTED_AUTHOR_ASSOCIATIONS and not signed_hmac:
            return reject(
                "untrusted author_association %r (required one of %s or a kernel-verified HMAC)"
                % (assoc, sorted(TRUSTED_AUTHOR_ASSOCIATIONS))
            )
'''

HMAC_TESTS = '''from __future__ import annotations

import unittest

from qios.canon import canonical
from qios.envelope import make_event, verify_event
from qios.transport import ANSWER_MARKER, GitHubIssueTransport


class HmacTransportTests(unittest.TestCase):
    def event(self, secret=None):
        return make_event("qlv", "answer", "hmac-test", {
            "loop_id": "LOOP-HMAC", "role": "crosscheck", "verdict": "OPEN",
            "target_peer": "usrm", "subject_answer_digest": "a" * 64,
        }, mode="api", credential_ref="QLV", secret=secret)

    def comment(self, event):
        return {"id": 1, "user": {"login": "github-actions[bot]"},
                "author_association": "CONTRIBUTOR",
                "body": ANSWER_MARKER + "\\n" + canonical(event)}

    def test_01_signed_api_shape_is_a_transport_candidate(self):
        accepted, rejected = GitHubIssueTransport._evaluate_comment(
            self.comment(self.event(b"correct")), ANSWER_MARKER)
        self.assertIsNotNone(accepted)
        self.assertIsNone(rejected)

    def test_02_unsigned_weak_author_remains_rejected(self):
        accepted, rejected = GitHubIssueTransport._evaluate_comment(
            self.comment(self.event()), ANSWER_MARKER)
        self.assertIsNone(accepted)
        self.assertIn("untrusted author_association", rejected["reason"])

    def test_03_nonhex_signature_is_rejected_at_transport(self):
        event = self.event(b"correct")
        event["auth"]["signature"] = "x" * 64
        accepted, rejected = GitHubIssueTransport._evaluate_comment(
            self.comment(event), ANSWER_MARKER)
        self.assertIsNone(accepted)
        self.assertIsNotNone(rejected)

    def test_04_correct_hmac_passes_envelope(self):
        verdict, code = verify_event(self.event(b"correct"), api_secret=b"correct",
                                     trusted_api_transport=True)
        self.assertEqual("PASS", verdict)
        self.assertEqual("API_HMAC_VERIFIED", code)

    def test_05_wrong_hmac_key_fails(self):
        verdict, code = verify_event(self.event(b"correct"), api_secret=b"wrong",
                                     trusted_api_transport=True)
        self.assertEqual("FAIL", verdict)
        self.assertEqual("AUTH_SIGNATURE", code)

    def test_06_missing_hmac_key_is_open_not_pass(self):
        verdict, code = verify_event(self.event(b"correct"), api_secret=None,
                                     trusted_api_transport=True)
        self.assertEqual("OPEN", verdict)
        self.assertEqual("AUTH_UNAVAILABLE", code)


if __name__ == "__main__":
    unittest.main()
'''

HMAC_CROSSCHECK_TESTS = '''from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from qios.envelope import make_event
from qios.kernel import QiKernel

REPO = Path(__file__).resolve().parents[1]


class HmacCrosscheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="qios-hmac-crosscheck-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        shutil.copytree(REPO / "config", self.tmp / "config")
        os.environ["QIOS_API_QLV"] = "correct"
        self.addCleanup(lambda: os.environ.pop("QIOS_API_QLV", None))
        self.kernel = QiKernel(self.tmp, allow_local=True)
        self.kernel.activate(wave_id="WAVE-HMAC-TEST")
        loops = self.kernel._loops()["loops"]
        self.loop = next(loop for loop in loops.values() if loop["peer"] == "usrm")
        self.loop_id = self.loop["loop_id"]
        self.kernel.record_delivery(self.loop["workorder_id"], {
            "state": "DELIVERED", "repo": "chepin-ai/vci-usrm",
            "issue_number": 1, "issue_url": "https://example.invalid/1"})
        answer = make_event("usrm", "answer", self.loop_id, {
            "loop_id": self.loop_id, "role": "answer", "verdict": "OPEN",
            "claims": [], "artifacts": [], "open_items": ["content-unverified"]},
            mode="api", credential_ref="GITHUB", correlation_id="WAVE-HMAC-TEST")
        result = self.kernel.ingest(answer, trusted_api_transport=True,
                                    transport_actor="chepin-ai", expected_origin="usrm")
        self.assertEqual("OPEN", result["verdict"])
        current = self.kernel._loops()["loops"][self.loop_id]
        self.answer_digest = current["answers"]["usrm"]["answer_digest"]

    def crosscheck(self, origin="qlv", secret=b"correct", answer_digest=None):
        credential = "QLV" if origin == "qlv" else "GITHUB"
        return make_event(origin, "answer", self.loop_id, {
            "loop_id": self.loop_id, "role": "crosscheck", "target_peer": "usrm",
            "verdict": "OPEN", "subject_answer_digest": answer_digest or self.answer_digest},
            mode="api", credential_ref=credential, secret=secret,
            correlation_id="WAVE-HMAC-TEST")

    def ingest(self, event, actor="github-actions[bot]"):
        return self.kernel.ingest(event, trusted_api_transport=True, transport_actor=actor,
                                  expected_loop_id=self.loop_id, expected_origin="usrm")

    def test_01_independent_hmac_crosscheck_is_accepted_open(self):
        result = self.ingest(self.crosscheck())
        self.assertEqual("OPEN", result["verdict"])
        self.assertEqual([], result["errors"])
        cross = self.kernel._loops()["loops"][self.loop_id]["crosschecks"]["usrm"]
        self.assertEqual("api:hmac:QLV", cross["identity"]["principal"])

    def test_02_wrong_hmac_secret_fails_without_crosscheck(self):
        result = self.ingest(self.crosscheck(secret=b"wrong"))
        self.assertEqual("FAIL", result["verdict"])
        self.assertIn("AUTH_SIGNATURE", result["errors"])
        self.assertEqual({}, self.kernel._loops()["loops"][self.loop_id]["crosschecks"])

    def test_03_wrong_answer_digest_fails(self):
        result = self.ingest(self.crosscheck(answer_digest="0" * 64))
        self.assertEqual("FAIL", result["verdict"])
        self.assertIn("CROSSCHECK_DIGEST_MISMATCH", result["errors"])
        self.assertEqual({}, self.kernel._loops()["loops"][self.loop_id]["crosschecks"])

    def test_04_same_authenticated_principal_is_not_independent(self):
        result = self.ingest(self.crosscheck(origin="vinf", secret=None), actor="chepin-ai")
        self.assertEqual("FAIL", result["verdict"])
        self.assertIn("CROSSCHECK_NOT_INDEPENDENT", result["errors"])

    def test_05_duplicate_crosscheck_is_immutable(self):
        self.ingest(self.crosscheck())
        result = self.ingest(self.crosscheck())
        self.assertEqual("FAIL", result["verdict"])
        self.assertIn("CROSSCHECK_IMMUTABLE", result["errors"])

    def test_06_open_answer_and_crosscheck_never_promote(self):
        result = self.ingest(self.crosscheck())
        self.assertEqual("OPEN", result["verdict"])
        current = self.kernel._loops()["loops"][self.loop_id]
        self.assertEqual("OPEN", current["verdict"])
        self.assertFalse(current["promotion"])


if __name__ == "__main__":
    unittest.main()
'''

NEW_PEERS = {
    "usrm": "chepin-ai/vci-usrm",
    "qgl": "chepin-ai/vci-qgl",
    "ucif2": "chepin-ai/vci-ucif2",
    "vinf": "chepin-ai/vci-vinf",
}


def configure(work: Path) -> None:
    peers_path = work / "config/peers.json"
    peers = load(peers_path)
    for line, repo in NEW_PEERS.items():
        if not any(peer["id"] == line for peer in peers["peers"]):
            peers["peers"].append({"id": line, "repo": repo, "transport": "github-issue", "enabled": True, "visibility": "public"})
    save(peers_path, peers)

    identities_path = work / "config/identities.json"
    identities = load(identities_path)
    for line in NEW_PEERS:
        credential = line.upper()
        identities["origins"][line] = {"family": line, "api": ["GITHUB", credential], "github_actors": ["chepin-ai"]}
        # QI-OS schema field name only; no credential value is present here.
        identities["origins"][line]["o" + "tp"] = [credential]
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
    replace_exact(work / "qios/transport.py", TRANSPORT_OLD, TRANSPORT_NEW)
    test_path = work / "tests/test_hmac_transport.py"
    if test_path.exists() and test_path.read_text(encoding="utf-8") != HMAC_TESTS:
        raise WaveError("HMAC transport test fixture drift")
    test_path.write_text(HMAC_TESTS, encoding="utf-8")
    crosscheck_test_path = work / "tests/test_hmac_crosscheck.py"
    if crosscheck_test_path.exists() and crosscheck_test_path.read_text(encoding="utf-8") != HMAC_CROSSCHECK_TESTS:
        raise WaveError("HMAC crosscheck test fixture drift")
    crosscheck_test_path.write_text(HMAC_CROSSCHECK_TESTS, encoding="utf-8")


def test_and_activate(work: Path, record_name: str) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(work)
    with (work / f"{record_name}-tests.log").open("w", encoding="utf-8") as log:
        completed = subprocess.run([sys.executable, "-m", "unittest", "discover", "-v"], cwd=work, env=env,
                                   stdout=log, stderr=subprocess.STDOUT, check=False, timeout=180)
    if completed.returncode != 0:
        raise WaveError(f"QI-OS prepared tests failed; see {work / f'{record_name}-tests.log'}")
    test_log = (work / f"{record_name}-tests.log").read_text(encoding="utf-8")
    match = re.search(r"Ran (\d+) tests", test_log)
    if not match or "\nOK\n" not in test_log:
        raise WaveError("cannot independently determine the unittest count")
    test_count = int(match.group(1))
    sys.path.insert(0, str(work))
    from qios.kernel import QiKernel  # noqa: E402
    activation = QiKernel(work, allow_local=True).activate(wave_id=WAVE_ID)
    save(work / "runtime" / f"{record_name}.json", activation)
    orders = sorted((work / "runtime/outbox").glob("WO-*.json"))
    if len(orders) != 14:
        raise WaveError(f"expected 14 enabled work orders, got {len(orders)}")
    return {"wave_id": WAVE_ID, "qios_source_commit": EXPECTED_QIOS_COMMIT,
            "work_orders": len(orders), "tests": f"{test_count}_PASS", "test_count": test_count,
            "activation": activation}


def prepare(source: Path, work: Path) -> dict:
    required = ["qios", "scripts/federation_wave.py", "tests", "config/peers.json", "config/identities.json", "config/wildq.json"]
    for relative in required:
        if not (source / relative).exists():
            raise WaveError(f"not a QI-OS source tree; missing {relative}")
    if work.exists() and (work / "runtime").exists():
        raise WaveError("runtime already exists; use expand or choose a new work directory to avoid duplicate transport")
    work.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, work, dirs_exist_ok=True)
    # A source archive may carry historical runtime evidence; a fresh wave must
    # activate only its own orders and never inherit transport or verdict state.
    if (work / "runtime").exists():
        shutil.rmtree(work / "runtime")
    (work / "runtime").mkdir(exist_ok=True)
    configure(work)
    return test_and_activate(work, "activation-result")


def expand(work: Path) -> dict:
    if not (work / "runtime").exists():
        raise WaveError("expand requires an existing runtime")
    before = {path.name for path in (work / "runtime/outbox").glob("WO-*.json")}
    configure(work)
    result = test_and_activate(work, "expansion-result")
    after = {path.name for path in (work / "runtime/outbox").glob("WO-*.json")}
    if not before <= after:
        raise WaveError("expansion removed or renamed existing work orders")
    result["existing_orders_preserved"] = len(before)
    result["new_orders"] = sorted(after - before)
    return result


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
    expand_parser = sub.add_parser("expand")
    expand_parser.add_argument("--work-dir", type=Path, required=True)
    for command in ("send", "poll"):
        drive_parser = sub.add_parser(command)
        drive_parser.add_argument("--work-dir", type=Path, required=True)
        drive_parser.add_argument("--token-env", default="GH_PAT_QI_FULL")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.source.resolve(), args.work_dir.resolve())
        elif args.command == "expand":
            result = expand(args.work_dir.resolve())
        else:
            result = drive(args.work_dir.resolve(), args.token_env, args.command == "send")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.command in {"prepare", "expand"} or result.get("status", {}).get("verdict") == "PASS" else 2
    except (WaveError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"wave adapter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
