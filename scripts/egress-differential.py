#!/usr/bin/env python3
"""Process-level old/new differential for the qfos bridge egress gate."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "egress_oracle", Path(__file__).with_name("verify-egress-python.py")
)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def outbox(url):
    genesis = "0" * 64
    return json.dumps({
        "session": "node",
        "url": url,
        "trust": "unsigned-hash-chain",
        "directives": [],
        "mailbox": {},
        "hash_chain": {
            "genesis": genesis,
            "latest": genesis,
            "height": 0,
            "blocks": [],
        },
    }, separators=(",", ":"))


class OneShotServer:
    def __init__(self, body):
        self.body = body.encode() if isinstance(body, str) else bytes(body)
        self.hits = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(5)
        self.address = "127.0.0.1:%d" % self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            connection, _ = self.sock.accept()
            with connection:
                self.hits += 1
                connection.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 16384:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(self.body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + self.body
                )
                connection.sendall(response)
        except (OSError, socket.timeout):
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=1)


def registry(url, network, unknown_field=False):
    session = {
        "url": url,
        "role": "egress-differential",
        "trust": "unsigned-hash-chain",
        "allow_insecure_http": True,
    }
    if unknown_field:
        session["allow_non_public_egress"] = True
    return {
        "schema_version": "egress-differential",
        "network_name": network,
        "trust_model": "unsigned-hash-chain",
        "sessions": {"node": session},
    }


def is_verified(report):
    return (
        report["summary"] == {"total": 1, "verified": 1, "failed": 0}
        and len(report["records"]) == 1
        and report["records"][0]["status"]["kind"] == "verified"
    )


def run_case(binary, directory, name, allow=False, unknown_field=False, hostile_proxy=False):
    case_dir = directory / name
    case_dir.mkdir()
    url_path = case_dir / "url.txt"
    # Construct the URL after binding but before starting the child. The body
    # served by both target and proxy is identical, so only socket hit counts
    # distinguish the actual route.
    holder = {}
    url = "http://placeholder"
    body = outbox(url)
    target = OneShotServer(body)
    url = f"http://{target.address}/outbox"
    target.body = outbox(url).encode()
    url_path.write_text(url, encoding="utf-8")
    proxy = OneShotServer(target.body) if hostile_proxy else None
    config = case_dir / "registry.json"
    report_path = case_dir / "report.json"
    config.write_text(json.dumps(registry(url, name, unknown_field)), encoding="utf-8")
    command = [
        str(binary), "--config", str(config), "--out", str(report_path),
        "--now", "100", "--fail-on-error",
    ]
    if allow:
        command.append("--allow-non-public-egress")
    environment = os.environ.copy()
    for key in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "NO_PROXY"]:
        environment.pop(key, None)
    if hostile_proxy:
        for key in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            environment[key] = f"http://{proxy.address}"
        environment["NO_PROXY"] = ""
        environment["no_proxy"] = ""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, cwd=ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        time.sleep(0.05)
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
        return {
            "command": command,
            "exit": completed.returncode,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "target_hits": target.hits,
            "proxy_hits": proxy.hits if proxy else 0,
            "report": report,
            "report_sha256": sha256(report_path) if report else None,
            "stderr": completed.stderr,
        }
    finally:
        target.close()
        if proxy:
            proxy.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True, type=Path)
    parser.add_argument("--new", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert ORACLE.self_test()[0] == 48
    with tempfile.TemporaryDirectory(prefix="asfa-egress-differential-") as temp:
        directory = Path(temp)
        old = run_case(args.old, directory, "EGR-02-old-loopback")
        assert old["exit"] == 0 and old["target_hits"] == 1 and is_verified(old["report"]), old
        new = run_case(args.new, directory, "EGR-02-new-loopback")
        assert new["exit"] == 2 and new["target_hits"] == 0, new
        ORACLE.verify_blocked_report(new["report"], new["target_hits"])
        explicit = run_case(args.new, directory, "EGR-04-explicit-local-proxy-bypass", allow=True, hostile_proxy=True)
        assert explicit["exit"] == 0 and explicit["target_hits"] == 1 and explicit["proxy_hits"] == 0, explicit
        assert is_verified(explicit["report"]), explicit
        unknown = run_case(args.new, directory, "EGR-06-registry-escape", unknown_field=True)
        assert unknown["exit"] == 2 and unknown["target_hits"] == 0 and unknown["report"] is None, unknown
        assert "unknown field" in unknown["stderr"], unknown
    evidence = {
        "schema_version": "asfa-egress-differential/v1",
        "recorded_at": "2026-11-17",
        "old_binary": {"path": str(args.old), "sha256": sha256(args.old)},
        "new_binary": {"path": str(args.new), "sha256": sha256(args.new)},
        "independent_oracle": {
            "address_cases": 48,
            "self_test": "PASS",
            "rejected_false_reports": [
                "wrong_status", "false_verified_summary", "actual_connection", "extra_record"
            ],
        },
        "cases": {
            "EGR-02-old-loopback": old,
            "EGR-02-new-loopback": new,
            "EGR-04-explicit-local-proxy-bypass": explicit,
            "EGR-06-registry-escape": unknown,
        },
        "differential_verdict": "PASS",
        "scope": "Application-layer bridge HTTP client only; not a network namespace, egress proxy, or hostile-OS boundary.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("egress differential: PASS old=verified/1-hit new=blocked/0-hit explicit=verified/1-hit proxy=0-hit registry_escape=rejected")


if __name__ == "__main__":
    main()
