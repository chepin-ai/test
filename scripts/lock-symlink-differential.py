#!/usr/bin/env python3
"""Run real old/new CLI processes against preregistered state-lock attacks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import time

SCHEMA = "asfa-lock-symlink-differential/v1"
CASES = ["symlink", "dangling", "regular", "hardlink", "control"]


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(path):
    path = Path(path)
    result = {
        "lexists": os.path.lexists(path),
        "exists": path.exists(),
        "file_type": "absent",
        "is_symlink": path.is_symlink(),
        "sha256": None,
        "identity": None,
        "link_identity": None,
        "nlink": None,
        "json_schema": None,
    }
    if not result["lexists"]:
        return result
    lst = path.lstat()
    result["link_identity"] = [lst.st_dev, lst.st_ino]
    result["nlink"] = lst.st_nlink
    if stat.S_ISLNK(lst.st_mode):
        result["file_type"] = "symlink"
        result["link_target"] = os.readlink(path)
    elif stat.S_ISREG(lst.st_mode):
        result["file_type"] = "regular"
    elif stat.S_ISFIFO(lst.st_mode):
        result["file_type"] = "fifo"
    else:
        result["file_type"] = "other"
    if path.is_file():
        result["sha256"] = sha256(path)
        target = path.stat()
        result["identity"] = [target.st_dev, target.st_ino]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                result["json_schema"] = value["schema_version"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def snapshots(paths):
    return {name: snapshot(path) for name, path in paths.items()}


def state_view(path):
    result = {"sha256": None, "schema_version": None, "pending": None, "consumed": None}
    if not path.is_file():
        return result
    result["sha256"] = sha256(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    result.update(
        schema_version=value.get("schema_version"),
        pending=len(value["directives"]),
        consumed=len(value["consumed"]),
    )
    return result


def run_cli(binary, registry, state, out, consume=False):
    command = [str(binary), "--config", str(registry), "--state", str(state), "--out", str(out), "--now", "100"]
    if consume:
        command.extend(["--consume-session", "exec", "--consume-id", "sum"])
    completed = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    return {"exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}


def prepare(binary, root, repo, registry):
    root.mkdir(parents=True)
    state = root / "state.json"
    initial_report = root / "initial-report.json"
    setup = run_cli(binary, registry, state, initial_report)
    if setup["exit_code"] != 0:
        raise RuntimeError(f"fixture setup failed for {root}: {setup}")
    initial = state_view(state)
    if initial["schema_version"] != "asfa-directive-ledger/v4" or initial["pending"] != 6 or initial["consumed"] != 0:
        raise RuntimeError(f"fixture setup did not produce the preregistered ledger for {root}: {initial}")
    return state, initial_report, setup


def release_fifo(path, process):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    chunks = []
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([descriptor], [], [], 0.1)
            if not readable:
                if process.poll() is not None and not chunks:
                    break
                continue
            chunk = os.read(descriptor, 65536)
            if chunk:
                chunks.append(chunk)
            else:
                break
        else:
            raise TimeoutError(f"FIFO did not reach EOF: {path}")
    finally:
        os.close(descriptor)
    value = b"".join(chunks)
    try:
        parsed = json.loads(value)
        schema = parsed.get("schema_version")
    except (UnicodeDecodeError, json.JSONDecodeError):
        schema = None
    return {"bytes": len(value), "sha256": sha256_bytes(value), "json_schema": schema}


def process_case(binary, attack, root, repo, registry):
    state, initial_report, setup = prepare(binary, root, repo, registry)
    lock = Path(str(state) + ".lock")
    fifo = root / "first-report.fifo"
    second_report = root / "second-report.json"
    paths = {"state": state, "lock": lock, "fifo": fifo, "second_report": second_report}
    initial_state = state_view(state)
    initial = snapshots({"state": state, "lock": lock, "initial_report": initial_report})
    if attack in ("symlink", "hardlink"):
        lock.unlink()
        if attack == "symlink":
            os.symlink("state.json", lock)
        else:
            os.link(state, lock)
    os.mkfifo(fifo)
    armed = snapshots(paths)
    process = subprocess.Popen(
        [str(binary), "--config", str(registry), "--state", str(state), "--out", str(fifo), "--now", "100"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            replaced = snapshot(state)["identity"] != initial["state"]["identity"]
            if replaced or process.poll() is not None:
                break
            time.sleep(0.01)
        else:
            raise TimeoutError(f"first process neither replaced state nor exited: {attack}")
        replaced = snapshot(state)["identity"] != initial["state"]["identity"]
        alive_before_second = process.poll() is None
        second = run_cli(binary, registry, state, second_report, consume=True)
        alive_after_second = process.poll() is None
        at_second = snapshots(paths)
        at_second_state = state_view(state)
        fifo_result = release_fifo(fifo, process)
        stdout, stderr = process.communicate(timeout=15)
        return {
            "setup": setup,
            "paths": {name: str(path) for name, path in paths.items()},
            "initial": initial,
            "initial_state": initial_state,
            "armed": armed,
            "first": {
                "pid": process.pid,
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "alive_before_second": alive_before_second,
                "alive_after_second": alive_after_second,
                "state_replaced_before_second": replaced,
                "fifo": fifo_result,
            },
            "second": second,
            "at_second": at_second,
            "at_second_state": at_second_state,
            "final": snapshots(paths),
            "final_state": state_view(state),
        }
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def single_case(binary, case, root, repo, registry):
    state, initial_report, setup = prepare(binary, root, repo, registry)
    lock = Path(str(state) + ".lock")
    report_path = root / "report.json"
    paths = {"state": state, "lock": lock, "report": report_path}
    if case == "dangling":
        lock.unlink()
        target = root / "missing-lock-target"
        os.symlink("missing-lock-target", lock)
        paths["target"] = target
    initial = snapshots({**paths, "initial_report": initial_report})
    initial_state = state_view(state)
    completed = run_cli(binary, registry, state, report_path)
    return {
        "setup": setup,
        "paths": {name: str(path) for name, path in paths.items()},
        "initial": initial,
        "initial_state": initial_state,
        "run": completed,
        "final": snapshots(paths),
        "final_state": state_view(state),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", type=Path, required=True)
    parser.add_argument("--new-binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path("/tmp/asfa-lock-symlink-differential"))
    args = parser.parse_args()
    repo = args.repo.resolve()
    old_binary = args.old_binary.resolve()
    new_binary = args.new_binary.resolve()
    shutil.rmtree(args.work, ignore_errors=True)
    args.work.mkdir(parents=True)
    outbox = args.work / "outbox.json"
    value = json.loads((repo / "fixtures/qfos-exec-outbox.json").read_text(encoding="utf-8"))
    value["url"] = outbox.as_uri()
    outbox.write_text(json.dumps(value), encoding="utf-8")
    registry = args.work / "registry.json"
    registry.write_text(json.dumps({
        "schema_version": "lock-symlink-poc",
        "network_name": "lock-symlink-poc",
        "trust_model": "unsigned-hash-chain",
        "sessions": {"exec": {"url": outbox.as_uri(), "trust": "unsigned-hash-chain", "allow_file": True}},
    }), encoding="utf-8")
    records = []
    for case in CASES:
        runner = single_case if case in ("dangling", "control") else process_case
        record = {
            "id": case,
            "old": runner(old_binary, case, args.work / case / "old", repo, registry),
            "new": runner(new_binary, case, args.work / case / "new", repo, registry),
        }
        records.append(record)
        if case in ("dangling", "control"):
            print(f"ran {case}: old={record['old']['run']['exit_code']} new={record['new']['run']['exit_code']}")
        else:
            print(f"ran {case}: old first/second={record['old']['first']['exit_code']}/{record['old']['second']['exit_code']} new first/second={record['new']['first']['exit_code']}/{record['new']['second']['exit_code']}")
    report = {
        "schema_version": SCHEMA,
        "baseline_commit": args.baseline_commit,
        "old_binary_sha256": sha256(old_binary),
        "new_binary_sha256": sha256(new_binary),
        "cases": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
