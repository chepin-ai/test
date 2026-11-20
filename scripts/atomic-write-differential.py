#!/usr/bin/env python3
"""Run real old/new CLI processes against predictable temporary-path attacks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

SCHEMA = "asfa-atomic-write-differential/v1"
SENTINEL = b"sentinel\n"
SENTINEL_SHA256 = hashlib.sha256(SENTINEL).hexdigest()
MAX_COLLISIONS = 128
CASES = ["symlink", "hardlink", "regular", "exhaustion", "control"]
EMPTY_REGISTRY = {
    "schema_version": "atomic-differential",
    "network_name": "atomic-differential",
    "trust_model": "unsigned-hash-chain",
    "sessions": {},
}


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
        "is_symlink": path.is_symlink(),
        "sha256": None,
        "json_schema": None,
        "identity": None,
    }
    if path.is_symlink():
        result["link_target"] = os.readlink(path)
    if path.is_file():
        result["sha256"] = sha256(path)
        stat = path.stat()
        result["identity"] = [stat.st_dev, stat.st_ino]
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                result["json_schema"] = value["schema_version"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def snapshots(paths):
    return {name: snapshot(path) for name, path in paths.items()}


def temporary_path(state, pid, serial):
    return state.with_suffix(f".tmp-{pid}-{serial}")


def run_one(binary, case, root, registry):
    root.mkdir(parents=True)
    state = root / "state.json"
    lock = Path(str(state) + ".lock")
    paths = {"state": state, "lock": lock}
    collision_count = MAX_COLLISIONS if case == "exhaustion" else 1
    if case in ("symlink", "hardlink"):
        paths["victim"] = root / "victim.json"
        paths["victim"].write_bytes(SENTINEL)
    before = snapshots(paths)

    def arm_collisions():
        if case == "control":
            return
        pid = os.getpid()
        for serial in range(1, collision_count + 1):
            temporary = temporary_path(state, pid, serial)
            if case == "symlink":
                os.symlink(paths["victim"], temporary)
            elif case == "hardlink":
                os.link(paths["victim"], temporary)
            else:
                with open(temporary, "xb") as handle:
                    handle.write(SENTINEL)

    process = subprocess.Popen(
        [str(binary), "--config", str(registry), "--state", str(state), "--now", "100"],
        cwd=registry.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=arm_collisions,
    )
    stdout, stderr = process.communicate(timeout=30)
    for serial in range(1, collision_count + 1):
        paths[f"temporary_{serial}"] = temporary_path(state, process.pid, serial)
    return {
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "child_pid": process.pid,
        "collision_kind": case,
        "collision_count": 0 if case == "control" else collision_count,
        "sentinel_sha256": SENTINEL_SHA256,
        "paths": {name: str(path) for name, path in paths.items()},
        "before": before,
        "after": snapshots(paths),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", type=Path, required=True)
    parser.add_argument("--new-binary", type=Path, required=True)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old_binary = args.old_binary.resolve()
    new_binary = args.new_binary.resolve()
    work = Path("/tmp/asfa-atomic-write-differential")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    registry = work / "registry.json"
    registry.write_text(json.dumps(EMPTY_REGISTRY), encoding="utf-8")
    records = []
    for case in CASES:
        record = {
            "id": case,
            "old": run_one(old_binary, case, work / case / "old", registry),
            "new": run_one(new_binary, case, work / case / "new", registry),
        }
        records.append(record)
        print(f"ran {case}: old={record['old']['exit_code']} new={record['new']['exit_code']}")
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
