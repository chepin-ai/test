#!/usr/bin/env python3
"""Run real old/new CLI processes against preregistered output-path attacks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

SCHEMA = "asfa-output-path-differential/v1"
EMPTY_REGISTRY = {
    "schema_version": "path-poc",
    "network_name": "path-poc",
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


def setup_case(case, root, repo):
    root.mkdir(parents=True)
    paths = {}
    args = []
    if case == "poll_parent":
        (root / "sub").mkdir()
        paths.update(state=root / "state.json", out=root / "sub/../state.json")
        args = ["--state", paths["state"], "--out", paths["out"], "--now", "100"]
    elif case == "wave_parent":
        (root / "sub").mkdir()
        paths.update(state=root / "state.json", wave=root / "sub/../state.json")
        args = ["--state", paths["state"], "--wave-out", paths["wave"], "--now", "100"]
    elif case == "execution_parent":
        (root / "sub").mkdir()
        paths.update(
            state=root / "state.json",
            wave=root / "plan.json",
            execution=root / "sub/../state.json",
        )
        shutil.copyfile(repo / "fixtures/qfos-exec-pre-state.json", paths["state"])
        shutil.copyfile(repo / "fixtures/qfos-exec-plan.json", paths["wave"])
        args = [
            "--state",
            paths["state"],
            "--wave-out",
            paths["wave"],
            "--execute-wave",
            "--execution-out",
            paths["execution"],
            "--now",
            "100",
        ]
    elif case == "dangling_symlink":
        paths.update(state=root / "state.json", out=root / "report.json")
        os.symlink(paths["state"], paths["out"])
        args = ["--state", paths["state"], "--out", paths["out"], "--now", "100"]
    elif case == "symlinked_parent":
        (root / "real").mkdir()
        os.symlink(root / "real", root / "linked")
        paths.update(state=root / "real/state.json", out=root / "linked/state.json")
        args = ["--state", paths["state"], "--out", paths["out"], "--now", "100"]
    elif case == "hardlink_plan_report":
        paths.update(
            state=root / "state.json",
            out=root / "report.json",
            wave=root / "plan.json",
        )
        paths["out"].write_text("sentinel\n", encoding="utf-8")
        os.link(paths["out"], paths["wave"])
        args = [
            "--state",
            paths["state"],
            "--out",
            paths["out"],
            "--wave-out",
            paths["wave"],
            "--now",
            "100",
        ]
    elif case == "dot_control":
        paths.update(state=root / "state.json", out=root / "./state.json")
        args = ["--state", paths["state"], "--out", paths["out"], "--now", "100"]
    elif case == "distinct_control":
        paths.update(
            state=root / "nested/state.json",
            out=root / "report.json",
            wave=root / "plan.json",
        )
        args = [
            "--state",
            paths["state"],
            "--out",
            paths["out"],
            "--wave-out",
            paths["wave"],
            "--now",
            "100",
        ]
    else:
        raise ValueError(case)
    if "state" in paths:
        paths["lock"] = Path(str(paths["state"]) + ".lock")
    return paths, [str(value) for value in args]


def run_one(binary, case, root, repo, registry):
    paths, args = setup_case(case, root, repo)
    config = repo / "config/sessions.execution.json" if case == "execution_parent" else registry
    before = snapshots(paths)
    completed = subprocess.run(
        [str(binary), "--config", str(config), *args],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "paths": {name: str(path) for name, path in paths.items()},
        "before": before,
        "after": snapshots(paths),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", type=Path, required=True)
    parser.add_argument("--new-binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    old_binary = args.old_binary.resolve()
    new_binary = args.new_binary.resolve()
    work = Path("/tmp/asfa-path-differential")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    registry = work / "registry.json"
    registry.write_text(json.dumps(EMPTY_REGISTRY), encoding="utf-8")
    cases = [
        "poll_parent",
        "wave_parent",
        "execution_parent",
        "dangling_symlink",
        "symlinked_parent",
        "hardlink_plan_report",
        "dot_control",
        "distinct_control",
    ]
    records = []
    for case in cases:
        records.append(
            {
                "id": case,
                "old": run_one(old_binary, case, work / case / "old", repo, registry),
                "new": run_one(new_binary, case, work / case / "new", repo, registry),
            }
        )
        print(f"ran {case}: old={records[-1]['old']['exit_code']} new={records[-1]['new']['exit_code']}")
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
