#!/usr/bin/env python3
"""Independent filesystem/oracle adjudication for output-path differentials."""

import argparse
import copy
import json
import os
from pathlib import Path
import tempfile

EXPECTED_BINARY = "457257a5ea0d33f69af7b019edde1e0c301d1431ec6c0f9f254beebe938659ef"
EXPECTED_BASELINE = "4ae57d5106b2f46dc0579e58520766abe4a9df46"
ATTACKS = {
    "poll_parent": ("state", "asfa-bridge-report/v1", "--out"),
    "wave_parent": ("state", "qfos-wave-plan/v1", "--wave-out"),
    "execution_parent": ("state", "qfos-wave-execution/v1", "--execution-out"),
    "dangling_symlink": ("state", "asfa-bridge-report/v1", "--out"),
    "symlinked_parent": ("state", "asfa-bridge-report/v1", "--out"),
    "hardlink_plan_report": ("out", "qfos-wave-plan/v1", "--wave-out"),
}
CASE_ORDER = [*ATTACKS, "dot_control", "distinct_control"]


def same_destination(first, second):
    if os.path.realpath(first) == os.path.realpath(second):
        return True
    try:
        return os.path.samefile(first, second)
    except (FileNotFoundError, OSError):
        return False


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
        import hashlib

        result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        stat = path.stat()
        result["identity"] = [stat.st_dev, stat.st_ino]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                result["json_schema"] = value["schema_version"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate_case(case, check_files=True):
    case_id = case["id"]
    old = case["old"]
    new = case["new"]
    for side in (old, new):
        if check_files:
            for name, path in side["paths"].items():
                require(
                    snapshot(path) == side["after"][name],
                    f"{case_id}: recorded {name} after-state does not match the filesystem",
                )
    if case_id in ATTACKS:
        damaged, schema, second_label = ATTACKS[case_id]
        require(old["exit_code"] == 0, f"{case_id}: old process did not complete")
        require(new["exit_code"] == 2, f"{case_id}: new process did not fail closed")
        require(
            old["after"][damaged]["json_schema"] == schema,
            f"{case_id}: old overwrite known answer is absent",
        )
        require(old["before"] != old["after"], f"{case_id}: old made no observed change")
        require(new["before"] == new["after"], f"{case_id}: new mutated a declared path")
        first_label = "--out" if case_id == "hardlink_plan_report" else "--state"
        require(
            "output path alias" in new["stderr"]
            and first_label in new["stderr"]
            and second_label in new["stderr"],
            f"{case_id}: new rejection lacks explicit alias diagnostics",
        )
        if case_id == "hardlink_plan_report":
            first_path = new["paths"]["out"]
            second_path = new["paths"]["wave"]
        else:
            first_path = new["paths"]["state"]
            second_name = {"--out": "out", "--wave-out": "wave", "--execution-out": "execution"}[second_label]
            second_path = new["paths"][second_name]
        require(same_destination(first_path, second_path), f"{case_id}: independent alias oracle failed")
        require(not new["after"]["lock"]["lexists"], f"{case_id}: new created a state lock")
        if case_id == "execution_parent":
            require(
                new["after"]["state"]["sha256"]
                == "702ec095d0c529d654c9d5585efada2fd8885b40b2a67e03b8a23b014449bd7a",
                "execution_parent: pre-state was not preserved byte-for-byte",
            )
        if case_id == "hardlink_plan_report":
            for name in ("out", "wave"):
                require(new["after"][name]["sha256"] is not None, "hardlink sentinel disappeared")
                require(
                    new["after"][name]["sha256"]
                    == "b5f7e7d285029324d9b3acae19cc05099271454ac98bfc059a92b0581625cd51",
                    "hardlink sentinel bytes changed",
                )
            require(
                new["after"]["out"]["identity"] == new["after"]["wave"]["identity"],
                "hardlink identities unexpectedly separated",
            )
    elif case_id == "dot_control":
        require(old["exit_code"] == new["exit_code"] == 2, "dot control must remain rejected")
        require(old["before"] == old["after"], "old dot control mutated files")
        require(new["before"] == new["after"], "new dot control mutated files")
        require(same_destination(new["paths"]["state"], new["paths"]["out"]), "dot oracle failed")
    elif case_id == "distinct_control":
        require(old["exit_code"] == new["exit_code"] == 0, "distinct control failed")
        for side in (old, new):
            require(side["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", "bad state")
            require(side["after"]["out"]["json_schema"] == "asfa-bridge-report/v1", "bad report")
            require(side["after"]["wave"]["json_schema"] == "qfos-wave-plan/v1", "bad plan")
        for name in ("state", "out", "wave"):
            require(
                old["after"][name]["sha256"] == new["after"][name]["sha256"],
                f"distinct control drifted for {name}",
            )
    else:
        raise AssertionError(f"unknown case {case_id}")


def validate_report(report, check_files=True):
    require(report["schema_version"] == "asfa-output-path-differential/v1", "bad report schema")
    require(report["baseline_commit"] == EXPECTED_BASELINE, "wrong baseline")
    require(report["old_binary_sha256"] == EXPECTED_BINARY, "wrong old binary")
    require([case["id"] for case in report["cases"]] == CASE_ORDER, "missing or reordered cases")
    for case in report["cases"]:
        validate_case(case, check_files=check_files)


def synthetic_valid_case():
    absent = {
        "lexists": False,
        "exists": False,
        "is_symlink": False,
        "sha256": None,
        "json_schema": None,
        "identity": None,
    }
    present = dict(absent, lexists=True, exists=True, sha256="x" * 64)
    damaged = dict(present, json_schema="asfa-bridge-report/v1")
    paths = {"state": "/tmp/self/state.json", "out": "/tmp/self/sub/../state.json", "lock": "/tmp/self/state.json.lock"}
    before = {name: dict(absent) for name in paths}
    old_after = {"state": damaged, "out": damaged, "lock": present}
    return {
        "id": "poll_parent",
        "old": {"exit_code": 0, "stderr": "", "paths": paths, "before": before, "after": old_after},
        "new": {
            "exit_code": 2,
            "stderr": "output path alias: --state and --out",
            "paths": paths,
            "before": before,
            "after": copy.deepcopy(before),
        },
    }


def self_test():
    with tempfile.TemporaryDirectory(prefix="asfa-path-oracle-") as directory:
        root = Path(directory)
        (root / "sub").mkdir()
        state = root / "state.json"
        require(same_destination(state, root / "sub/../state.json"), "parent known answer")
        require(same_destination(state, root / "./state.json"), "dot known answer")
        os.symlink(state, root / "link.json")
        require(same_destination(state, root / "link.json"), "dangling symlink known answer")
        state.write_text("known", encoding="utf-8")
        os.link(state, root / "hard.json")
        require(same_destination(state, root / "hard.json"), "hardlink known answer")
        require(not same_destination(state, root / "distinct.json"), "distinct known answer")
    valid = synthetic_valid_case()
    validate_case(valid, check_files=False)
    mutations = []
    changed = copy.deepcopy(valid)
    changed["new"]["exit_code"] = 0
    mutations.append(changed)
    changed = copy.deepcopy(valid)
    changed["old"]["after"]["state"]["json_schema"] = "asfa-directive-ledger/v4"
    mutations.append(changed)
    changed = copy.deepcopy(valid)
    changed["new"]["after"]["state"]["lexists"] = True
    mutations.append(changed)
    changed = copy.deepcopy(valid)
    changed["new"]["stderr"] = "different files"
    mutations.append(changed)
    changed = copy.deepcopy(valid)
    changed["old"]["exit_code"] = 2
    mutations.append(changed)
    for index, changed in enumerate(mutations):
        try:
            validate_case(changed, check_files=False)
        except AssertionError:
            continue
        raise AssertionError(f"fake report {index} was accepted")
    print("path verifier self-test: PASS (5 path oracles, 5 rejected fake reports)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--skip-filesystem-recheck", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if args.report:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        validate_report(report, check_files=not args.skip_filesystem_recheck)
        print(f"path differential: PASS ({len(report['cases'])} old/new cases)")
    if not args.self_test and not args.report:
        parser.error("provide --self-test and/or --report")


if __name__ == "__main__":
    main()
