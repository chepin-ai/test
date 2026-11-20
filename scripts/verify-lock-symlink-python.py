#!/usr/bin/env python3
"""Independent process/filesystem adjudication for state-lock differentials."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

EXPECTED_BASELINE = "be95cba53c25cd04e1f1dd25fe437a09f6a9f2bd"
EXPECTED_OLD_BINARY = "d7c7d8ee03616322193c5a4a7db92171b5dc9fb1b03346cca9f307b816a92280"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CASE_ORDER = ["symlink", "dangling", "regular", "hardlink", "control"]


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


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def require_initial(side, label):
    require(side["setup"]["exit_code"] == 0, f"{label}: fixture setup failed")
    initial = side["initial_state"]
    require(initial["schema_version"] == "asfa-directive-ledger/v4", f"{label}: wrong initial schema")
    require(initial["pending"] == 6 and initial["consumed"] == 0, f"{label}: wrong initial ledger")
    require(len(initial["sha256"]) == 64, f"{label}: missing initial hash")


def require_unchanged(side, label, same_inode=True):
    require(side["at_second_state"] == side["initial_state"], f"{label}: state bytes or counts changed")
    require(side["final_state"] == side["initial_state"], f"{label}: final state changed")
    if same_inode:
        require(side["at_second"]["state"]["identity"] == side["initial"]["state"]["identity"], f"{label}: state inode changed")


def require_fifo_report(side, label):
    fifo = side["first"]["fifo"]
    require(fifo["bytes"] > 0 and fifo["json_schema"] == "asfa-bridge-report/v1", f"{label}: first FIFO report is absent or invalid")
    require(len(fifo["sha256"]) == 64 and fifo["sha256"] != EMPTY_SHA256, f"{label}: wrong FIFO hash")


def validate_symlink(case, check_files):
    old, new = case["old"], case["new"]
    require(old["armed"]["lock"]["file_type"] == "symlink", "symlink: old lock was not armed")
    require(old["armed"]["lock"].get("link_target") == "state.json", "symlink: wrong old target")
    require(old["armed"]["lock"]["identity"] == old["initial"]["state"]["identity"], "symlink: old lock did not target initial state")
    require(old["first"]["alive_before_second"] and old["first"]["alive_after_second"], "symlink: old first process was not alive during second consumption")
    require(old["first"]["state_replaced_before_second"], "symlink: old state was not replaced before second process")
    require(old["first"]["exit_code"] == 0 and old["second"]["exit_code"] == 0, "symlink: old exploit processes did not complete")
    require(old["at_second_state"]["pending"] == 5 and old["at_second_state"]["consumed"] == 1, "symlink: old second process did not consume sum")
    require(old["at_second_state"]["sha256"] != old["initial_state"]["sha256"], "symlink: old state bytes did not change")
    require(old["at_second"]["state"]["identity"] != old["initial"]["state"]["identity"], "symlink: old state inode did not change")
    require(old["at_second"]["lock"]["identity"] == old["at_second"]["state"]["identity"], "symlink: old lock did not migrate to replacement state inode")
    require(old["at_second"]["second_report"]["json_schema"] == "asfa-bridge-report/v1", "symlink: old second report is absent")
    require_fifo_report(old, "symlink old")

    require(new["armed"]["lock"]["file_type"] == "symlink", "symlink: new lock was not armed")
    require(new["first"]["exit_code"] == 2 and new["second"]["exit_code"] == 2, "symlink: new processes did not fail closed")
    require(not new["first"]["alive_before_second"] and not new["first"]["alive_after_second"], "symlink: new first process unexpectedly remained alive")
    require(not new["first"]["state_replaced_before_second"], "symlink: new replaced state")
    require(new["first"]["fifo"]["bytes"] == 0 and new["first"]["fifo"]["sha256"] == EMPTY_SHA256, "symlink: new wrote a FIFO report")
    require(new["at_second"]["second_report"]["file_type"] == "absent", "symlink: new wrote a second report")
    require("must not be a symbolic link" in new["first"]["stderr"], "symlink: new first diagnostic is absent")
    require("must not be a symbolic link" in new["second"]["stderr"], "symlink: new second diagnostic is absent")
    require("polled=" not in new["first"]["stderr"] and "polled=" not in new["second"]["stderr"], "symlink: new reached poll completion")
    require_unchanged(new, "symlink new")
    require(new["final"]["lock"]["file_type"] == "symlink" and new["final"]["lock"].get("link_target") == "state.json", "symlink: new altered the lock symlink")


def validate_excluding_process(case, check_files):
    case_id = case["id"]
    for label, side in (("old", case["old"]), ("new", case["new"])):
        prefix = f"{case_id} {label}"
        require(side["first"]["alive_before_second"] and side["first"]["alive_after_second"], f"{prefix}: first process not alive")
        require(side["first"]["state_replaced_before_second"], f"{prefix}: state was not atomically replaced")
        require(side["first"]["exit_code"] == 0, f"{prefix}: first process failed")
        require(side["second"]["exit_code"] == 2, f"{prefix}: second process acquired the lock")
        require("state is already locked" in side["second"]["stderr"], f"{prefix}: explicit contention diagnostic absent")
        require(side["at_second"]["second_report"]["file_type"] == "absent", f"{prefix}: contested second process wrote a report")
        require_fifo_report(side, prefix)
        require_unchanged(side, prefix, same_inode=False)
        require(side["at_second"]["lock"]["file_type"] == "regular", f"{prefix}: sidecar type changed")
        require(side["at_second"]["lock"]["identity"] == side["armed"]["lock"]["identity"], f"{prefix}: sidecar inode moved")
        require(side["at_second"]["lock"]["identity"] != side["at_second"]["state"]["identity"], f"{prefix}: sidecar migrated to replacement state")
        if case_id == "hardlink":
            require(side["armed"]["lock"]["identity"] == side["initial"]["state"]["identity"], f"{prefix}: hardlink did not share initial state inode")


def validate_single(case, check_files):
    case_id = case["id"]
    old, new = case["old"], case["new"]
    if case_id == "dangling":
        for label, side in (("old", old), ("new", new)):
            require(side["initial"]["lock"]["file_type"] == "symlink", f"dangling {label}: lock was not armed")
            require(side["initial"]["lock"].get("link_target") == "missing-lock-target", f"dangling {label}: wrong target")
            require(side["final_state"] == side["initial_state"], f"dangling {label}: state changed")
            require(side["final"]["lock"]["file_type"] == "symlink", f"dangling {label}: lock was replaced")
        require(old["run"]["exit_code"] == 0, "dangling: old control run failed")
        require(old["final"]["target"]["file_type"] == "regular", "dangling: old did not create the followed target")
        require(old["final"]["report"]["json_schema"] == "asfa-bridge-report/v1", "dangling: old report absent")
        require(new["run"]["exit_code"] == 2, "dangling: new did not fail closed")
        require(new["final"]["target"]["file_type"] == "absent", "dangling: new created the target")
        require(new["final"]["report"]["file_type"] == "absent", "dangling: new wrote a report")
        require("must not be a symbolic link" in new["run"]["stderr"], "dangling: explicit diagnostic absent")
    elif case_id == "control":
        for label, side in (("old", old), ("new", new)):
            require(side["run"]["exit_code"] == 0, f"control {label}: run failed")
            require(side["final_state"] == side["initial_state"], f"control {label}: state changed")
            require(side["final"]["state"]["file_type"] == "regular", f"control {label}: state not regular")
            require(side["final"]["lock"]["file_type"] == "regular", f"control {label}: lock not regular")
            require(side["final"]["report"]["json_schema"] == "asfa-bridge-report/v1", f"control {label}: report invalid")
        require(old["final"]["state"]["sha256"] == new["final"]["state"]["sha256"], "control: old/new state bytes drifted")
        require(old["final"]["report"]["sha256"] == new["final"]["report"]["sha256"], "control: old/new report bytes drifted")
    else:
        raise AssertionError(f"unknown single case {case_id}")


def validate_case(case, check_files=True):
    case_id = case["id"]
    for label, side in (("old", case["old"]), ("new", case["new"])):
        require_initial(side, f"{case_id} {label}")
        if check_files:
            for name, path in side["paths"].items():
                require(snapshot(path) == side["final"][name], f"{case_id} {label}: final {name} does not match filesystem")
    if case_id == "symlink":
        validate_symlink(case, check_files)
    elif case_id in ("regular", "hardlink"):
        validate_excluding_process(case, check_files)
    else:
        validate_single(case, check_files)


def validate_source(path):
    source = path.read_text(encoding="utf-8")
    require("std::fs::symlink_metadata(&lock_path)" in source, "source: portable symlink precheck absent")
    require("options.custom_flags(libc::O_NOFOLLOW);" in source, "source: Unix O_NOFOLLOW absent")
    require(source.index("options.custom_flags(libc::O_NOFOLLOW);") < source.index("options.open(&lock_path)?"), "source: O_NOFOLLOW is not applied before open")
    require("file.try_lock_exclusive()" in source, "source: exclusive lock acquisition absent")


def validate_report(report, source=None, check_files=True):
    require(report["schema_version"] == "asfa-lock-symlink-differential/v1", "bad report schema")
    require(report["baseline_commit"] == EXPECTED_BASELINE, "wrong baseline commit")
    require(report["old_binary_sha256"] == EXPECTED_OLD_BINARY, "wrong old binary")
    require(len(report["new_binary_sha256"]) == 64 and report["new_binary_sha256"] != report["old_binary_sha256"], "wrong new binary anchor")
    require([case["id"] for case in report["cases"]] == CASE_ORDER, "missing or reordered cases")
    initial_hashes = {side["initial_state"]["sha256"] for case in report["cases"] for side in (case["old"], case["new"])}
    require(len(initial_hashes) == 1, "initial ledger bytes drifted across cases or old/new binaries")
    for case in report["cases"]:
        validate_case(case, check_files=check_files)
    if source is not None:
        validate_source(source)


def entry(kind="absent", identity=None, sha=None, schema=None, target=None):
    value = {
        "lexists": kind != "absent", "exists": kind != "absent", "file_type": kind,
        "is_symlink": kind == "symlink", "sha256": sha, "identity": identity,
        "link_identity": identity, "nlink": 1 if kind != "absent" else None, "json_schema": schema,
    }
    if kind == "symlink":
        value["exists"] = True
        value["link_target"] = target
    return value


def state(sha, pending, consumed):
    return {"sha256": sha, "schema_version": "asfa-directive-ledger/v4", "pending": pending, "consumed": consumed}


def synthetic_symlink_side(vulnerable):
    initial_sha, final_sha = "a" * 64, "b" * 64 if vulnerable else "a" * 64
    initial_state_id, final_state_id = [1, 1], [1, 4] if vulnerable else [1, 1]
    initial_lock = entry("regular", [1, 2])
    armed_lock = entry("symlink", initial_state_id, target="state.json")
    at_state = entry("regular", final_state_id, final_sha, "asfa-directive-ledger/v4")
    at_lock = entry("symlink", final_state_id, target="state.json")
    report = entry("regular", [1, 8], "c" * 64, "asfa-bridge-report/v1") if vulnerable else entry()
    return {
        "setup": {"exit_code": 0},
        "paths": {"state": "/self/state", "lock": "/self/lock", "fifo": "/self/fifo", "second_report": "/self/second"},
        "initial": {"state": entry("regular", initial_state_id, initial_sha), "lock": initial_lock},
        "initial_state": state(initial_sha, 6, 0),
        "armed": {"lock": armed_lock},
        "first": {
            "exit_code": 0 if vulnerable else 2, "alive_before_second": vulnerable,
            "alive_after_second": vulnerable, "state_replaced_before_second": vulnerable,
            "stdout": "", "stderr": "" if vulnerable else "must not be a symbolic link",
            "fifo": {"bytes": 100 if vulnerable else 0, "sha256": "d" * 64 if vulnerable else EMPTY_SHA256,
                     "json_schema": "asfa-bridge-report/v1" if vulnerable else None},
        },
        "second": {"exit_code": 0 if vulnerable else 2, "stderr": "" if vulnerable else "must not be a symbolic link"},
        "at_second": {"state": at_state, "lock": at_lock, "second_report": report},
        "at_second_state": state(final_sha, 5 if vulnerable else 6, 1 if vulnerable else 0),
        "final": {"state": at_state, "lock": at_lock, "fifo": entry("fifo", [1, 9]), "second_report": report},
        "final_state": state(final_sha, 5 if vulnerable else 6, 1 if vulnerable else 0),
    }


def expect_reject(case, label):
    try:
        validate_case(case, check_files=False)
    except AssertionError:
        return
    raise AssertionError(f"fake report was accepted: {label}")


def self_test():
    with tempfile.TemporaryDirectory(prefix="asfa-lock-oracle-") as directory:
        root = Path(directory)
        regular = root / "state.json"
        regular.write_text(json.dumps({"schema_version": "asfa-directive-ledger/v4", "directives": [0] * 6, "consumed": []}), encoding="utf-8")
        symlink, hardlink, fifo = root / "lock", root / "hard", root / "fifo"
        os.symlink("state.json", symlink)
        os.link(regular, hardlink)
        os.mkfifo(fifo)
        require(snapshot(regular)["sha256"] == sha256(regular), "regular known answer failed")
        require(snapshot(symlink)["identity"] == snapshot(regular)["identity"], "symlink known answer failed")
        require(snapshot(hardlink)["identity"] == snapshot(regular)["identity"], "hardlink known answer failed")
        require(snapshot(fifo)["file_type"] == "fifo", "FIFO known answer failed")
        require(snapshot(root / "absent")["file_type"] == "absent", "absent known answer failed")
    valid = {"id": "symlink", "old": synthetic_symlink_side(True), "new": synthetic_symlink_side(False)}
    validate_case(valid, check_files=False)
    mutations = []
    mutated = copy.deepcopy(valid); mutated["old"]["first"]["alive_after_second"] = False; mutations.append((mutated, "old first not alive"))
    mutated = copy.deepcopy(valid); mutated["old"]["at_second_state"]["pending"] = 6; mutations.append((mutated, "old without consumption"))
    mutated = copy.deepcopy(valid); mutated["old"]["at_second"]["lock"]["identity"] = [1, 1]; mutations.append((mutated, "old without inode migration"))
    mutated = copy.deepcopy(valid); mutated["new"]["first"]["exit_code"] = 0; mutations.append((mutated, "new first accepted"))
    mutated = copy.deepcopy(valid); mutated["new"]["final_state"]["sha256"] = "e" * 64; mutations.append((mutated, "new state changed"))
    mutated = copy.deepcopy(valid); mutated["new"]["first"]["fifo"]["bytes"] = 1; mutations.append((mutated, "new FIFO output"))
    for mutated, label in mutations:
        expect_reject(mutated, label)
    print("lock-symlink oracle self-test: PASS (5 filesystem answers, 6 fake reports)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent / "bridge-poller/src/state_lock.rs")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if args.report:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        validate_report(report, source=args.source)
        print("lock-symlink differential: PASS (5 old/new cases; source and filesystem checked)")
    if not args.self_test and not args.report:
        parser.error("a report or --self-test is required")


if __name__ == "__main__":
    main()
