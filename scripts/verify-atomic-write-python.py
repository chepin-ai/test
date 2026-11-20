#!/usr/bin/env python3
"""Independent filesystem adjudication for atomic-write differentials."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile

EXPECTED_BINARY = "7d17536d82cadd784ae6f9d9def2d53708d44eb906449522ca1067ad7c0cef5d"
EXPECTED_BASELINE = "2a40df076c0d4f63a1f5dd25f368f2916a8d0d50"
SENTINEL_SHA256 = "b5f7e7d285029324d9b3acae19cc05099271454ac98bfc059a92b0581625cd51"
CASE_ORDER = ["symlink", "hardlink", "regular", "exhaustion", "control"]


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
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                result["json_schema"] = value["schema_version"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def require_sentinel(side, name, message):
    require(side["after"][name]["lexists"], f"{message}: entry is absent")
    require(side["after"][name]["sha256"] == SENTINEL_SHA256, f"{message}: bytes changed")


def validate_case(case, check_files=True):
    case_id = case["id"]
    old = case["old"]
    new = case["new"]
    for side in (old, new):
        require(side["sentinel_sha256"] == SENTINEL_SHA256, f"{case_id}: wrong sentinel anchor")
        if check_files:
            for name, path in side["paths"].items():
                require(
                    snapshot(path) == side["after"][name],
                    f"{case_id}: recorded {name} after-state does not match the filesystem",
                )

    if case_id in ("symlink", "hardlink"):
        require(old["exit_code"] == 0, f"{case_id}: old process did not complete")
        require(old["after"]["victim"]["json_schema"] == "asfa-directive-ledger/v4", f"{case_id}: old victim was not overwritten")
        require(old["after"]["victim"]["sha256"] != SENTINEL_SHA256, f"{case_id}: old sentinel survived")
        require(old["after"]["state"]["sha256"] == old["after"]["victim"]["sha256"], f"{case_id}: old state and victim differ")
        require(old["after"]["state"]["identity"] == old["after"]["victim"]["identity"], f"{case_id}: old state does not share victim identity")
        require(old["after"]["state"]["is_symlink"] == (case_id == "symlink"), f"{case_id}: old final link type is wrong")
        require(not old["after"]["temporary_1"]["lexists"], f"{case_id}: old temporary name was not renamed")

        require(new["exit_code"] == 0, f"{case_id}: new safe retry failed")
        require_sentinel(new, "victim", f"{case_id}: new victim")
        require_sentinel(new, "temporary_1", f"{case_id}: new collision")
        require(new["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", f"{case_id}: new state is invalid")
        require(not new["after"]["state"]["is_symlink"], f"{case_id}: new state remains a symlink")
        require(new["after"]["state"]["identity"] != new["after"]["victim"]["identity"], f"{case_id}: new state shares victim identity")
        if case_id == "symlink":
            require(new["after"]["temporary_1"]["is_symlink"], "symlink: new collision was replaced")
            require(new["after"]["temporary_1"].get("link_target") == new["paths"]["victim"], "symlink: link target changed")
        else:
            require(not new["after"]["temporary_1"]["is_symlink"], "hardlink: collision became a symlink")
            require(new["after"]["temporary_1"]["identity"] == new["after"]["victim"]["identity"], "hardlink: identities separated")
    elif case_id == "regular":
        require(old["exit_code"] == 0, "regular: old process did not complete")
        require(old["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", "regular: old state is invalid")
        require(not old["after"]["temporary_1"]["lexists"], "regular: old temporary name was not renamed")
        require(new["exit_code"] == 0, "regular: new safe retry failed")
        require_sentinel(new, "temporary_1", "regular: new collision")
        require(not new["after"]["temporary_1"]["is_symlink"], "regular: collision type changed")
        require(new["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", "regular: new state is invalid")
        require(not new["after"]["state"]["is_symlink"], "regular: new state is a symlink")
    elif case_id == "exhaustion":
        require(old["exit_code"] == 0, "exhaustion: old process did not complete")
        require(old["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", "exhaustion: old state is invalid")
        require(not old["after"]["temporary_1"]["lexists"], "exhaustion: old first collision was not renamed")
        for serial in range(2, 129):
            require_sentinel(old, f"temporary_{serial}", f"exhaustion: old collision {serial}")
        require(new["exit_code"] == 2, "exhaustion: new process did not fail closed")
        require(not new["after"]["state"]["lexists"], "exhaustion: new created a state")
        require("cannot allocate unique temporary state file" in new["stderr"] and "after 128 attempts" in new["stderr"], "exhaustion: explicit diagnostic is absent")
        for serial in range(1, 129):
            require_sentinel(new, f"temporary_{serial}", f"exhaustion: new collision {serial}")
    elif case_id == "control":
        for label, side in (("old", old), ("new", new)):
            require(side["exit_code"] == 0, f"control: {label} process failed")
            require(side["after"]["state"]["json_schema"] == "asfa-directive-ledger/v4", f"control: {label} state is invalid")
            require(not side["after"]["state"]["is_symlink"], f"control: {label} state is a symlink")
            require(not side["after"]["temporary_1"]["lexists"], f"control: {label} left a temporary path")
        require(old["after"]["state"]["sha256"] == new["after"]["state"]["sha256"], "control: old/new state bytes drifted")
    else:
        raise AssertionError(f"unknown case {case_id}")


def validate_report(report, check_files=True):
    require(report["schema_version"] == "asfa-atomic-write-differential/v1", "bad report schema")
    require(report["baseline_commit"] == EXPECTED_BASELINE, "wrong baseline")
    require(report["old_binary_sha256"] == EXPECTED_BINARY, "wrong old binary")
    require([case["id"] for case in report["cases"]] == CASE_ORDER, "missing or reordered cases")
    for case in report["cases"]:
        validate_case(case, check_files=check_files)
    control_hash = report["cases"][-1]["new"]["after"]["state"]["sha256"]
    for case in report["cases"][:3]:
        require(case["new"]["after"]["state"]["sha256"] == control_hash, f"{case['id']}: new state differs from control")


def synthetic_entry(lexists=False, sha=None, schema=None, identity=None, symlink=False, target=None):
    value = {
        "lexists": lexists,
        "exists": lexists,
        "is_symlink": symlink,
        "sha256": sha,
        "json_schema": schema,
        "identity": identity,
    }
    if symlink:
        value["link_target"] = target
    return value


def synthetic_symlink_case():
    state = "/tmp/self/state.json"
    victim = "/tmp/self/victim.json"
    temporary = "/tmp/self/state.tmp-1-1"
    lock = "/tmp/self/state.json.lock"
    paths = {"state": state, "victim": victim, "temporary_1": temporary, "lock": lock}
    absent = synthetic_entry()
    ledger = "a" * 64
    control = "b" * 64
    old_after = {
        "state": synthetic_entry(True, ledger, "asfa-directive-ledger/v4", [1, 2], True, victim),
        "victim": synthetic_entry(True, ledger, "asfa-directive-ledger/v4", [1, 2]),
        "temporary_1": absent,
        "lock": synthetic_entry(True, "c" * 64, identity=[1, 4]),
    }
    new_after = {
        "state": synthetic_entry(True, control, "asfa-directive-ledger/v4", [1, 3]),
        "victim": synthetic_entry(True, SENTINEL_SHA256, identity=[1, 2]),
        "temporary_1": synthetic_entry(True, SENTINEL_SHA256, identity=[1, 2], symlink=True, target=victim),
        "lock": synthetic_entry(True, "c" * 64, identity=[1, 4]),
    }
    side = lambda code, after: {
        "exit_code": code,
        "stdout": "",
        "stderr": "",
        "sentinel_sha256": SENTINEL_SHA256,
        "paths": paths,
        "before": {},
        "after": copy.deepcopy(after),
    }
    return {"id": "symlink", "old": side(0, old_after), "new": side(0, new_after)}


def expect_reject(case, label):
    try:
        validate_case(case, check_files=False)
    except AssertionError:
        return
    raise AssertionError(f"fake report was accepted: {label}")


def self_test():
    with tempfile.TemporaryDirectory(prefix="asfa-atomic-oracle-") as directory:
        root = Path(directory)
        regular = root / "regular"
        symlink = root / "symlink"
        hardlink = root / "hardlink"
        regular.write_bytes(b"sentinel\n")
        os.symlink(regular, symlink)
        os.link(regular, hardlink)
        require(snapshot(regular)["sha256"] == SENTINEL_SHA256, "regular known answer failed")
        require(snapshot(symlink)["is_symlink"], "symlink known answer failed")
        require(snapshot(hardlink)["identity"] == snapshot(regular)["identity"], "hardlink known answer failed")
        require(not snapshot(root / "absent")["lexists"], "absent known answer failed")

    valid = synthetic_symlink_case()
    validate_case(valid, check_files=False)
    mutated = copy.deepcopy(valid)
    mutated["old"]["exit_code"] = 2
    expect_reject(mutated, "old failure")
    mutated = copy.deepcopy(valid)
    mutated["old"]["after"]["victim"]["sha256"] = SENTINEL_SHA256
    expect_reject(mutated, "old without damage")
    mutated = copy.deepcopy(valid)
    mutated["new"]["after"]["victim"]["sha256"] = "d" * 64
    expect_reject(mutated, "new victim changed")
    mutated = copy.deepcopy(valid)
    mutated["new"]["after"]["state"]["is_symlink"] = True
    expect_reject(mutated, "new state symlink")
    mutated = copy.deepcopy(valid)
    mutated["new"]["after"]["temporary_1"] = synthetic_entry()
    expect_reject(mutated, "new collision removed")
    print("atomic-write oracle self-test: PASS (4 filesystem answers, 5 fake reports)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if args.report:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        validate_report(report)
        print("atomic-write differential: PASS (5 old/new cases)")
    if not args.self_test and not args.report:
        parser.error("a report or --self-test is required")


if __name__ == "__main__":
    main()
