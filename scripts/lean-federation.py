#!/usr/bin/env python3
"""Build and synchronize QF Lean evidence capsules without final-verdict self-assertion."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SCHEMA = "qf-lean-capsule/v1"
REPORT_SCHEMA = "qf-lean-federation-report/v1"
REGISTRY_SCHEMA = "qf-lean-registry/v1"
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
SOURCE_FILES = (
    "lean/lean-toolchain",
    "lean/lakefile.toml",
    "lean/lake-manifest.json",
    "lean/Qf.lean",
    "lean/Qf/Relations.lean",
    "lean/Qf/Federation.lean",
    "lean/Audit.lean",
)
PROJECTIONS = ("canonical_json", "knowledge_graph", "cell_complex", "superhypergraph", "category_hott", "latex")


class FederationError(Exception):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_load(path: Path):
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise FederationError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        raise FederationError(f"cannot load {path}: {exc}") from exc


def strip_lean_comments(source: str) -> str:
    """Remove line/nested block comments and preserve string contents as blank space."""
    out = []
    i = 0
    block_depth = 0
    line_comment = False
    string = False
    escaped = False
    while i < len(source):
        pair = source[i:i + 2]
        char = source[i]
        if line_comment:
            if char == "\n":
                line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if block_depth:
            if pair == "/-":
                block_depth += 1
                out.extend("  ")
                i += 2
            elif pair == "-/":
                block_depth -= 1
                out.extend("  ")
                i += 2
            else:
                out.append("\n" if char == "\n" else " ")
                i += 1
            continue
        if string:
            out.append("\n" if char == "\n" else " ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                string = False
            i += 1
            continue
        if pair == "--":
            line_comment = True
            out.extend("  ")
            i += 2
        elif pair == "/-":
            block_depth = 1
            out.extend("  ")
            i += 2
        elif char == '"':
            string = True
            out.append(" ")
            i += 1
        else:
            out.append(char)
            i += 1
    if block_depth or string:
        raise FederationError("unterminated Lean comment or string")
    return "".join(out)


def scan_lean_sources(repo: Path) -> dict:
    findings = []
    for relative in SOURCE_FILES:
        if not relative.endswith(".lean"):
            continue
        path = repo / relative
        stripped = strip_lean_comments(path.read_text(encoding="utf-8"))
        for token in ("sorry", "admit", "axiom", "native_decide", "unsafe"):
            if re.search(rf"\b{token}\b", stripped):
                findings.append({"path": relative, "token": token})
    if findings:
        raise FederationError(f"forbidden Lean constructs: {findings}")
    return {"status": "PASS", "forbidden_constructs": findings}


def statement_digest(name: str, statement_type: str) -> str:
    return digest({"schema": "qf-lean-statement/v1", "name": name, "type": " ".join(statement_type.split())})


def extract_check_blocks(text: str, anchors: list[dict]) -> dict:
    """Bind each certificate to the actual Lean-rendered #check block."""
    check_region = text.split("\n'", 1)[0]
    expected = [anchor["name"] for anchor in anchors]
    matches = list(re.finditer(r"(?m)^Qf\.[A-Za-z0-9_.]+", check_region))
    names = [match.group(0) for match in matches]
    if names != expected:
        raise FederationError(f"#check sequence mismatch: expected={expected} observed={names}")
    blocks = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(check_region)
        blocks[match.group(0)] = " ".join(check_region[match.start():end].split())
    return blocks


def run_process(args: list[str], cwd: Path, log_path: Path) -> dict:
    env = os.environ.copy()
    env.setdefault("LEAN_NUM_THREADS", "2")
    completed = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=600, check=False)
    log_path.write_text(completed.stdout, encoding="utf-8")
    return {"argv": args, "exit_code": completed.returncode,
            "log": log_path.name, "log_sha256": sha_bytes(completed.stdout.encode())}


def parse_axiom_audit(text: str, expected_names: set[str]) -> dict:
    observed = {}
    for line in text.splitlines():
        match = re.match(r"^'([^']+)' depends on axioms: \[(.*)\]$", line.strip())
        if match:
            observed[match.group(1)] = [x.strip() for x in match.group(2).split(",") if x.strip()]
            continue
        match = re.match(r"^'([^']+)' does not depend on any axioms$", line.strip())
        if match:
            observed[match.group(1)] = []
    if set(observed) != expected_names:
        raise FederationError(f"axiom audit name mismatch: expected={sorted(expected_names)} observed={sorted(observed)}")
    extra = {name: sorted(set(axioms) - ALLOWED_AXIOMS) for name, axioms in observed.items()
             if set(axioms) - ALLOWED_AXIOMS}
    if extra:
        raise FederationError(f"non-whitelisted axioms: {extra}")
    return {"status": "PASS", "allowed": sorted(ALLOWED_AXIOMS), "observed": observed}


def make_capsule(repo: Path, source_commit: str, work: Path) -> dict:
    anchors = strict_load(repo / "federation/lean-anchors.json")["declarations"]
    names = {anchor["name"] for anchor in anchors}
    build = run_process(["lake", "build"], repo / "lean", work / "lake-build.log")
    if build["exit_code"] != 0:
        raise FederationError(f"lake build failed; see {work / build['log']}")
    audit = run_process(["lake", "env", "lean", "Audit.lean"], repo / "lean", work / "axiom-audit.log")
    if audit["exit_code"] != 0:
        raise FederationError(f"Lean audit failed; see {work / audit['log']}")
    audit_text = (work / audit["log"]).read_text(encoding="utf-8")
    check_blocks = extract_check_blocks(audit_text, anchors)
    axioms = parse_axiom_audit(audit_text, names)
    source_tree = {}
    for relative in SOURCE_FILES:
        data = (repo / relative).read_bytes()
        source_tree[relative] = sha_bytes(data)
    toolchain = (repo / "lean/lean-toolchain").read_text(encoding="utf-8").strip()
    manifest_sha = source_tree["lean/lake-manifest.json"]
    profile_hash = digest({"toolchain": toolchain, "manifest_sha256": manifest_sha})
    declarations = []
    for anchor in anchors:
        statement_type = check_blocks[anchor["name"]]
        statement_hash = statement_digest(anchor["name"], statement_type)
        declarations.append({**anchor, "statement_type": statement_type,
                             "statement_sha256": statement_hash,
                             "declaration_id": digest({"schema": "qf-lean-declaration/v1",
                                                       "logical_key": anchor["logical_key"],
                                                       "statement_sha256": statement_hash})})
    capsule = {
        "schema_version": SCHEMA,
        "origin": "asfa-ai",
        "package_id": "qf-constraints",
        "source_commit": source_commit,
        "toolchain": toolchain,
        "dependency_profile": "core-only",
        "manifest_sha256": manifest_sha,
        "profile_hash": profile_hash,
        "source_tree_sha256": source_tree,
        "declarations": declarations,
        "evidence": {
            "level": "FORMAL_R1",
            "source_scan": scan_lean_sources(repo),
            "lake_build": {"status": "PASS", **build},
            "axiom_audit": {"status": "PASS", **axioms, **audit},
            "sandboxed_kernel_replay": {"status": "NOT_ESTABLISHED"},
            "independent_kernel_replay": {"status": "NOT_ESTABLISHED"}
        }
    }
    (work / "capsule.json").write_bytes(canonical(capsule) + b"\n")
    return capsule


def require_capsule(capsule: dict) -> None:
    if capsule.get("schema_version") != SCHEMA:
        raise FederationError("unsupported capsule schema")
    if capsule.get("evidence", {}).get("level") != "FORMAL_R1":
        raise FederationError("only a verified FORMAL_R1 capsule can be admitted")
    for key in ("source_scan", "lake_build", "axiom_audit"):
        if capsule["evidence"].get(key, {}).get("status") != "PASS":
            raise FederationError(f"evidence gate is not PASS: {key}")
    if not capsule.get("declarations"):
        raise FederationError("empty declaration set")
    for declaration in capsule["declarations"]:
        expected = statement_digest(declaration["name"], declaration["statement_type"])
        if declaration["statement_sha256"] != expected:
            raise FederationError(f"statement digest mismatch: {declaration['name']}")
        expected_id = digest({"schema": "qf-lean-declaration/v1",
                              "logical_key": declaration["logical_key"],
                              "statement_sha256": expected})
        if declaration["declaration_id"] != expected_id:
            raise FederationError(f"declaration identity mismatch: {declaration['name']}")


def attestation_for(capsule: dict, declaration: dict) -> dict:
    attestation = {
        "origin": capsule["origin"],
        "package_id": capsule["package_id"],
        "source_commit": capsule["source_commit"],
        "toolchain": capsule["toolchain"],
        "profile_hash": capsule["profile_hash"],
        "source_tree_sha256": capsule["source_tree_sha256"],
        "evidence_level": capsule["evidence"]["level"],
        "lake_build_log_sha256": capsule["evidence"]["lake_build"]["log_sha256"],
        "axiom_audit_log_sha256": capsule["evidence"]["axiom_audit"]["log_sha256"],
    }
    attestation["attestation_id"] = digest({"schema": "qf-lean-attestation/v1",
                                            "declaration_id": declaration["declaration_id"],
                                            **attestation})
    return attestation


def admit_capsule(registry: dict, capsule: dict) -> tuple[dict, dict]:
    require_capsule(capsule)
    staged = copy.deepcopy(registry)
    if staged.get("schema_version") != REGISTRY_SCHEMA:
        raise FederationError("unsupported registry schema")
    declarations = staged.setdefault("declarations", [])
    for package in staged.get("packages", []):
        if package.get("package_id") == capsule["package_id"]:
            package["status"] = "ACTIVE_LOCAL_FORMAL_R1"
    added = []
    attestations_added = []
    for candidate in capsule["declarations"]:
        same_key = [item for item in declarations if item["logical_key"] == candidate["logical_key"]]
        if len(same_key) > 1:
            raise FederationError(f"registry has duplicate logical key: {candidate['logical_key']}")
        attestation = attestation_for(capsule, candidate)
        if same_key:
            current = same_key[0]
            if current["statement_sha256"] != candidate["statement_sha256"]:
                raise FederationError(f"statementConflict: {candidate['logical_key']}")
            if current["declaration_id"] != candidate["declaration_id"] or current["name"] != candidate["name"]:
                raise FederationError(f"declaration identity collision: {candidate['logical_key']}")
            if not any(item["attestation_id"] == attestation["attestation_id"]
                       for item in current["attestations"]):
                current["attestations"].append(attestation)
                current["attestations"].sort(key=lambda item: item["attestation_id"])
                attestations_added.append(attestation["attestation_id"])
        else:
            declarations.append({
                "logical_key": candidate["logical_key"],
                "name": candidate["name"],
                "statement_type": candidate["statement_type"],
                "statement_sha256": candidate["statement_sha256"],
                "declaration_id": candidate["declaration_id"],
                "attestations": [attestation],
            })
            added.append(candidate["declaration_id"])
            attestations_added.append(attestation["attestation_id"])
    declarations.sort(key=lambda item: item["logical_key"])
    return staged, {"declarations_added": added, "attestations_added": attestations_added}


def project_registry(registry: dict) -> dict:
    projections = []
    for declaration in registry["declarations"]:
        for target in PROJECTIONS:
            exact = target == "canonical_json"
            projections.append({
                "declaration_id": declaration["declaration_id"],
                "target": target,
                "mode": "EXACT" if exact else "LOSSY",
                "evidence": declaration["attestations"][0]["evidence_level"] if exact else "CANDIDATE",
                "reverse_status": "NOT_REQUIRED" if exact else "REQUIRES_LEAN_REPLAY",
                "payload": ({"logical_key": declaration["logical_key"], "statement_type": declaration["statement_type"]}
                            if target != "latex" else
                            {"text": "\\texttt{" + declaration["name"].replace("_", "\\_") + "}"}),
            })
    return {"schema_version": "qf-lean-projections/v1", "projections": projections}


def execute(repo: Path, source_commit: str, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    capsule = make_capsule(repo, source_commit, work)
    seed = strict_load(repo / "federation/registry-seed.json")
    admitted, changes = admit_capsule(seed, capsule)
    replay, replay_changes = admit_capsule(admitted, capsule)
    if canonical(replay) != canonical(admitted) or replay_changes["attestations_added"]:
        raise FederationError("idempotent replay changed registry")
    conflict = copy.deepcopy(capsule)
    conflict["declarations"][0]["statement_sha256"] = "0" * 64
    conflict["declarations"][0]["declaration_id"] = digest({
        "schema": "qf-lean-declaration/v1",
        "logical_key": conflict["declarations"][0]["logical_key"],
        "statement_sha256": conflict["declarations"][0]["statement_sha256"]})
    conflict_rejected = False
    before_conflict = canonical(admitted)
    try:
        admit_capsule(admitted, conflict)
    except FederationError as exc:
        conflict_rejected = "statementConflict" in str(exc) or "statement digest mismatch" in str(exc)
    conflict_unchanged = before_conflict == canonical(admitted)
    if not (conflict_rejected and conflict_unchanged):
        raise FederationError("conflict control did not fail closed")
    projections = project_registry(admitted)
    (work / "registry.json").write_bytes(canonical(admitted) + b"\n")
    (work / "projections.json").write_bytes(canonical(projections) + b"\n")
    report = {
        "schema_version": REPORT_SCHEMA,
        "result_status": "EXECUTED_AWAITING_INDEPENDENT_ORACLE",
        "source_commit": source_commit,
        "capsule": capsule,
        "seed_registry_sha256": sha_bytes(canonical(seed)),
        "registry": admitted,
        "registry_sha256": sha_bytes(canonical(admitted)),
        "projections": projections,
        "changes": changes,
        "idempotent_replay": True,
        "conflict_control": {"rejected": conflict_rejected, "registry_unchanged": conflict_unchanged},
        "legacy_usrm": {"status": "REGISTERED_NOT_ACTIVATED", "toolchain_rewritten": False},
        "boundary": "Local Lean build and provenance synchronization only. No global federation activation, external CI, cross-line acknowledgement, sandboxed replay, independent-kernel verdict, or informal-statement fidelity claim."
    }
    (work / "report.json").write_bytes(canonical(report) + b"\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--source-commit", required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "run":
            report = execute(args.repo.resolve(), args.source_commit, args.work_dir.resolve())
            print(json.dumps({"out": str(args.work_dir / "report.json"),
                              "declarations": len(report["registry"]["declarations"]),
                              "status": report["result_status"]}, ensure_ascii=False))
            return 0
    except (FederationError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"lean federation runner failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
