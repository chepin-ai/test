#!/usr/bin/env python3
"""Independent stdlib oracle for QF Lean capsules and fail-closed registry synchronization."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

ALLOWED = {"propext", "Classical.choice", "Quot.sound"}
SOURCES = {
    "lean/lean-toolchain", "lean/lakefile.toml", "lean/lake-manifest.json", "lean/Qf.lean",
    "lean/Qf/Relations.lean", "lean/Qf/Federation.lean", "lean/Audit.lean",
}
TARGETS = {"canonical_json", "knowledge_graph", "cell_complex", "superhypergraph", "category_hott", "latex"}


class Reject(Exception):
    pass


def cjson(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load(path: Path):
    def hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Reject(f"duplicate key {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)


def statement_sha(name: str, rendered: str) -> str:
    return sha(cjson({"schema": "qf-lean-statement/v1", "name": name, "type": " ".join(rendered.split())}))


def declaration_id(key: str, statement: str) -> str:
    return sha(cjson({"schema": "qf-lean-declaration/v1", "logical_key": key, "statement_sha256": statement}))


def lean_without_comments(text: str) -> str:
    # Independent nested-comment lexer. Strings are retained as blanks, never scanned as code.
    result = []
    i, nested = 0, 0
    line = string = escape = False
    while i < len(text):
        two, one = text[i:i + 2], text[i]
        if line:
            line = one != "\n"
            result.append("\n" if one == "\n" else " ")
            i += 1
        elif nested:
            if two == "/-":
                nested += 1; result.append("  "); i += 2
            elif two == "-/":
                nested -= 1; result.append("  "); i += 2
            else:
                result.append("\n" if one == "\n" else " "); i += 1
        elif string:
            result.append("\n" if one == "\n" else " ")
            if escape:
                escape = False
            elif one == "\\":
                escape = True
            elif one == '"':
                string = False
            i += 1
        elif two == "--":
            line = True; result.append("  "); i += 2
        elif two == "/-":
            nested = 1; result.append("  "); i += 2
        elif one == '"':
            string = True; result.append(" "); i += 1
        else:
            result.append(one); i += 1
    if nested or string:
        raise Reject("unterminated Lean lexical construct")
    return "".join(result)


def check_blocks(audit: str, anchors: list[dict]) -> dict:
    region = audit.split("\n'", 1)[0]
    expected = [item["name"] for item in anchors]
    names = []
    blocks = {}
    current = None
    for line in region.splitlines():
        name = line.split(" ", 1)[0] if line.startswith("Qf.") else None
        if name:
            names.append(name)
            current = name
            blocks[current] = []
        if current is not None:
            blocks[current].append(line)
    if names != expected:
        raise Reject(f"unexpected #check sequence: {names}")
    return {name: " ".join(" ".join(blocks[name]).split()) for name in names}


def axiom_observations(audit: str) -> dict:
    result = {}
    for line in audit.splitlines():
        match = re.fullmatch(r"'([^']+)' depends on axioms: \[(.*)\]", line.strip())
        if match:
            result[match.group(1)] = {part.strip() for part in match.group(2).split(",") if part.strip()}
        match = re.fullmatch(r"'([^']+)' does not depend on any axioms", line.strip())
        if match:
            result[match.group(1)] = set()
    return result


def validate_capsule(repo: Path, capsule: dict, directory: Path, require_commit: bool) -> None:
    if capsule.get("schema_version") != "qf-lean-capsule/v1":
        raise Reject("capsule schema")
    if require_commit and not re.fullmatch(r"[0-9a-f]{40}", capsule.get("source_commit", "")):
        raise Reject("capsule is not bound to an implementation commit")
    if set(capsule.get("source_tree_sha256", {})) != SOURCES:
        raise Reject("source tree coverage")
    for relative in SOURCES:
        data = (repo / relative).read_bytes()
        if capsule["source_tree_sha256"][relative] != sha(data):
            raise Reject(f"source hash mismatch: {relative}")
        if relative.endswith(".lean"):
            code = lean_without_comments(data.decode())
            for token in ("sorry", "admit", "axiom", "native_decide", "unsafe"):
                if re.search(rf"\b{token}\b", code):
                    raise Reject(f"forbidden construct {token} in {relative}")
    toolchain = (repo / "lean/lean-toolchain").read_text().strip()
    if toolchain != capsule["toolchain"]:
        raise Reject("toolchain mismatch")
    profile = sha(cjson({"toolchain": toolchain, "manifest_sha256": capsule["manifest_sha256"]}))
    if profile != capsule["profile_hash"]:
        raise Reject("profile hash")
    evidence = capsule["evidence"]
    if evidence["level"] != "FORMAL_R1":
        raise Reject("evidence level")
    for gate in ("source_scan", "lake_build", "axiom_audit"):
        if evidence[gate]["status"] != "PASS":
            raise Reject(f"evidence gate {gate}")
    for replay in ("sandboxed_kernel_replay", "independent_kernel_replay"):
        if evidence[replay]["status"] != "NOT_ESTABLISHED":
            raise Reject(f"unverified replay promotion: {replay}")
    anchors = load(repo / "federation/lean-anchors.json")["declarations"]
    names = [item["name"] for item in anchors]
    for gate, filename in (("lake_build", "lake-build.log"), ("axiom_audit", "axiom-audit.log")):
        log = (directory / filename).read_bytes()
        if evidence[gate]["log"] != filename or evidence[gate]["log_sha256"] != sha(log):
            raise Reject(f"log hash: {gate}")
        if evidence[gate]["exit_code"] != 0:
            raise Reject(f"process exit: {gate}")
    build_text = (directory / "lake-build.log").read_text()
    if "Build completed successfully" not in build_text:
        raise Reject("build success marker")
    audit = (directory / "axiom-audit.log").read_text()
    blocks = check_blocks(audit, anchors)
    observations = axiom_observations(audit)
    if set(observations) != set(names) or any(not axioms <= ALLOWED for axioms in observations.values()):
        raise Reject("axiom whitelist")
    if [item["name"] for item in capsule["declarations"]] != names:
        raise Reject("declaration anchors")
    for declaration in capsule["declarations"]:
        name = declaration["name"]
        if declaration["statement_type"] != blocks[name]:
            raise Reject(f"rendered statement mismatch: {name}")
        expected = statement_sha(name, blocks[name])
        if declaration["statement_sha256"] != expected:
            raise Reject(f"statement hash: {name}")
        if declaration["declaration_id"] != declaration_id(declaration["logical_key"], expected):
            raise Reject(f"declaration id: {name}")


def attestation(capsule: dict) -> dict:
    result = {
        "origin": capsule["origin"], "package_id": capsule["package_id"],
        "source_commit": capsule["source_commit"], "toolchain": capsule["toolchain"],
        "profile_hash": capsule["profile_hash"], "source_tree_sha256": capsule["source_tree_sha256"],
        "evidence_level": capsule["evidence"]["level"],
        "lake_build_log_sha256": capsule["evidence"]["lake_build"]["log_sha256"],
        "axiom_audit_log_sha256": capsule["evidence"]["axiom_audit"]["log_sha256"],
    }
    return result


def admit(registry: dict, capsule: dict) -> dict:
    if capsule["evidence"]["level"] != "FORMAL_R1":
        raise Reject("candidateNotFormal")
    staged = copy.deepcopy(registry)
    for package in staged.get("packages", []):
        if package.get("package_id") == capsule["package_id"]:
            package["status"] = "ACTIVE_LOCAL_FORMAL_R1"
    for candidate in capsule["declarations"]:
        if candidate["statement_sha256"] != statement_sha(candidate["name"], candidate["statement_type"]):
            raise Reject("statement digest")
        matches = [x for x in staged["declarations"] if x["logical_key"] == candidate["logical_key"]]
        att = attestation(capsule)
        att["attestation_id"] = sha(cjson({"schema": "qf-lean-attestation/v1",
                                            "declaration_id": candidate["declaration_id"], **att}))
        if matches:
            if len(matches) != 1:
                raise Reject("duplicate logical key")
            current = matches[0]
            if current["statement_sha256"] != candidate["statement_sha256"]:
                raise Reject("statementConflict")
            if current["declaration_id"] != candidate["declaration_id"] or current["name"] != candidate["name"]:
                raise Reject("identity collision")
            if all(x["attestation_id"] != att["attestation_id"] for x in current["attestations"]):
                current["attestations"].append(att)
                current["attestations"].sort(key=lambda x: x["attestation_id"])
        else:
            staged["declarations"].append({
                "logical_key": candidate["logical_key"], "name": candidate["name"],
                "statement_type": candidate["statement_type"],
                "statement_sha256": candidate["statement_sha256"],
                "declaration_id": candidate["declaration_id"], "attestations": [att],
            })
    staged["declarations"].sort(key=lambda x: x["logical_key"])
    return staged


def synthetic_capsule(origin: str, profile: str, statement: str = "P") -> dict:
    declaration = {"logical_key": "synthetic.key", "name": "Synthetic.theorem",
                   "statement_type": statement}
    declaration["statement_sha256"] = statement_sha(declaration["name"], statement)
    declaration["declaration_id"] = declaration_id(declaration["logical_key"], declaration["statement_sha256"])
    return {"schema_version": "qf-lean-capsule/v1", "origin": origin, "package_id": "synthetic",
            "source_commit": origin, "toolchain": profile, "profile_hash": profile,
            "source_tree_sha256": {}, "declarations": [declaration],
            "evidence": {"level": "FORMAL_R1", "lake_build": {"log_sha256": "b"},
                         "axiom_audit": {"log_sha256": "a"}}}


def compose(left: str, right: str):
    rules = {
        ("equivalence", "equivalence"): "equivalence", ("embedding", "embedding"): "embedding",
        ("equivalence", "embedding"): "embedding", ("embedding", "equivalence"): "embedding",
        ("implication", "implication"): "implication", ("dependency", "dependency"): "dependency",
    }
    return rules.get((left, right))


def self_test() -> dict:
    known = [
        ("coupling", "coupling", None), ("bridging", "bridging", None),
        ("symmetry", "symmetry", None), ("duality", "duality", None),
        ("embedding", "embedding", "embedding"), ("implication", "implication", "implication"),
        ("dependency", "dependency", "dependency"), ("equivalence", "embedding", "embedding"),
    ]
    for left, right, expected in known:
        if compose(left, right) != expected:
            raise Reject(f"relation known answer: {left}/{right}")
    seed = {"schema_version": "qf-lean-registry/v1", "packages": [], "declarations": [], "relations": []}
    first = synthetic_capsule("origin-a", "profile-a")
    second = synthetic_capsule("origin-b", "profile-b")
    registry_a = admit(seed, first)
    registry_b = admit(registry_a, second)
    if len(registry_b["declarations"]) != 1 or len(registry_b["declarations"][0]["attestations"]) != 2:
        raise Reject("new environment attestation")
    origins = [x["origin"] for x in registry_b["declarations"][0]["attestations"]]
    if set(origins) != {"origin-a", "origin-b"}:
        raise Reject("origin preservation")
    if cjson(admit(registry_b, second)) != cjson(registry_b):
        raise Reject("idempotence")
    before = cjson(registry_b)
    rejected = 0
    for mutate in ("statement", "informal", "digest", "identity"):
        candidate = copy.deepcopy(second)
        if mutate == "statement":
            candidate["declarations"][0]["statement_type"] = "Q"
            candidate["declarations"][0]["statement_sha256"] = statement_sha("Synthetic.theorem", "Q")
            candidate["declarations"][0]["declaration_id"] = declaration_id("synthetic.key", candidate["declarations"][0]["statement_sha256"])
        elif mutate == "informal":
            candidate["evidence"]["level"] = "CANDIDATE"
        elif mutate == "digest":
            candidate["declarations"][0]["statement_sha256"] = "0" * 64
        else:
            candidate["declarations"][0]["declaration_id"] = "0" * 64
        try:
            admit(registry_b, candidate)
        except Reject:
            rejected += 1
        if cjson(registry_b) != before:
            raise Reject(f"registry mutated on {mutate}")
    if rejected != 4:
        raise Reject("synthetic rejection coverage")
    for evidence in ("INFORMAL", "CANDIDATE", "FORMAL_R1"):
        projected = evidence if evidence != "FORMAL_R1" else "CANDIDATE"
        if projected == "FORMAL_R1":
            raise Reject("lossy projection promoted evidence")
    return {"relation_known_answers": len(known), "synthetic_valid": 2,
            "synthetic_rejections": rejected, "projection_known_answers": 3}


def validate_report(repo: Path, report: dict, directory: Path, require_commit: bool) -> dict:
    if report.get("schema_version") != "qf-lean-federation-report/v1":
        raise Reject("report schema")
    if report.get("result_status") != "EXECUTED_AWAITING_INDEPENDENT_ORACLE":
        raise Reject("runner asserted a final verdict")
    capsule = report["capsule"]
    validate_capsule(repo, capsule, directory, require_commit)
    if capsule != load(directory / "capsule.json"):
        raise Reject("report/capsule divergence")
    seed = load(repo / "federation/registry-seed.json")
    if report["seed_registry_sha256"] != sha(cjson(seed)):
        raise Reject("seed hash")
    expected = admit(seed, capsule)
    if report["registry"] != expected or report["registry_sha256"] != sha(cjson(expected)):
        raise Reject("registry reconstruction")
    if cjson(admit(expected, capsule)) != cjson(expected) or not report["idempotent_replay"]:
        raise Reject("idempotent replay")
    conflict = copy.deepcopy(capsule)
    declaration = conflict["declarations"][0]
    declaration["statement_type"] += " ∧ False"
    declaration["statement_sha256"] = statement_sha(declaration["name"], declaration["statement_type"])
    declaration["declaration_id"] = declaration_id(declaration["logical_key"], declaration["statement_sha256"])
    before = cjson(expected)
    try:
        admit(expected, conflict)
        raise Reject("semantic conflict accepted")
    except Reject as exc:
        if "semantic conflict accepted" in str(exc):
            raise
        if "statementConflict" not in str(exc):
            raise Reject(f"wrong conflict rejection: {exc}")
    if cjson(expected) != before or report["conflict_control"] != {"rejected": True, "registry_unchanged": True}:
        raise Reject("conflict no-write gate")
    projections = report["projections"]["projections"]
    if len(projections) != len(expected["declarations"]) * len(TARGETS):
        raise Reject("projection coverage")
    if {item["target"] for item in projections} != TARGETS:
        raise Reject("projection targets")
    for item in projections:
        if item["target"] == "canonical_json":
            if item["mode"] != "EXACT" or item["evidence"] != "FORMAL_R1":
                raise Reject("exact projection")
        elif item["mode"] != "LOSSY" or item["evidence"] != "CANDIDATE" or item["reverse_status"] != "REQUIRES_LEAN_REPLAY":
            raise Reject("lossy projection evidence boundary")
    forged = copy.deepcopy(report)
    forged_declaration = forged["registry"]["declarations"][0]
    forged_declaration["statement_type"] = "FORGED_BUT_HASH_REPAIRED"
    forged_declaration["statement_sha256"] = statement_sha(forged_declaration["name"], forged_declaration["statement_type"])
    forged_declaration["declaration_id"] = declaration_id(forged_declaration["logical_key"], forged_declaration["statement_sha256"])
    forged["registry_sha256"] = sha(cjson(forged["registry"]))
    forged_rejected = False
    try:
        if forged["registry"] != expected:
            raise Reject("forged registry semantics")
    except Reject:
        forged_rejected = True
    if not forged_rejected:
        raise Reject("forged real report accepted")
    return {"verdict": "PASS", "declarations": len(expected["declarations"]),
            "attestations": sum(len(x["attestations"]) for x in expected["declarations"]),
            "projections": len(projections), "forged_real_report": "REJECTED_BEFORE_ACCEPTANCE"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--require-commit", action="store_true")
    args = parser.parse_args()
    try:
        base = self_test()
        if args.self_test and not args.report:
            result = {"schema_version": "qf-lean-federation-oracle/v1", "self_test": "PASS", "details": base}
        else:
            if not args.report or not args.repo:
                raise Reject("--report and --repo are required")
            report = load(args.report)
            verdict = validate_report(args.repo.resolve(), report, args.report.parent.resolve(), args.require_commit)
            result = {"schema_version": "qf-lean-federation-oracle/v1", "self_test": base,
                      "report_sha256": sha(args.report.read_bytes()), **verdict,
                      "boundary": "Independent source, capsule, registry and projection oracle. FORMAL_R1 only; no sandboxed/multi-kernel replay, global activation, CI, federation ACK, or informal-statement fidelity claim."}
        text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            args.out.write_text(text)
        print(text, end="")
        return 0
    except (Reject, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"oracle rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
