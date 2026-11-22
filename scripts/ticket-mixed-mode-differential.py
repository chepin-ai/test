#!/usr/bin/env python3
"""Real pre-fix/fixed CLI differential for mixed execution and ticket mutations."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Harness:
    def __init__(self, args):
        self.repo = Path(args.repo).resolve()
        self.new_bin = Path(args.new_bin).resolve()
        self.old_bin = Path(args.old_bin).resolve()
        self.work = Path(args.work_dir).resolve()
        self.config = self.repo / "config/sessions.execution.json"
        self.pre_state = self.repo / "fixtures/qfos-exec-pre-state.json"
        self.fixed_plan = self.repo / "fixtures/qfos-exec-plan.json"
        self.fixed_state = self.repo / "fixtures/qfos-exec-state.json"
        self.fixed_execution = self.repo / "fixtures/qfos-exec-report.json"

    def call(self, steps, role, binary, args, expected=0):
        completed = subprocess.run(
            [str(binary), *map(str, args)], cwd=self.repo, text=True,
            capture_output=True, timeout=30, check=False,
        )
        record = {
            "role": role,
            "binary_sha256": sha(binary),
            "args": list(map(str, args)),
            "exit_code": completed.returncode,
            "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            "stderr": completed.stderr,
        }
        steps.append(record)
        require(completed.returncode == expected, f"{role}: exit {completed.returncode} != {expected}: {completed.stderr}")
        return record

    def base_args(self, state, now):
        return ["--config", self.config, "--state", state, "--now", now]

    def mint_base(self, role, binary, steps):
        directory = self.work / f"{role}-base"
        directory.mkdir(parents=True)
        state = directory / "state.json"
        plan = directory / "plan.json"
        shutil.copyfile(self.pre_state, state)
        self.call(steps, role, binary, [
            *self.base_args(state, 50), "--wave-out", plan,
            "--ticket-mint-root", "nonce-1", "--ticket-controller", "root",
            "--ticket-agent", "alice", "--ticket-out", directory / "mint-ticket.json",
            "--out", directory / "mint-bridge.json",
        ])
        require(plan.read_bytes() == self.fixed_plan.read_bytes(), f"{role} mint plan drift")
        return directory, state, plan

    def ticketed(self, steps, role, binary, state, plan, directory, label, now, expected=0):
        self.call(steps, role, binary, [
            *self.base_args(state, now), "--wave-out", plan, "--execute-wave",
            "--ticketed-execution", "--ticket-agent", "alice",
            "--execution-out", directory / f"{label}-execution.json",
            "--ticket-out", directory / f"{label}-ticket.json",
            "--out", directory / f"{label}-bridge.json",
        ], expected)


def mutation_args(mode, root_id, work_id):
    if mode == "transfer_self":
        return ["--ticket-transfer", work_id, "--ticket-agent", "alice", "--ticket-to", "alice"]
    if mode == "revoke":
        return ["--ticket-revoke-root", root_id, "--ticket-agent", "root"]
    raise ValueError(mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--new-bin", required=True)
    parser.add_argument("--old-bin", required=True)
    parser.add_argument("--new-commit", required=True)
    parser.add_argument("--old-commit", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    h = Harness(args)
    if h.work.exists():
        shutil.rmtree(h.work)
    h.work.mkdir(parents=True)
    cases = []

    steps = []
    legacy = {}
    for role, binary in [("old", h.old_bin), ("new", h.new_bin)]:
        directory = h.work / f"legacy-{role}"
        directory.mkdir()
        state = directory / "state.json"
        plan = directory / "plan.json"
        execution = directory / "execution.json"
        shutil.copyfile(h.pre_state, state)
        shutil.copyfile(h.fixed_plan, plan)
        h.call(steps, role, binary, [
            *h.base_args(state, 100), "--wave-out", plan, "--execute-wave",
            "--execution-out", execution, "--out", directory / "bridge.json",
        ])
        legacy[role] = {
            "state_sha256": sha(state), "plan_sha256": sha(plan),
            "execution_sha256": sha(execution),
            "state_matches_fixture": state.read_bytes() == h.fixed_state.read_bytes(),
            "plan_matches_fixture": plan.read_bytes() == h.fixed_plan.read_bytes(),
            "execution_matches_fixture": execution.read_bytes() == h.fixed_execution.read_bytes(),
        }
        require(all(legacy[role][key] for key in ["state_matches_fixture", "plan_matches_fixture", "execution_matches_fixture"]), "legacy fixture drift")
    cases.append({"name": "legacy_v4_control", "steps": steps, "observations": legacy})

    setup_steps = []
    old_base, old_base_state, old_plan = h.mint_base("old", h.old_bin, setup_steps)
    new_base, new_base_state, new_plan = h.mint_base("new", h.new_bin, setup_steps)
    require(old_base_state.read_bytes() == new_base_state.read_bytes(), "mint state differs across binaries")
    minted_state = load(new_base_state)
    root_id = next(t["ticket_id"] for t in minted_state["tickets"]["tickets"] if t["body"]["kind"] == "control")
    work_id = next(t["ticket_id"] for t in minted_state["tickets"]["tickets"] if t["body"]["kind"] == "execute" and t["body"]["job"]["id"] == "sum")

    for mode in ["transfer_self", "revoke"]:
        steps = []
        directory = h.work / mode
        directory.mkdir()
        old_state = directory / "old-state.json"
        new_state = directory / "new-state.json"
        shutil.copyfile(old_base_state, old_state)
        shutil.copyfile(new_base_state, new_state)
        old_execution = directory / "old-execution.json"
        old_ticket = directory / "old-ticket.json"
        old_out = directory / "old-bridge.json"
        h.call(steps, "old", h.old_bin, [
            *h.base_args(old_state, 100), "--wave-out", old_plan, "--execute-wave",
            "--execution-out", old_execution, *mutation_args(mode, root_id, work_id),
            "--ticket-out", old_ticket, "--out", old_out,
        ])
        old_mixed_state = load(old_state)
        old_mixed_hash = sha(old_state)
        old_recovery_execution = directory / "old-recovery-execution.json"
        old_recovery_ticket = directory / "old-recovery-ticket.json"
        old_recovery_out = directory / "old-recovery-bridge.json"
        recovery = h.call(steps, "old", h.old_bin, [
            *h.base_args(old_state, 101), "--wave-out", old_plan, "--execute-wave",
            "--ticketed-execution", "--ticket-agent", "alice",
            "--execution-out", old_recovery_execution, "--ticket-out", old_recovery_ticket,
            "--out", old_recovery_out,
        ], 2)
        old_recovery_state_sha256 = sha(old_state)
        require(old_recovery_state_sha256 == old_mixed_hash, "old recovery mutated mixed state")
        adoption = None
        if mode == "transfer_self":
            adoption = h.call(steps, "old", h.old_bin, [
                *h.base_args(old_state, 100), "--wave-out", old_plan, "--execute-wave",
                "--ticketed-execution", "--ticket-agent", "alice",
                "--execution-out", directory / "old-adopt-execution.json",
                "--ticket-out", directory / "old-adopt-ticket.json",
                "--out", directory / "old-adopt-bridge.json",
            ])
            adopted_state = load(old_state)
        else:
            adopted_state = None

        new_execution = directory / "new-execution.json"
        new_ticket = directory / "new-ticket.json"
        new_out = directory / "new-bridge.json"
        rejection = h.call(steps, "new", h.new_bin, [
            *h.base_args(new_state, 100), "--wave-out", new_plan, "--execute-wave",
            "--execution-out", new_execution, *mutation_args(mode, root_id, work_id),
            "--ticket-out", new_ticket, "--out", new_out,
        ], 2)
        require(sha(new_state) == sha(new_base_state), "fixed rejection mutated Mint state")
        rejected_state = load(new_state)
        rejected_outputs_absent = not any(path.exists() for path in [new_execution, new_ticket, new_out])
        require(rejected_outputs_absent, "fixed rejection created an output")
        h.ticketed(steps, "new", h.new_bin, new_state, new_plan, directory, "new-normal", 100)
        normal_state = load(new_state)
        normal_hash = sha(new_state)
        h.ticketed(steps, "new", h.new_bin, new_state, new_plan, directory, "new-replay", 101)
        require(sha(new_state) == normal_hash, "fixed replay mutated state")
        replay_operation = load(directory / "new-replay-ticket.json")
        cases.append({
            "name": f"mixed_{mode}", "steps": steps,
            "old_mixed_state": old_mixed_state,
            "old_mixed_state_sha256": old_mixed_hash,
            "old_recovery": {
                "exit_code": recovery["exit_code"], "stderr": recovery["stderr"],
                "state_sha256_after_recovery": old_recovery_state_sha256,
                "state_unchanged": old_recovery_state_sha256 == old_mixed_hash,
                "outputs_absent": not any(path.exists() for path in [old_recovery_execution, old_recovery_ticket, old_recovery_out]),
            },
            "old_timestamp_matched_adoption": None if adoption is None else {
                "exit_code": adoption["exit_code"], "final_state": adopted_state,
            },
            "new_rejection": {
                "exit_code": rejection["exit_code"], "stderr": rejection["stderr"],
                "state_sha256": sha(new_base_state), "rejected_state": rejected_state,
                "outputs_absent": rejected_outputs_absent,
            },
            "new_normal_state": normal_state,
            "new_replay_operation": replay_operation,
            "new_replay_state_sha256": sha(new_state),
            "new_normal_state_sha256": normal_hash,
        })

    steps = []
    directory = h.work / "standalone"
    directory.mkdir()
    state = directory / "state.json"
    shutil.copyfile(new_base_state, state)
    h.call(steps, "new", h.new_bin, [
        *h.base_args(state, 60), "--ticket-transfer", work_id,
        "--ticket-agent", "alice", "--ticket-to", "bob",
        "--ticket-out", directory / "transfer.json", "--out", directory / "transfer-bridge.json",
    ])
    h.call(steps, "new", h.new_bin, [
        *h.base_args(state, 61), "--ticket-revoke-root", root_id,
        "--ticket-agent", "root", "--ticket-out", directory / "revoke.json",
        "--out", directory / "revoke-bridge.json",
    ])
    cases.append({"name": "standalone_mutations", "steps": steps, "final_state": load(state)})
    cases.append({"name": "mint_setup", "steps": setup_steps, "old_state": load(old_base_state), "new_state": minted_state})

    report = {
        "schema_version": "asfa-ticket-mixed-mode-differential/v1",
        "created_at": dt.datetime.now().astimezone().isoformat(),
        "result_status": "EXECUTED_AWAITING_INDEPENDENT_ORACLE",
        "source": {
            "repo": str(h.repo), "old_commit": args.old_commit, "new_commit": args.new_commit,
            "old_binary_sha256": sha(h.old_bin), "new_binary_sha256": sha(h.new_bin),
            "pre_state_sha256": sha(h.pre_state), "fixed_plan_sha256": sha(h.fixed_plan),
            "fixed_state_sha256": sha(h.fixed_state), "fixed_execution_sha256": sha(h.fixed_execution),
        },
        "cases": cases,
        "boundary": "Local CLI mode-composition and recovery consistency only; legacy execution without a ticket mutation remains supported. No signature, consensus, ZK, external CI, federation, or distributed exactly-once claim.",
    }
    dump(args.out, report)
    print(json.dumps({"out": str(args.out), "cases": len(cases), "status": report["result_status"]}))


if __name__ == "__main__":
    main()
