#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/asfa-os-xi-target}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
python3 scripts/check-no-secrets.py
python3 scripts/verify-outbox-python.py --self-test \
  fixtures/python-oracle-outbox.json \
  fixtures/qfos-exec-outbox.json \
  outbox/asfa-ai-outbox.json
python3 scripts/verify-policy-python.py --fixture fixtures/policy-oracle.json
python3 scripts/verify-egress-python.py --self-test
python3 scripts/verify-json-budget-python.py
python3 scripts/verify-path-python.py --self-test
python3 scripts/verify-atomic-write-python.py --self-test
python3 scripts/verify-lock-symlink-python.py --self-test
python3 scripts/verify-ticket-utxo-python.py --self-test
python3 scripts/verify-wave-python.py \
  --expect-plan-hash 5b27a80652ea74fc1b11e07033119ea49708018244325e5dae56f0f6bb88ca34
rm -f /tmp/asfa-wave-report.json /tmp/asfa-wave-state.json \
  /tmp/asfa-wave-state.json.lock /tmp/asfa-wave-plan.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.wave.json \
  --state /tmp/asfa-wave-state.json \
  --out /tmp/asfa-wave-report.json \
  --wave-out /tmp/asfa-wave-plan.json \
  --now 100 --wave-max-jobs 3 --wave-max-per-source 2
cmp fixtures/qfos-wave-state.json /tmp/asfa-wave-state.json
cmp fixtures/qfos-wave-plan.json /tmp/asfa-wave-plan.json
python3 scripts/verify-wave-python.py \
  --registry config/sessions.wave.json \
  --snapshot /tmp/asfa-wave-state.json \
  --plan /tmp/asfa-wave-plan.json \
  --expect-plan-hash 5b27a80652ea74fc1b11e07033119ea49708018244325e5dae56f0f6bb88ca34
python3 scripts/verify-wave-python.py \
  --registry config/sessions.execution.json \
  --snapshot fixtures/qfos-exec-pre-state.json \
  --plan fixtures/qfos-exec-plan.json \
  --expect-plan-hash f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a
python3 scripts/verify-execution-python.py \
  --closed-world --self-test \
  --expect-plan-hash f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a \
  --expect-execution-hash 4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c
rm -f /tmp/asfa-exec-state.json /tmp/asfa-exec-state.json.lock \
  /tmp/asfa-exec-pre-state.json /tmp/asfa-exec-plan.json /tmp/asfa-exec-report.json \
  /tmp/asfa-exec-replay-report.json /tmp/asfa-exec-bridge.json \
  /tmp/asfa-exec-committed.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-exec-state.json \
  --out /tmp/asfa-exec-bridge.json \
  --wave-out /tmp/asfa-exec-plan.json \
  --now 50
cmp fixtures/qfos-exec-pre-state.json /tmp/asfa-exec-state.json
cp /tmp/asfa-exec-state.json /tmp/asfa-exec-pre-state.json
cmp fixtures/qfos-exec-plan.json /tmp/asfa-exec-plan.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-exec-state.json \
  --out /tmp/asfa-exec-bridge.json \
  --wave-out /tmp/asfa-exec-plan.json \
  --execute-wave --execution-out /tmp/asfa-exec-report.json \
  --now 100
cmp fixtures/qfos-exec-state.json /tmp/asfa-exec-state.json
cmp fixtures/qfos-exec-report.json /tmp/asfa-exec-report.json
python3 scripts/verify-execution-python.py \
  --registry config/sessions.execution.json \
  --pre-snapshot /tmp/asfa-exec-pre-state.json \
  --snapshot /tmp/asfa-exec-state.json \
  --plan /tmp/asfa-exec-plan.json \
  --report /tmp/asfa-exec-report.json \
  --closed-world --self-test \
  --expect-plan-hash f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a \
  --expect-execution-hash 4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c
cp /tmp/asfa-exec-state.json /tmp/asfa-exec-committed.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-exec-state.json \
  --out /tmp/asfa-exec-bridge.json \
  --wave-out /tmp/asfa-exec-plan.json \
  --execute-wave --execution-out /tmp/asfa-exec-replay-report.json \
  --now 100
cmp /tmp/asfa-exec-committed.json /tmp/asfa-exec-state.json
python3 - <<'PY'
import json
with open('/tmp/asfa-exec-replay-report.json') as f:
    report = json.load(f)
assert report['summary'] == {
    'offered': 7,
    'succeeded': 0,
    'dead_lettered': 0,
    'skipped_succeeded': 2,
    'skipped_dead_lettered': 5,
}, report['summary']
print('execution replay: PASS', report['summary'])
PY
rm -rf /tmp/asfa-ticket-v5
mkdir -p /tmp/asfa-ticket-v5
cp fixtures/qfos-exec-pre-state.json /tmp/asfa-ticket-v5/state.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-ticket-v5/state.json \
  --out /tmp/asfa-ticket-v5/mint-bridge.json \
  --wave-out /tmp/asfa-ticket-v5/plan.json \
  --ticket-mint-root nonce-1 --ticket-controller root --ticket-agent alice \
  --ticket-out /tmp/asfa-ticket-v5/mint.json \
  --now 50
cmp fixtures/qfos-exec-plan.json /tmp/asfa-ticket-v5/plan.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-ticket-v5/state.json \
  --out /tmp/asfa-ticket-v5/execute-bridge.json \
  --wave-out /tmp/asfa-ticket-v5/plan.json \
  --execute-wave --ticketed-execution --ticket-agent alice \
  --execution-out /tmp/asfa-ticket-v5/execution.json \
  --ticket-out /tmp/asfa-ticket-v5/execute.json \
  --now 100
cmp fixtures/qfos-exec-report.json /tmp/asfa-ticket-v5/execution.json
cp /tmp/asfa-ticket-v5/state.json /tmp/asfa-ticket-v5/committed.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-ticket-v5/state.json \
  --out /tmp/asfa-ticket-v5/replay-bridge.json \
  --wave-out /tmp/asfa-ticket-v5/plan.json \
  --execute-wave --ticketed-execution --ticket-agent alice \
  --execution-out /tmp/asfa-ticket-v5/replay.json \
  --ticket-out /tmp/asfa-ticket-v5/replay-ticket.json \
  --now 101
cmp /tmp/asfa-ticket-v5/committed.json /tmp/asfa-ticket-v5/state.json
python3 scripts/verify-ticket-utxo-python.py \
  --state /tmp/asfa-ticket-v5/state.json
COGNITIVE_OUTPUT="$(cargo run --locked --quiet --example cognitive_demo -p asfa-userspace)"
COGNITIVE_OUTPUT="$COGNITIVE_OUTPUT" python3 - <<'PY'
import os
expected = 'skill_output={"sum":42}; edge=1; matches=[1]'
actual = os.environ['COGNITIVE_OUTPUT'].strip()
assert actual == expected, (actual, expected)
print('cognitive demo: PASS', actual)
PY
rm -f /tmp/asfa-smoke-report.json /tmp/asfa-smoke-state.json
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.smoke.json \
  --out /tmp/asfa-smoke-report.json \
  --state /tmp/asfa-smoke-state.json \
  --now 1000
python3 scripts/verify-policy-python.py \
  --fixture fixtures/policy-oracle.json \
  --registry config/sessions.smoke.json \
  --snapshot /tmp/asfa-smoke-state.json
python3 - <<'PY'
import json
with open('/tmp/asfa-smoke-report.json') as f:
    report = json.load(f)
assert report['summary'] == {'total': 3, 'verified': 1, 'failed': 2}, report['summary']
kinds = {r['session']: r['status']['kind'] for r in report['records']}
assert kinds == {'good': 'verified', 'malformed': 'invalid_json', 'missing': 'transport'}, kinds
print('smoke: PASS', report['summary'], kinds)
PY
