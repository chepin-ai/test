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
  outbox/asfa-ai-outbox.json
python3 scripts/verify-policy-python.py --fixture fixtures/policy-oracle.json
python3 scripts/verify-wave-python.py \
  --expect-plan-hash fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302
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
  --expect-plan-hash fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302
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
