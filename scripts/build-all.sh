#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/asfa-os-xi-target}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
python3 scripts/check-no-secrets.py
cargo run --locked -p asfa-bridge-poller -- \
  --config config/sessions.smoke.json \
  --out /tmp/asfa-smoke-report.json \
  --now 1000
python3 - <<'PY'
import json
with open('/tmp/asfa-smoke-report.json') as f:
    report = json.load(f)
assert report['summary'] == {'total': 3, 'verified': 1, 'failed': 2}, report['summary']
kinds = {r['session']: r['status']['kind'] for r in report['records']}
assert kinds == {'good': 'verified', 'malformed': 'invalid_json', 'missing': 'transport'}, kinds
print('smoke: PASS', report['summary'], kinds)
PY
