#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: bash scripts/lean-federation-gate.sh SOURCE_COMMIT WORK_DIR REPO" >&2
  exit 64
fi

SOURCE_COMMIT="$1"
WORK_DIR="$2"
REPO="$3"

if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit must be a full lowercase Git SHA" >&2
  exit 64
fi

cd "$REPO"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
python3 scripts/lean-federation.py run \
  --repo "$REPO" \
  --source-commit "$SOURCE_COMMIT" \
  --work-dir "$WORK_DIR"
python3 scripts/verify-lean-federation-python.py \
  --report "$WORK_DIR/report.json" \
  --repo "$REPO" \
  --require-commit \
  --out "$WORK_DIR/oracle.json"
