#!/usr/bin/env python3
"""Fail CI when common credential forms enter tracked source files."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "github_pat": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "legacy_otp_field": re.compile(r'["\']otp["\']\s*:'),
}
SKIP_PARTS = {".git", "target", ".pytest_cache"}
failures = []
for path in ROOT.rglob("*"):
    if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
        continue
    if path.suffix.lower() not in {".rs", ".toml", ".json", ".md", ".yml", ".yaml", ".sh", ".py", ".v"}:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            failures.append(f"{path.relative_to(ROOT)}:{line}: {name}")
if failures:
    print("credential scan failed:", file=sys.stderr)
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("credential scan: PASS")
