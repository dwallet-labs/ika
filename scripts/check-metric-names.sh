#!/usr/bin/env bash
# Metric-name ratchet: every prometheus metric registered with a literal
# name must either use the `ika_` prefix (the convention for all NEW
# metrics) or appear in scripts/metric-name-allowlist.txt (the frozen
# legacy set — never add to it; rename or prefix new metrics instead).
#
# Names built dynamically (format!) cannot be validated statically and
# are skipped; keep those few call sites' generated names in the
# allowlist by hand (see the pruner's `kind` interpolation).
#
# Usage:
#   check-metric-names.sh          # validate (CI)
#   check-metric-names.sh --list   # print every literal metric name found
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "$@" <<'EOF'
import pathlib
import re
import sys

MACRO = re.compile(
    r'register_[a-z_]+_with_registry!\s*\(\s*(?:"(?P<name>[a-z0-9_]+)"|(?P<dynamic>format!|&|\w+\s*,))',
    re.S,
)

names = set()
dynamic_sites = 0
for path in pathlib.Path("crates").rglob("*.rs"):
    text = path.read_text(errors="replace")
    for m in MACRO.finditer(text):
        if m.group("name"):
            names.add(m.group("name"))
        else:
            dynamic_sites += 1

if "--list" in sys.argv:
    for n in sorted(names):
        print(n)
    print(f"# {len(names)} literal names; {dynamic_sites} dynamic (format!-built) sites not listed", file=sys.stderr)
    sys.exit(0)

allowlist_path = pathlib.Path("scripts/metric-name-allowlist.txt")
allowlist = {
    line.strip()
    for line in allowlist_path.read_text().splitlines()
    if line.strip() and not line.startswith("#")
}

violations = sorted(n for n in names if not n.startswith("ika_") and n not in allowlist)
if violations:
    print("ERROR: new prometheus metrics must use the `ika_` prefix:", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    print(
        "Rename the metric to ika_<name>. The allowlist is the FROZEN legacy\n"
        "set — do not add to it. Convention: dev-docs/conventions/metrics.md",
        file=sys.stderr,
    )
    sys.exit(1)

stale = sorted(a for a in allowlist if a not in names)
if stale:
    print("NOTE: allowlist entries no longer registered (consider pruning):", file=sys.stderr)
    for s in stale:
        print(f"  {s}", file=sys.stderr)

print(f"metric names OK ({len(names)} literal, {dynamic_sites} dynamic sites skipped)")
EOF
