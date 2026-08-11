#!/usr/bin/env bash
# Metric-name ratchet, two halves of one rule: ika owns `ika_*` and nothing
# else owns any of it.
#   1. every metric registered with a literal name uses the `ika_` prefix (or
#      appears in scripts/metric-name-allowlist.txt, the frozen legacy set —
#      never add to it; rename or prefix new metrics instead);
#   2. no prefixed registry re-exports someone else's metrics under a prefix
#      starting with `ika`.
# Together those make an ika name and a vendored name unable to occupy the
# same string, whatever upstream adds (ika #2022).
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

# The vendored half of the namespace rule. ika's own metrics all start with
# `ika_` (enforced above), so a re-exported registry must NOT — otherwise the
# two namespaces share a prefix and an upstream name can land exactly on one of
# ours. That is #2022: RegistryService merges the registries at /metrics,
# prometheus's duplicate check is per-registry, and the prefix is applied at
# gather(), so the collision is invisible until a scraper starts dropping
# samples.
#
# Checked from source, not from a gathered registry, because it is a property
# of how the registry is CREATED. Self-extending by construction: a vendored
# registry added later is caught without anyone updating a list — which is the
# whole point, since the failure mode of the previous design was a list nobody
# remembered to update.
#
# Matches after the first `#[cfg(test)]` in a file are skipped: test modules
# build throwaway registries to exercise composition, and their prefixes never
# reach a node's endpoint. That heuristic is REPORTED, not silent — the summary
# line prints how many were skipped, so a production registry that ever ends up
# below a test module shows as a count change instead of vanishing.
VENDORED_PREFIX = re.compile(r'new_custom\(\s*Some\(\s*"(?P<prefix>[a-z0-9_]+)"')
vendored = {}
test_scoped = 0
for path in pathlib.Path("crates").rglob("*.rs"):
    text = path.read_text(errors="replace")
    cutoff = text.find("#[cfg(test)]")
    if cutoff == -1:
        cutoff = len(text)
    for m in VENDORED_PREFIX.finditer(text, 0, cutoff):
        vendored.setdefault(m.group("prefix"), set()).add(str(path))
    test_scoped += len(VENDORED_PREFIX.findall(text[cutoff:]))

ika_prefixed_registries = sorted(p for p in vendored if p.startswith("ika"))
if ika_prefixed_registries:
    print(
        "ERROR: a prefixed registry re-exports metrics under an `ika`-prefixed\n"
        "namespace. That shares a prefix with ika's own metrics, so an upstream\n"
        "name can collide with one of ours and the node publishes it twice,\n"
        "dropping a sample per scrape (ika #2022):",
        file=sys.stderr,
    )
    for prefix in ika_prefixed_registries:
        for f in sorted(vendored[prefix]):
            print(f"  {prefix!r} in {f}", file=sys.stderr)
    print(
        "Give the vendored registry a prefix that does NOT start with `ika`\n"
        "(e.g. `consensus_ika`). Convention: dev-docs/conventions/metrics.md",
        file=sys.stderr,
    )
    sys.exit(1)

stale = sorted(a for a in allowlist if a not in names)
if stale:
    print("NOTE: allowlist entries no longer registered (consider pruning):", file=sys.stderr)
    for s in stale:
        print(f"  {s}", file=sys.stderr)

print(
    f"metric names OK ({len(names)} literal, {dynamic_sites} dynamic sites skipped; "
    f"{len(vendored)} prefixed registr{'y' if len(vendored) == 1 else 'ies'} "
    f"({', '.join(sorted(vendored)) or 'none'}), none under `ika`; "
    f"{test_scoped} test-scoped skipped)"
)
EOF
