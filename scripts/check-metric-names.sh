#!/usr/bin/env bash
# Metric-name ratchet, three halves of one rule: ika owns `ika_*` and nothing
# else owns any of it.
#   1. every metric registered with a literal name uses the `ika_` prefix (or
#      appears in scripts/metric-name-allowlist.txt, the frozen legacy set —
#      never add to it; rename or prefix new metrics instead);
#   2. no prefixed registry re-exports someone else's metrics under a prefix
#      starting with `ika`;
#   3. every metric is registered with an EXPLICIT registry —
#      `register_*_with_registry!`, never the bare `register_*!` form that
#      writes to prometheus's process-global default registry.
# Together those make an ika name and a vendored name unable to occupy the
# same string, whatever upstream adds (ika #2022).
#
# Rule 3 is what makes rule 1 total rather than best-effort. The extractor can
# only see names passed to `register_*_with_registry!`, so a metric registered
# on the default registry is exported by the binary and invisible to every
# check here — unvalidated, uninventoried, and undiscoverable by anyone writing
# a dashboard. ika-proxy shipped nine such metrics (`consumer_operations`,
# `relay_pressure`, `http_handler_hits`, …) straight through the 1.2.0
# `ika_` rename because of exactly that blind spot: they were gathered onto
# /metrics by `ika-proxy/src/metrics.rs` while no rule could reach them.
# Rejecting the bare form is preferred over teaching the extractor to read it,
# because an explicit registry is the workspace convention anyway
# (dev-docs/conventions/metrics.md) and rejection needs no per-macro upkeep.
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

# Any `register_*!` invocation. The ones ending in `_with_registry` name a
# registry explicitly; every other one writes to prometheus's default registry.
# Deliberately not restricted to today's prometheus macro list, so a metric
# family the crate adds later is covered without anyone editing this file. The
# cost is that an unrelated `register_*!` macro would be flagged — a loud,
# one-line-to-diagnose false positive, which is the failure direction to prefer
# over silently missing a real default-registry registration.
ANY_MACRO = re.compile(r'\bregister_(?P<kind>[a-z_]+)!')

sources = sorted(pathlib.Path("crates").rglob("*.rs"))

names = set()
dynamic_sites = 0
default_registry_sites = []
for path in sources:
    text = path.read_text(errors="replace")
    for m in MACRO.finditer(text):
        if m.group("name"):
            names.add(m.group("name"))
        else:
            dynamic_sites += 1
    for m in ANY_MACRO.finditer(text):
        if m.group("kind").endswith("_with_registry"):
            continue
        line = text.count("\n", 0, m.start()) + 1
        default_registry_sites.append((str(path), line, m.group(0).rstrip("!")))

if "--list" in sys.argv:
    for n in sorted(names):
        print(n)
    print(f"# {len(names)} literal names; {dynamic_sites} dynamic (format!-built) sites not listed", file=sys.stderr)
    sys.exit(0)

# Rule 3, checked BEFORE the name rules: a metric on the default registry is
# one the name rules cannot see at all, so a green prefix check over the rest
# means nothing while such a site exists.
if default_registry_sites:
    print(
        "ERROR: prometheus metrics must be registered with an EXPLICIT registry.\n"
        "These call sites use the bare macro, which registers on prometheus's\n"
        "process-global default registry — invisible to the `ika_` prefix rule\n"
        "and missing from the generated inventory, while still being exported:",
        file=sys.stderr,
    )
    for f, line, macro in default_registry_sites:
        print(f"  {f}:{line}: {macro}!", file=sys.stderr)
    print(
        "Use the `_with_registry` form and pass the registry the endpoint\n"
        "gathers (e.g. `register_counter_vec_with_registry!(name, help, labels,\n"
        "registry)`). Convention: dev-docs/conventions/metrics.md",
        file=sys.stderr,
    )
    sys.exit(1)

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

# The generated inventory in the metrics convention doc must match the
# source exactly. It drifted silently for months (24 missing names, one
# dead one) precisely because nothing enforced it — a list nobody
# remembers to update is the failure mode this script exists to prevent,
# so the doc block is checked here, in the same CI-run default path as
# the prefix rules.
doc_path = pathlib.Path("dev-docs/conventions/metrics.md")
doc_match = re.search(
    r"## Inventory \(generated\).*?```\n(?P<block>.*?)\n```",
    doc_path.read_text(),
    re.S,
)
if not doc_match:
    print(f"ERROR: inventory block not found in {doc_path}", file=sys.stderr)
    sys.exit(1)
documented = set(doc_match.group("block").splitlines())
missing_from_doc = sorted(names - documented)
dead_in_doc = sorted(documented - names)
if missing_from_doc or dead_in_doc:
    print(f"ERROR: {doc_path} inventory is out of date:", file=sys.stderr)
    for n in missing_from_doc:
        print(f"  missing: {n}", file=sys.stderr)
    for n in dead_in_doc:
        print(f"  no longer registered: {n}", file=sys.stderr)
    print(
        "Regenerate the block: ./scripts/check-metric-names.sh --list\n"
        "(paste the metric names into the fenced block under '## Inventory (generated)')",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"metric names OK ({len(names)} literal, {dynamic_sites} dynamic sites skipped; "
    f"{len(vendored)} prefixed registr{'y' if len(vendored) == 1 else 'ies'} "
    f"({', '.join(sorted(vendored)) or 'none'}), none under `ika`; "
    f"{test_scoped} test-scoped skipped); "
    f"{len(sources)} source files, no default-registry registration"
)
EOF
