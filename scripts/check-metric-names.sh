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

# `ika_consensus_*` is NOT ika's namespace. consensus_manager/mod.rs starts
# consensus-core with `Registry::new_custom(Some("ika_consensus"))`, so every
# metric upstream registers is exported under that prefix, and upstream may add
# any name at any time. RegistryService merges that registry with ika's own at
# /metrics, and prometheus's duplicate check is per-registry, so a name present
# on both sides is silently served twice and the scraper drops a sample per
# scrape (ika #2022). The rule is structural: ika registers nothing in there.
#
# THIS LIST ONLY EVER SHRINKS. It enumerates OUR OWN pre-existing names, which
# we control and which are stable — it does NOT mirror anything upstream, so
# there is nothing to regenerate on a Sui bump. Adding an entry means putting a
# NEW ika metric into a namespace that is not ours; pick a name outside
# `ika_consensus_*` instead. Deleting an entry, as each metric migrates out, is
# the only edit this list should ever see.
#
# Keep in sync with LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS in
# crates/ika-core/src/epoch/epoch_metrics.rs (the runtime half of this rule).
LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS = {
    # crates/ika-core/src/authority.rs (AuthorityMetrics)
    "ika_consensus_calculated_throughput",
    "ika_consensus_calculated_throughput_profile",
    "ika_consensus_committed_messages",
    "ika_consensus_committed_subdags",
    "ika_consensus_committed_user_transactions",
    "ika_consensus_handler_cancelled_transactions",
    "ika_consensus_handler_num_low_scoring_authorities",
    "ika_consensus_handler_processed",
    "ika_consensus_handler_scores",
    "ika_consensus_handler_transaction_sizes",
    # crates/ika-core/src/consensus_manager/mod.rs (ConsensusManagerMetrics)
    "ika_consensus_manager_shutdown_latency",
    "ika_consensus_manager_start_latency",
    # crates/ika-core/src/epoch/epoch_metrics.rs (EpochMetrics)
    "ika_consensus_last_committed_timestamp_seconds",
}

namespace_violations = sorted(
    n
    for n in names
    if n.startswith("ika_consensus_") and n not in LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS
)
if namespace_violations:
    print(
        "ERROR: these ika metrics are registered inside `ika_consensus_*`, the\n"
        "namespace ika hands to consensus-core, so upstream may collide with them\n"
        "at any time and the node would publish each name TWICE, dropping a sample\n"
        "per scrape (ika #2022):",
        file=sys.stderr,
    )
    for v in namespace_violations:
        print(f"  {v}", file=sys.stderr)
    print(
        "Give the metric a name outside `ika_consensus_*`. Do NOT add it to\n"
        "LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS — that list only shrinks.\n"
        "Convention: dev-docs/conventions/metrics.md",
        file=sys.stderr,
    )
    sys.exit(1)

stale_namespace = sorted(
    a for a in LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS if a not in names
)
if stale_namespace:
    print(
        "ERROR: LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS lists metrics that are no\n"
        "longer registered — delete them, the list only shrinks:",
        file=sys.stderr,
    )
    for s in stale_namespace:
        print(f"  {s}", file=sys.stderr)
    sys.exit(1)

stale = sorted(a for a in allowlist if a not in names)
if stale:
    print("NOTE: allowlist entries no longer registered (consider pruning):", file=sys.stderr)
    for s in stale:
        print(f"  {s}", file=sys.stderr)

print(
    f"metric names OK ({len(names)} literal, {dynamic_sites} dynamic sites skipped; "
    f"{len(LEGACY_IKA_CONSENSUS_NAMESPACE_METRICS)} legacy `ika_consensus_*` names "
    f"remaining to migrate)"
)
EOF
