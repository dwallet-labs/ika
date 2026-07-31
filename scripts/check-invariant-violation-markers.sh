#!/usr/bin/env bash
# Keep should-never-happen logs coupled to their Prometheus counter.
set -euo pipefail
cd "$(dirname "$0")/.."

matches="$(
    grep -RInE --include='*.rs' \
        'should_never_happen[[:space:]]*=[[:space:]]*true[[:space:]]*,' crates \
        | grep -v '^crates/ika-types/src/metrics.rs:' \
        || true
)"
if [[ -n "$matches" ]]; then
    echo "ERROR: bare should_never_happen marker bypasses report_invariant_violation!:"
    echo "$matches"
    exit 1
fi

if ! grep -Eq 'tracing::error!\(should_never_happen[[:space:]]*=[[:space:]]*true[[:space:]]*,' \
    crates/ika-types/src/metrics.rs; then
    echo "ERROR: report_invariant_violation! no longer emits should_never_happen = true"
    exit 1
fi

# These sites live in the five-second network-key sync loop. They must remain
# transition-gated: putting either marker back on the raw condition turns one
# incident into hundreds of invariant events per host per hour.
syncer=crates/ika-core/src/sui_connector/sui_syncer.rs
for site in \
    network_key_registry_read_empty \
    stranded_network_key_missing_from_registry_read
do
    count="$(grep -Fc "\"$site\"" "$syncer")"
    if [[ "$count" -ne 1 ]] || \
        ! grep -B 3 "\"$site\"" "$syncer" | grep -q 'ConditionTransition::Entered'
    then
        echo "ERROR: hot-loop invariant site '$site' must have exactly one transition-gated call:"
        grep -n "\"$site\"" "$syncer" || true
        exit 1
    fi
done

echo "invariant violation markers OK"
