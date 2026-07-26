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

echo "invariant violation markers OK"
