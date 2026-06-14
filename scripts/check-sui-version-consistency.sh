#!/usr/bin/env bash
# Verify the Sui version pin agrees everywhere it lives.
# The pin can be a mainnet-vX.Y.Z OR testnet-vX.Y.Z tag; the network
# flavor is part of the pin and must match too.
# Locations and bump procedure: dev-docs/conventions/sui-version-bump.md
set -euo pipefail
cd "$(dirname "$0")/.."

TAG_RE='(mainnet|testnet)-v[0-9]+\.[0-9]+\.[0-9]+'
fail=0

# Source of truth: the tag pinned in the root Cargo.toml. There must be
# exactly one distinct Sui release tag across all Sui git dependencies.
tags=$(grep -oE "$TAG_RE" Cargo.toml | sort -u)
count=$(echo "$tags" | grep -c . || true)
if [ "$count" -ne 1 ]; then
    echo "ERROR: root Cargo.toml pins $count distinct Sui release tags:" >&2
    echo "$tags" >&2
    fail=1
fi
tag=$(echo "$tags" | head -1)
echo "root Cargo.toml Sui pin: $tag"

# Every other location must carry the same tag (same flavor, same version).
check_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local found
    found=$(grep -oE "$TAG_RE" "$file" | sort -u || true)
    [ -n "$found" ] || return 0
    local mismatched
    mismatched=$(echo "$found" | grep -v -x "$tag" || true)
    if [ -n "$mismatched" ]; then
        echo "ERROR: $file references Sui tag(s) [$(echo "$mismatched" | tr '\n' ' ')] != $tag" >&2
        echo "       Bump everywhere together: dev-docs/conventions/sui-version-bump.md" >&2
        fail=1
    else
        echo "$file: OK"
    fi
}

check_file .github/workflows/ts-integration-tests.yaml
check_file .github/workflows/ts-ci.yaml
check_file CLAUDE.md
# Excluded workspaces: manifests resolve workspace deps against the root,
# but any direct tag pin added later must stay in lockstep.
check_file sdk/ika-wasm/Cargo.toml
check_file sdk/dwallet-mpc-wasm/Cargo.toml

exit "$fail"
