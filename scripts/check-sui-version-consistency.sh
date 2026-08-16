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

# The standalone SDK is a coordinated four-crate pin. A partial bump can
# compile while mixing protobuf, transaction, signing, and wire-type surfaces.
sdk_crates='sui-crypto sui-rpc sui-sdk-types sui-transaction-builder'
sdk_revs=''
for crate in $sdk_crates; do
    line=$(grep -E "^${crate} = .*MystenLabs/sui-rust-sdk.git" Cargo.toml || true)
    if [ -z "$line" ]; then
        echo "ERROR: Cargo.toml has no standalone SDK pin for $crate" >&2
        fail=1
        continue
    fi
    count=$(echo "$line" | grep -c . || true)
    if [ "$count" -ne 1 ]; then
        echo "ERROR: Cargo.toml has $count standalone SDK dependency lines for $crate" >&2
        fail=1
        continue
    fi
    rev=$(echo "$line" | grep -oE 'rev = "[0-9a-f]{40}"' | grep -oE '[0-9a-f]{40}' || true)
    if [ -z "$rev" ]; then
        echo "ERROR: $crate must pin sui-rust-sdk with one full 40-character rev" >&2
        fail=1
        continue
    fi
    sdk_revs="${sdk_revs}${rev}\n"
done
sdk_revs=$(printf '%b' "$sdk_revs" | grep -v '^$' | sort -u || true)
sdk_rev_count=$(echo "$sdk_revs" | grep -c . || true)
if [ "$sdk_rev_count" -ne 1 ]; then
    echo "ERROR: standalone SDK crates pin $sdk_rev_count distinct revisions:" >&2
    echo "$sdk_revs" >&2
    fail=1
else
    echo "root Cargo.toml sui-rust-sdk pin: $sdk_revs"
fi

# Every other location must carry the same tag (same flavor, same version).
# Compare whatever tags a file carries against the root pin.
compare_tags() {
    local file="$1" found="$2"
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

# A location that MUST exist and MUST carry the pin. A missing file or a file
# that has lost its tag used to return success silently, so a rename or a
# refactor that dropped the pin read as green.
check_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "ERROR: $file is checked for the Sui pin but does not exist" >&2
        echo "       Update the list in $0 if the file moved." >&2
        fail=1
        return 0
    fi
    local found
    found=$(grep -oE "$TAG_RE" "$file" | sort -u || true)
    if [ -z "$found" ]; then
        echo "ERROR: $file is checked for the Sui pin but carries no release tag" >&2
        echo "       Update the list in $0 if the pin legitimately moved out." >&2
        fail=1
        return 0
    fi
    compare_tags "$file" "$found"
}

# A location that legitimately carries no tag today because it resolves Sui
# deps against the root workspace, but must not drift if a direct pin is added
# later. The FILE must still exist: if it does not, this list is stale and the
# guard has quietly stopped watching something.
check_optional_pin() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "ERROR: $file is listed for the Sui pin check but does not exist" >&2
        echo "       Update the list in $0 if the file moved or was removed." >&2
        fail=1
        return 0
    fi
    local found
    found=$(grep -oE "$TAG_RE" "$file" | sort -u || true)
    if [ -z "$found" ]; then
        echo "$file: OK (no direct pin)"
        return 0
    fi
    compare_tags "$file" "$found"
}

check_file .github/workflows/ts-integration-tests.yaml
check_file .github/workflows/ts-ci.yaml
check_file .github/workflows/system-tests-ci.yaml
check_file .github/workflows/sdk-live-endpoints.yaml
check_file CLAUDE.md
# Excluded workspaces: manifests resolve workspace deps against the root,
# but any direct tag pin added later must stay in lockstep.
check_optional_pin sdk/ika-wasm/Cargo.toml

exit "$fail"
