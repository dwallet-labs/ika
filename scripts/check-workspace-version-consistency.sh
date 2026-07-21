#!/usr/bin/env bash
# Guard: every standalone lockfile that pins root-workspace crates must agree
# with the workspace version. The v1.2.2 bump updated Cargo.toml + the root
# Cargo.lock but missed sdk/ika-wasm/Cargo.lock, leaving its path deps at
# 1.2.1 and breaking --locked SDK builds. This makes that class of miss a
# red PR instead of a post-release discovery.
#
# A path dependency appears in a lockfile as a [[package]] with NO `source`
# line. We assert every such package (except the wasm workspace's own crates)
# matches the root workspace version.
set -euo pipefail

WS_VERSION=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
[ -n "$WS_VERSION" ] || { echo "::error::could not read workspace version from Cargo.toml"; exit 1; }

FAIL=0
check_lock() {
  local lock="$1"; shift
  local skip_names=("$@")
  # Emit "name version has_source" per [[package]] block.
  awk '
    /^\[\[package\]\]/ { if (name != "") print name, ver, src; name=""; ver=""; src="0" }
    /^name = / { gsub(/"/,"",$3); name=$3 }
    /^version = / { gsub(/"/,"",$3); ver=$3 }
    /^source = / { src="1" }
    END { if (name != "") print name, ver, src }
  ' "$lock" | while read -r name ver has_source; do
    [ "$has_source" = "1" ] && continue
    for s in "${skip_names[@]}"; do [ "$name" = "$s" ] && continue 2; done
    if [ "$ver" != "$WS_VERSION" ]; then
      echo "::error file=$lock::$lock pins path dependency '$name' at $ver but the workspace version is $WS_VERSION - run 'cargo update --workspace' in $(dirname "$lock")"
      echo "MISMATCH" >> /tmp/lock-guard-failures
    fi
  done
}

rm -f /tmp/lock-guard-failures
# sdk/ika-wasm is its own workspace; its own package (dwallet-mpc-wasm,
# independently versioned) is skipped. Add new standalone lockfiles here as
# they appear.
check_lock sdk/ika-wasm/Cargo.lock dwallet-mpc-wasm

if [ -s /tmp/lock-guard-failures ]; then
  exit 1
fi
echo "workspace version consistency OK (workspace $WS_VERSION)"
