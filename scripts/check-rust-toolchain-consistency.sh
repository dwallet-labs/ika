#!/usr/bin/env bash
# The Rust version is pinned in two places that do not update together:
# rust-toolchain.toml (what every developer, PR CI job, and the macOS/Windows
# release builds use via rustup) and the `FROM rust:<ver>-bookworm` base image
# of the Docker builders (what the Linux release binaries and the node/proxy
# images are built with). Nothing on PR CI builds those Dockerfiles, so a
# drift between the two only surfaces when a release tag is pushed — which is
# how the v1.4.0 release build failed: a dependency refresh raised the MSRV
# past the Docker image's rustc while rust-toolchain.toml was already ahead.
#
# The Docker tag carries major.minor (rust:1.97-bookworm tracks the latest
# 1.97.x), so that is the granularity compared.
set -euo pipefail
cd "$(dirname "$0")/.."

want=$(sed -nE 's/^channel = "([0-9]+\.[0-9]+)(\.[0-9]+)?"$/\1/p' rust-toolchain.toml)
[ -n "$want" ] || { echo "ERROR: could not read the channel from rust-toolchain.toml"; exit 1; }

status=0
for f in docker/builder/Dockerfile docker/ika-node/Dockerfile docker/ika-proxy/Dockerfile; do
  got=$(sed -nE 's/^FROM rust:([0-9]+\.[0-9]+)(\.[0-9]+)?-bookworm AS builder$/\1/p' "$f")
  if [ -z "$got" ]; then
    echo "ERROR: $f: no 'FROM rust:<major.minor>-bookworm AS builder' line found"; status=1
  elif [ "$got" != "$want" ]; then
    echo "ERROR: $f pins rust:$got but rust-toolchain.toml is $want — bump the FROM line (the Linux release build compiles with the image's rustc, and the lockfile's MSRV already assumes $want)"; status=1
  fi
done
[ $status -eq 0 ] && echo "rust toolchain pins consistent ($want): rust-toolchain.toml + 3 Dockerfiles"
exit $status
