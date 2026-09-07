#!/usr/bin/env bash
# The Rust version is pinned in two places that do not update together:
# rust-toolchain.toml (what every developer, PR CI job, and the macOS/Windows
# release builds use via rustup) and the RUST_VERSION installed by the Docker
# builders (what the Linux release binaries and the node/proxy images are
# built with). Nothing on PR CI builds those Dockerfiles, so a
# drift between the two only surfaces when a release tag is pushed — which is
# how the v1.4.0 release build failed: a dependency refresh raised the MSRV
# past the Docker image's rustc while rust-toolchain.toml was already ahead.
#
# Compare the exact toolchain version and the base image's major.minor.
# Official image tags can lag behind Rust patch releases, so the builders
# install the requested patch explicitly with rustup.
set -euo pipefail
cd "$(dirname "$0")/.."

want=$(sed -nE 's/^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' rust-toolchain.toml)
[ -n "$want" ] || { echo "ERROR: could not read the channel from rust-toolchain.toml"; exit 1; }

status=0
for f in docker/builder/Dockerfile docker/ika-node/Dockerfile docker/ika-proxy/Dockerfile sdk/typescript/test/system-tests/Dockerfile; do
  base=$(sed -nE 's/^FROM rust:([0-9]+\.[0-9]+)-trixie AS builder$/\1/p' "$f")
  got=$(sed -nE 's/^ENV RUST_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' "$f")
  if [ "$base" != "${want%.*}" ]; then
    echo "ERROR: $f: expected 'FROM rust:${want%.*}-trixie AS builder'"; status=1
  fi
  if [ "$got" != "$want" ]; then
    echo "ERROR: $f: expected 'ENV RUST_VERSION=$want' to match rust-toolchain.toml"; status=1
  fi
done
[ $status -eq 0 ] && echo "rust toolchain pins consistent ($want): rust-toolchain.toml + 4 Dockerfiles"
exit $status
