#!/bin/bash -e
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear

# verify that git repo is clean
if [[ -n $(git status -s) ]]; then
  echo "Working directory is not clean. Please commit all changes before running this script."
  exit 1
fi

# apply git patch
git apply ./scripts/simtest/config-patch

root_dir=$(git rev-parse --show-toplevel)
# Must match scripts/simtest/cargo-simtest: ika has no examples/move/basics
# (that is a Sui path), the no-dep warm-up stub lives in ika-test-cluster.
export SIMTEST_STATIC_INIT_MOVE=$root_dir"/crates/ika-test-cluster/move-stub"

MSIM_WATCHDOG_TIMEOUT_MS=60000 MSIM_TEST_SEED=1 cargo llvm-cov --ignore-run-fail --lcov --output-path lcov-simtest.info nextest --cargo-profile simulator

# remove the patch
git checkout .cargo/config.toml Cargo.toml Cargo.lock
