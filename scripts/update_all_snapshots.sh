#!/bin/bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Automatically update all snapshots. This is needed when the protocol config
# is changed.
#
# NOTE: `ika-protocol-config`'s snapshot test exists to pin *released* protocol
# versions. Only ever accept a snapshot for a version you just added — never
# re-record an existing one (see the banner the test itself prints).

set -x
set -e

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
ROOT="$SCRIPT_DIR/.."

cd "$ROOT" && cargo insta test --review -p ika-protocol-config
