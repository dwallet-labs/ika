#!/usr/bin/env bash
# Workspace-membership ratchet: every crate under `crates/` must be something
# cargo actually builds, or be named in the root `exclude` list.
#
# Cargo is silent about the third state. A crate that is in neither `members`
# nor `exclude` — and is not a path dependency of a member, which cargo
# auto-includes — is simply never built. It rots invisibly: `ika-cluster-test`
# came to inherit eleven workspace dependencies that do not exist
# (`ika-indexer`, `ika-faucet`, `ika-graphql-rpc`, …) and `ika-sdk` came to
# import `ika_types` modules that had been removed, and neither ever failed a
# build, because neither was in one.
#
# Membership is taken from `cargo metadata`, not by parsing `members`, so
# cargo's own resolution rules are the authority — in particular the
# auto-inclusion of members' path dependencies, which a naive read of
# `members` gets wrong.
#
# Deliberately NOT checked here: that each `<dep>.workspace = true` in a member
# resolves to a `[workspace.dependencies]` entry. `cargo metadata` already
# fails outright when it does not, so a separate check could never fire — the
# command below would have errored first.
#
# Usage:
#   check-workspace-manifests.sh          # validate (CI)
set -euo pipefail
cd "$(dirname "$0")/.."

cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml \
  | python3 -c '
import json
import pathlib
import re
import sys

meta = json.load(sys.stdin)
built = {
    str(pathlib.Path(p["manifest_path"]).parent.resolve())
    for p in meta["packages"]
}

root = pathlib.Path("Cargo.toml").read_text()
m = re.search(r"^exclude = \[(.*?)^\]", root, re.M | re.S)
excluded = {
    str(pathlib.Path(e).resolve()) for e in re.findall(r"\"([^\"]+)\"", m.group(1))
} if m else set()

orphans = sorted(
    str(c.parent)
    for c in pathlib.Path("crates").glob("*/Cargo.toml")
    if str(c.parent.resolve()) not in built
    and str(c.parent.resolve()) not in excluded
)

if orphans:
    print(
        "ERROR: these crates are neither built by the workspace nor listed in\n"
        "`exclude`, so nothing ever checks that they still compile:",
        file=sys.stderr,
    )
    for o in orphans:
        print(f"  {o}", file=sys.stderr)
    print(
        "\nAdd each to `members` (it gets built and checked) or to `exclude`\n"
        "with a comment saying why, so its status is deliberate.",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"workspace membership OK ({len(built)} crates built, "
    f"{len(excluded)} explicitly excluded)"
)
'
