# Sui upstream as a reference

ika is forked from Sui Network. Much of the node, authority, checkpoint,
epoch, and networking structure mirrors Sui's, and the consensus layer
(Mysticeti) is consumed from Sui directly. When a forked subsystem is
unclear, or you're reasoning about consensus behavior, **read the pinned
Sui source** — it is the canonical reference for the patterns ika
inherited.

## Where the source is

`Cargo.lock` is authoritative for each crate. Most Sui crates use the upstream
release tag in root `Cargo.toml`. **`consensus-core` is patched from the
`dwallet-labs/sui` fork** to provide consensus-owned, consumer-paced full replay.
This is a compatibility backport of
[MystenLabs/sui#27909](https://github.com/MystenLabs/sui/pull/27909) to Ika's
pinned Sui release, not a switch to the newer Sui main branch.
Its companion crates retain the upstream source identity. Do not infer the
consensus implementation from the first Sui entry or the workspace dependency's
tag without checking Cargo's patch table.

Resolve the crate's actual source before reading it:

```bash
python3 - <<'PYTHON'
import tomllib
with open('Cargo.lock', 'rb') as lock:
    packages = tomllib.load(lock)['package']
for name in ['consensus-core', 'consensus-config', 'sui-core']:
    for package in packages:
        if package['name'] == name:
            print(name, package.get('source', 'local path'))
PYTHON
```

The source records both the repository and resolved revision. Match that
revision against `~/.cargo/git/checkouts/sui-*/<rev-prefix>/`; several upstream
and fork checkouts can coexist. If absent, `cargo fetch` populates it. For web
references, use the recorded repository and exact revision.

The `sui-rust-sdk-*` directories are a separate dependency. The Sui checkout
has `consensus/`, `crates/`, and `sui-execution/` at its root.

**Derive the source every time, including for a one-line check.** Nearby
revisions look alike until the detail that changed matters. Reading a plausible
file is not proof that Cargo uses it. Cite the revision with source anchors so
reviewers can verify claims after a dependency bump.

## What to read for what

- **Consensus (Mysticeti):** Sui's `consensus/core/` — block production,
  commit rule, the DAG, leader schedule, the `CommitConsumer`. ika routes
  MPC messages through this; the commit/round semantics the freeze and
  epoch-close logic depend on (leader rounds advancing non-monotonically,
  commit boundaries) are defined here, not in ika.
- **Authority / epoch / checkpoint patterns:** ika's
  `crates/ika-core/src/authority/`, `epoch/`, and checkpoint stores mirror
  Sui's `crates/sui-core/`. When an ika type or flow looks like it has
  unexplained machinery, diff it against the Sui original — the ika
  version is often "Sui's file with the MPC-specific parts swapped in."
- **Networking:** ika's P2P / anemo usage follows Sui's `crates/sui-network`
  and the anemo patterns.

## How to use it

1. Find the ika file you're working on; identify the Sui crate it mirrors
   (names usually match: `sui-core` → `ika-core`, etc.).
2. Open the same-named file in the pinned Sui source and compare — the
   delta is the ika-specific behavior; the shared part behaves like
   upstream.
3. For consensus questions, go straight to `consensus/core/` rather than
   inferring behavior from ika's call sites.

## Caveat

It is a *reference*, not gospel for ika's current behavior: ika has
renamed symbols, removed some flows, and added MPC-specific logic, and it
is pinned to one Sui version. Use upstream to understand inherited
mechanics and intent; confirm ika's actual behavior against ika's code at
the pinned version.
