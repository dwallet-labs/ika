# Sui upstream as a reference

ika is forked from Sui Network. Much of the node, authority, checkpoint,
epoch, and networking structure mirrors Sui's, and the consensus layer
(Mysticeti) is consumed from Sui directly. When a forked subsystem is
unclear, or you're reasoning about consensus behavior, **read the pinned
Sui source** — it is the canonical reference for the patterns ika
inherited.

## Where the source is

- **Pinned version:** the `mainnet-v1.70.2` tag of
  `https://github.com/MystenLabs/sui` (sometimes a `testnet-v*` tag —
  check the `tag = "..."` in the root `Cargo.toml`). Always read the
  version ika actually pins; older/newer Sui differs.
- **Browse online:** github.com/MystenLabs/sui at that tag — the stable
  way to reference a specific file/line.
- **Local checkout** (fetched by cargo for the git dependencies):
  `~/.cargo/git/checkouts/sui-<hash>/<rev>/`. The `<rev>` is the commit
  the tag resolves to; find the directory with
  `ls -d ~/.cargo/git/checkouts/sui-*/*/` (the `sui-rust-sdk-*` checkout
  is a different dependency — the one you want has `consensus/`,
  `crates/`, `sui-execution/` at its root). If it's absent, a
  `cargo fetch` / build populates it.

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
