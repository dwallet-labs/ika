# Sui upstream as a reference

ika is forked from Sui Network. Much of the node, authority, checkpoint,
epoch, and networking structure mirrors Sui's, and the consensus layer
(Mysticeti) is consumed from Sui directly. When a forked subsystem is
unclear, or you're reasoning about consensus behavior, **read the pinned
Sui source** — it is the canonical reference for the patterns ika
inherited.

## Where the source is

- **Pinned version:** whatever release tag the root `Cargo.toml` pins —
  read it there (`grep 'tag = ' Cargo.toml`); it's a `mainnet-v*`
  (sometimes `testnet-v*`) tag of `https://github.com/MystenLabs/sui`.
  This page deliberately doesn't restate the number, so it can't drift out
  of sync: `Cargo.toml` is the source of truth (with a human-readable note
  in `CLAUDE.md`). Older/newer Sui differs, so always read the version ika
  actually pins.
- **Browse online:** github.com/MystenLabs/sui at that tag — the stable
  way to reference a specific file/line.
- **Local checkout** (fetched by cargo for the git dependencies):
  `~/.cargo/git/checkouts/sui-<hash>/<rev>/`. **Do not pick by eye** —
  every prior version bump leaves its own `<rev>` behind, so several
  structurally identical Sui checkouts usually coexist (this machine has
  three) and reading a stale one means reasoning about year-old upstream
  behavior. Derive the right one from the lockfile:

  ```bash
  # the rev cargo actually resolved, then the matching checkout dir
  REV=$(grep -m1 -oE 'MystenLabs/sui\?tag=[^#]*#[0-9a-f]+' Cargo.lock | cut -d'#' -f2)
  ls -d ~/.cargo/git/checkouts/sui-*/"${REV:0:7}"/
  ```

  (The `sui-rust-sdk-*` checkouts are a different dependency — the one you
  want has `consensus/`, `crates/`, `sui-execution/` at its root.) If it's
  absent, a `cargo fetch` / build populates it.

  **Derive it every time, including for "just one line".** The failure mode
  is silent by construction: a stale checkout is structurally identical, the
  file is where you expect, the symbol is there, and the code reads
  plausibly — nothing errors and nothing looks wrong. Reading a neighbouring
  revision usually AGREES with the pinned one, so "what I read matched what
  the code does" is not evidence you read the right tree; it is the
  most likely outcome either way, right up until the one detail that moved.
  Worked example: #2058 was implemented against `433212f` while the lockfile
  resolved `51d177a`. Every claim happened to hold at both, so the mistake
  cost only a re-verification pass — but that was luck, not method.

  Two consequences worth internalising:

  - **`Cargo.toml`'s tag is not enough to pick a directory.** It names the
    tag; checkouts are named by REV. Resolve the rev from `Cargo.lock`, as
    above, and check the directory prefix against it.
  - **Cite the rev, not just the path,** when a line number lands in a
    comment or a spec — `commit_observer.rs:162 (51d177a)` survives the next
    bump as a checkable claim, where a bare line number silently rots.

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
