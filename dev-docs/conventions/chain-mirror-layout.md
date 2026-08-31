# Chain-mirror layout discipline

Three Rust structs are **untagged mirrors** of Move structs deployed on
mainnet and testnet:

| Rust | Move |
|---|---|
| `DWalletCoordinatorInnerV1` (`crates/ika-types/src/sui/system_inner_v1.rs`) | `DWalletCoordinatorInner` (`contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move`) |
| `SystemInnerV1` (`crates/ika-types/src/sui/system_inner_v1.rs`) | `SystemInner` (`contracts/ika_system/sources/system/system_inner.move`) |
| `DWalletNetworkEncryptionKey` (`crates/ika-types/src/messages_dwallet_mpc.rs`) | `DWalletNetworkEncryptionKey` (`contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move`) |

BCS is positional and these types carry no version tag, so **their field
order is the wire format** of bytes a deployed package has already
written. Nothing in those bytes identifies the layout that produced them.

## Why this needs a guard at all

A verified read proves *provenance*, never *shape*. The OCS trust chain —
committee BLS → artifacts digest → Merkle inclusion → id binding →
changeset currency — establishes that these bytes are the chain's. Not one
of those gates establishes that the reader's struct still describes them.
A tagged type like `VersionedMPCData` fails closed on an unknown variant;
these cannot, because there is no tag to be unknown.

Two things are already true and are **not** what the guard is for:

- **Decoding is as strict as BCS allows.** Every decode goes through
  `bcs::from_bytes`, which runs the deserializer to `end()` and rejects
  residue. There is no reader-style partial decode anywhere in the repo.
- **Most drift therefore fails loudly.** Each mirror is the last value in
  its byte stream and ends in a fixed-width tail (`extra_fields: Bag` is
  40 bytes; the fieldless `state` enum is one), so a length-changing
  field-add trips `remaining input`, or dies earlier on a strict `bool` or
  an unknown enum variant.

What is left is narrow but real, and it is two things:

1. **A same-total-length reshuffle decodes silently.** Remove a field and
   add one of equal encoded width, or retype `u64` → `u64`, and every byte
   still parses. Nothing anywhere notices.
2. **When it does fail, it fails in the wrong place.** A bare
   `unexpected end of input` raised several fields past the one that
   actually moved sends the reader hunting in the wrong struct — that has
   already cost this repo multiple CI cycles (see
   `dev-docs/learnings/pitfalls.md`, "Sui types & encoding").

## Why the guard is build-time, not runtime

An in-place field-add cannot reach mainnet or testnet: Sui's
compatible-policy upgrade checker rejects datatype layout changes, so
there is no same-version path to chain. Drift arrives one of two ways,
and both pass through this repo:

- a `const VERSION` bump plus `migrate()`, which installs the inner under
  a new dynamic-field key — this is the *intended*, upgrade-legal way a
  layout change ships; or
- a fresh package publish (a localnet, devnet, or testnet redeploy).

A red build is the cheapest possible signal for both.

## The trap the version wrapper is currently not catching

Both outer objects carry a `u64 version` (`VERSION = 2` today in
`coordinator.move` and `system.move`), and `migrate()` exists precisely so
a layout change can ship under a new version. **Rust does not use that
seam.** Both readers do:

```rust
match wrapper.version {
    1 | 2 => { /* decode as ...V1 */ }
```

in `crates/ika-sui-client/src/lib.rs` and
`crates/ika-core/src/sui_connector/verified_reader.rs`. That is an
assertion that versions 1 and 2 share one layout. It happens to be true —
the Move struct is a single unsuffixed declaration and the bump carried no
layout change — but nothing tested it and nothing forces the next bump to
revisit it.

Deliberately **not** fixed by splitting the arm: the two versions really
do share a layout today, so separate types would fabricate a distinction
the bytes do not have. The `VERSION` value is pinned in the manifest
instead, so the next bump fails the build and lands in front of a human.

## The guard, in two halves

Both halves must move together. Either side moving alone is exactly the
drift being guarded against.

- **Move half** — `scripts/check-chain-mirror-layout.sh`, run in CI,
  pinned by `scripts/chain-mirror-layout.txt`. Extracts each Move struct's
  ordered `(name, type)` list, each Rust mirror's ordered field names, and
  each `const VERSION`, and diffs them against the manifest. The manifest
  maps Move field → Rust field **explicitly**, because the names genuinely
  differ in places (`presign_sessions` → `presigns`,
  `pricing_and_fee_manager` → `pricing_and_fee_management`,
  `witnesses_approving_advance_epoch` → `witness_approving_advance_epoch`);
  a name-equality check would be a lie.
- **Rust half** — the golden layout tests beside each mirror, run by CI as
  `cargo test -p ika-types --lib -- layout_is_pinned variant_indices_are_pinned`
  (the second name pins the `DWalletNetworkEncryptionKeyState` variant
  indices, which are part of the same untagged byte stream). Each builds a
  fully-populated value and pins its encoded length and Blake2b digest.
  The struct literal is itself half of this: every field is written out
  with no `..Default::default()`, so an added or removed Rust field fails
  to **compile**. The digest covers what compilation cannot see — a
  reorder or a retype — which is why every field gets a distinct value:
  with zeroes everywhere, swapping two `u64`s would encode identically.

Runtime keeps one thing, and it is diagnosis only:
`ika_types::chain_mirror::decode_chain_mirror` wraps `bcs::from_bytes` at
every leaf decode site. It changes nothing about strictness and names the
Move source plus the layout-drift hypothesis in the error.

## Changing a mirrored struct

All of these move in the same PR:

1. The Move struct and the Rust mirror.
2. The version dispatch: a layout change means versions 1 and 2 no longer
   share a layout, so the `1 | 2 =>` arm must stop claiming they do.
3. The `const VERSION` bump plus `migrate()` that carries old state
   across.
4. The golden tests, both names CI runs:
   `cargo test -p ika-types --lib -- layout_is_pinned variant_indices_are_pinned`.
5. The Residuals section of `dev-docs/specs/ocs-verified-sui-reads.md`.
6. The manifest: `./scripts/check-chain-mirror-layout.sh --write`.

Run `--write` only after a deliberate change, never to turn a red build
green.

## What this does not buy

- **Nothing here authenticates shape at runtime.** A node reading a chain
  whose layout drifted still depends on `bcs::from_bytes` exhaustion to
  notice, and a same-total-length reshuffle still mis-decodes silently.
- **The guards bind this repo's releases only.** They are build-time, so
  they say nothing about a node pointed at a foreign or hand-patched
  package, or a redeploy built from a different source tree.
- **The Move half proves agreement, not correctness.** It proves the Move
  declaration has not moved since a human last checked it against the Rust
  mirror. It cannot prove the mirror was right in the first place — the
  Move and Rust type vocabularies do not correspond mechanically
  (`VecMap<ID, vector<u8>>` vs `VecMap<ObjectID, Vec<u8>>`), so types are
  pinned as text on the Move side and only names and order are tied across.

The only true runtime fix is a version tag inside the Move struct, which
is a Move change plus a protocol version bump. Given that the upgrade
checker already blocks the in-place case, that has not been judged worth
its cost.
