# Making the V3 network DKG output canonical (within v4 off-chain)

Status: active — 2026-06-21, design agreed (v4 + epoch-alignment),
implementation starting, no PR yet. Consensus-critical. The in-memory V3
reconstruction this builds on landed in `013cb1b75f`.

## What this is

Each network encryption key carries a `VersionedNetworkDkgOutput` (the
`network_dkg_output` field of `NetworkEncryptionKeyPublicData`,
`crates/dwallet-mpc-types/src/dwallet_mpc.rs:111`):

- **V2** — the backward-compatible `decentralized_party::dkg::PublicOutputCore`.
  The deployed mainnet/testnet key has a V2 anchor.
- **V3** — the full `decentralized_party::dkg::PublicOutput` = the V2 core plus a
  trailing `threshold_encryption_to_sharing_output`, produced only by the
  threshold-encryption-to-sharing sub-protocol that backward-compatible
  reconfiguration predates.

A pure, RNG-free helper reconstructs V3 from (V2 DKG output, a full V3
reconfiguration output): `reconstruct_full_network_dkg_output`
(`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs:721`),
already called in `build_network_encryption_key_public_data` and stored in the
in-memory field `NetworkEncryptionKeyPublicData::reconstructed_full_network_dkg_output`
(committed `013cb1b75f`).

**Goal:** make the V3 output the *canonical* network DKG output — what the
cross-epoch handoff attests, what `adopt_cert_verified_keys` matches, and what
joiners install.

## Framing: within v4, not a new protocol version

The handoff and `adopt_cert_verified_keys` are gated on
`off_chain_validator_metadata_enabled()` (v4), which is **not live** on any
deployed network, so v4 handoff behavior carries no back-compat constraint. The
canonical-V3 behavior rides that same gate — no new protocol version, no
`MAX_PROTOCOL_VERSION` bump.

### Why the V2 anchor cannot simply stay V2

The handoff digest, the overlay/instantiation source, and the adopt comparison
all resolve through the **same** perpetual `key_id -> digest` mirror
(`network_dkg_output_digests_by_key`, read by `get_network_dkg_output_digests`,
`authority_per_epoch_store.rs:2545`; resolved into the overlay by
`fetch_network_key_data_with_off_chain_blobs`, `validator_metadata.rs:1422`).
And a joiner caches the cert-pinned blob as `network_dkg_output` via
`cache_network_dkg_output` (`crates/ika-node/src/lib.rs:2966`) — the same write
path continuing nodes use. So whatever the cert pins becomes `network_dkg_output`
network-wide: if the cert pins V3, `network_dkg_output` is V3 everywhere, and so
are the session ids hashed from it (`mpc_manager.rs:1443`/`:1518`). There is no
way to make the cert V3 while keeping the field V2.

### Why the flip must be epoch-aligned, and how

`instantiate_adopted_network_keys` re-instantiates whenever the overlay's
DKG/reconfiguration bytes move (`mpc_manager.rs:2198-2225`), not once per epoch.
So a naive "flip when the V3 reconstruction appears" trigger would land
mid-epoch at wall-clock-divergent times across validators, diverging both the
session identifiers and the handoff attestation. The flip must therefore be
driven by a signal that is identical across validators for a whole epoch.

That signal is the **cert-pinned reconfiguration output**: `adopt_cert_verified_keys`
enforces that a key's adopted reconfiguration output matches the prior epoch's
certified reconfiguration digest (`mpc_manager.rs:897`), so at any epoch every
validator instantiates from the same reconfiguration output. The flip decision
("present V3") is therefore made **once, at instantiation (epoch entry), from the
cert-pinned overlay** — V2 stored DKG output plus a V3 reconfiguration output —
and is uniform across the committee for the epoch.

## Design

Three coordinated pieces, all under `off_chain_validator_metadata_enabled()`:

### 1. Flip the persisted mirror at instantiation (epoch entry)

When a key is instantiated with off-chain on and the result carries a
`reconstructed_full_network_dkg_output = Some(V3)` (i.e. stored DKG output is V2
and the cert-pinned reconfiguration output is V3), persist that V3 once via the
existing `cache_network_dkg_output(key_id, v3_bytes)` write path. That single
call:

- adds the V3 blob to the content-addressed `mpc_artifact_blobs` store (insert
  guarded by `Blake2b256(bytes)==digest`, `authority_perpetual_tables.rs:184`),
  so peers — and joiners — can fetch V3 bytes under the cert-pinned V3 digest;
- flips the single-valued `network_dkg_output_digests_by_key` mirror to the V3
  digest (`authority_perpetual_tables.rs:53`), so `get_network_dkg_output_digests`
  (the handoff source) and the overlay both resolve V3 from the next epoch on.

It is naturally one-shot: once the overlay resolves V3, the stored DKG output is
V3, `reconstruct` returns `None`, and the trigger no longer fires. The on-chain
V2 output and the content-addressed V2 blob are never destroyed (zero-data-loss).
Epoch-alignment holds because the trigger is the cert-pinned reconfiguration
output, identical committee-wide; the handoff digest read at `EndOfPublish` is V3
on every validator because all instantiated (and flipped) at epoch entry, a whole
epoch earlier.

### 2. Re-key session identifiers onto `NetworkKeyId`

Replace the `network_dkg_output().as_bytes()` preimage at `mpc_manager.rs:1443`
(internal-presign) and `:1518` (network-owned-address sign) with the
`NetworkKeyId` bytes (the curve25519 NOA ed25519 pubkey, invariant across
reconfiguration AND the V2→V3 reconstruction). This removes the flipping bytes
from the session-id preimage, so the field change is invisible to session
identity regardless of instantiation timing. Fallback for an unmapped key (no
`NetworkKeyId` registered yet): keep the current `network_dkg_output` bytes —
uniform across validators because the mapping is seeded/registered identically.

### 3. Digest-gated dual-accept in adopt

Within the flip epoch, after the mirror flips, a later adopt tick reads the
overlay as V3 while the prior cert still pins V2. Make the reconfigured-branch
comparison (`mpc_manager.rs:897`) accept when **either** the local canonical
digest matches the prior cert (steady state) **or** the local digest differs but
the retained V2 output (resolved by the prior cert's V2 digest from
`mpc_artifact_blobs`, which we never delete) matches the prior cert — proving
possession of exactly the V2 the prior committee certified, now migrated to V3.
This keeps adoption stable across the flip without a spurious mismatch, and it
cannot mask a genuine steady-state V3-vs-V3 mismatch (which fails both legs).

## Per-consumer summary

1. **Adopt** (`mpc_manager.rs:808-905`): digest-gated dual-accept; no change to
   the raw-bytes comparison itself.
2. **Handoff digest** (`validator_metadata.rs:866`): unchanged code — it reads
   the mirror, which the flip writes V3. Update the stale `:873` comment.
3. **Perpetual store**: the flip reuses `cache_network_dkg_output`; no new table.
4. **Session ids** (`mpc_manager.rs:1443`/`:1518`): re-keyed onto `NetworkKeyId`.
5. **Joiner** (`ika-node/src/lib.rs:2966`): unchanged — fetches V3 by the
   cert-pinned digest once the V3 blob is persisted (piece 1).
6. **Syncer gate** (`sui_syncer.rs:859-863`): unchanged (presence-only).

No `ika-protocol-config` change.

## Why no transition point wedges

- **Session ids:** re-keyed onto the flip-invariant `NetworkKeyId` — timing of
  the field flip is irrelevant.
- **Handoff attestation:** the flip is latched at instantiation (epoch entry)
  from the cert-pinned reconfiguration output, uniform committee-wide; by
  `EndOfPublish` every validator's mirror is V3, so all emit the same digest.
- **Cross-epoch adopt:** the digest-gated dual-accept bridges the one flip epoch
  via possession of the retained V2 output.
- **Joiner:** the persisted V3 blob lets a peer serve bytes hashing to the
  cert-pinned V3 digest.

## Open / out of scope

- Pruning the retained V2 output, dropping the per-epoch reconfiguration-blob
  dependency for instantiation, and deleting the backward-compatible V2 paths
  are a separate far-future effort once every deployed key is V3-anchored.

## Scope & tests

- **Crates:** `ika-core` only — `mpc_manager.rs` (flip trigger at instantiation,
  dual-accept, session-id re-key), `validator_metadata.rs` (comment),
  `authority_per_epoch_store.rs`/`authority_perpetual_tables.rs` (reused). No
  `ika-protocol-config`, `ika-node` verify-only.
- **Tests:**
  - Unit: the session-id preimage uses `NetworkKeyId` when mapped and falls back
    otherwise; the dual-accept leg-2 matches a retained V2 output against a V2
    prior cert.
  - Cluster/sim: the **v3→v4 upgrade** path is the one that exercises case A — a
    V2 key read from chain, v4 reconfigurations flipping it to V3, the dual-accept
    at the flip epoch, and a **joiner** installing the V3 at/after the flip.
    Genesis-v4 clusters exercise only case B (already V3).
