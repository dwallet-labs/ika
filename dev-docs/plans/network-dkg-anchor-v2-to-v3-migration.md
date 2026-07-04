# Making the V3 network DKG output canonical (within v4 off-chain)

Status: active — implementation complete and validated end-to-end (2026-06-28),
PR #1758 (into `dev`, ready for review); flip to `landed` on merge.
Consensus-critical. Builds on the in-memory V3 reconstruction (`013cb1b75f`).
The durable behavioral contract — the `NetworkDkgOutput` item's one-time
pre-V3 -> V3 migration (from a V2 anchor, or from the deployed keys' V1 anchor)
and the adoption tolerance — now lives in
`dev-docs/specs/handoff.md`; this plan is the intent/sequencing record.

## What this is

Each network encryption key carries a `VersionedNetworkDkgOutput` (the
`network_dkg_output` field of `NetworkEncryptionKeyPublicData`,
`crates/dwallet-mpc-types/src/dwallet_mpc.rs:111`):

- **V2** — the backward-compatible `decentralized_party::dkg::PublicOutputCore`.
- The deployed mainnet/testnet keys carry a **V1** anchor on chain (raw
  `class_groups::dkg::PublicOutput`, written by a pre-1.1.8 binary and never
  rewritten — reconfiguration writes a separate field). Their reconfiguration
  outputs are V2. The v3 reconfiguration input builder reads (V1 anchor,
  V2 reconfiguration output) every epoch, and the main (v4) builder accepts the
  same shape for the deployed keys' first v4 reconfigurations (a V1 arm that
  decodes the anchor directly as the raw class-groups DKG output).
- **V3** — the full `decentralized_party::dkg::PublicOutput` = the V2 core plus a
  trailing `threshold_encryption_to_sharing_output`, produced only by the
  threshold-encryption-to-sharing sub-protocol that backward-compatible
  reconfiguration predates.

A pure, RNG-free helper reconstructs V3 from (V1 or V2 DKG output, a full V3
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
`reconstructed_full_network_dkg_output = Some(V3)` (i.e. stored DKG output is V1
or V2 and the cert-pinned reconfiguration output is V3), persist that V3 once via the
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

### 3. Tolerate the one-epoch DKG-digest migration in adopt

Within the flip epoch, after the mirror flips, a later adopt tick reads the
overlay as V3 while the prior cert still pins V2. `adopt_cert_verified_keys`
(reconfigured branch) mirrors its existing reconfiguration-digest handling onto
the DKG digest: when the overlay DKG digest no longer matches the prior cert but
the key is **already adopted**, that is the expected one-epoch defer — keep the
adopted value (debug), do not drop the key; only an **unadopted** key
contradicting the cert warns. Softening the already-adopted case is safe because
the output-quorum byte-equality tally remains the guard against a genuinely
divergent output, and a wrong V3 would require either a cert-mismatching
reconfiguration output (separately checked at the same site) or a
non-deterministic reconstruct (impossible — it is a pure function).

(The design considered a stricter "digest-gated dual-accept" that re-derives the
prior cert's V2 digest from the retained `mpc_artifact_blobs` blob; the shipped
tolerance is simpler, consistent with the reconfiguration-digest handling, and
relies on the output-quorum tally for the residual guarantee.)

## Per-consumer summary

1. **Adopt** (`mpc_manager.rs`): tolerate the one-epoch V2->V3 DKG-digest move
   for an already-adopted key (keep its value, debug not warn), mirroring the
   reconfiguration-digest handling; the raw-bytes comparison is unchanged.
2. **Handoff digest** (`validator_metadata.rs`): unchanged code — it reads the
   mirror, which the flip writes V3. (Stale "stable across epochs" comment
   updated.)
3. **Perpetual store**: the flip reuses `cache_network_dkg_output`; no new table.
4. **Session ids** (`mpc_manager.rs:1443`/`:1518`): re-keyed onto `NetworkKeyId`.
5. **Joiner** (`ika-node/src/lib.rs`): unchanged — fetches V3 by the cert-pinned
   digest once the V3 blob is persisted (piece 1).
6. **Syncer gate** (`sui_syncer.rs`): unchanged (presence-only).
7. **Observability**: `ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version`
   (`IntGauge`) is set at each off-chain instantiation to the version mirrored
   into the handoff — 2 before the migration, 3 after — so the migration is
   observable (and asserted by the v118 tests).

No `ika-protocol-config` change.

## Why no transition point wedges

- **Session ids:** re-keyed onto the flip-invariant `NetworkKeyId` — timing of
  the field flip is irrelevant.
- **Handoff attestation:** the flip is latched at instantiation (epoch entry)
  from the cert-pinned reconfiguration output, uniform committee-wide; by
  `EndOfPublish` every validator's mirror is V3, so all emit the same digest.
- **Cross-epoch adopt:** the already-adopted tolerance bridges the one flip epoch
  (the key keeps its adopted value while its overlay DKG digest moves past the
  prior V2 cert); the output-quorum tally guards correctness.
- **Joiner:** the persisted V3 blob lets a peer serve bytes hashing to the
  cert-pinned V3 digest.

## Open / out of scope

- Pruning the retained V2 output, dropping the per-epoch reconfiguration-blob
  dependency for instantiation, and deleting the backward-compatible V2 paths
  are a separate far-future effort once every deployed key is V3-anchored.

## Scope & tests

- **Crates:** `ika-core` (`mpc_manager.rs` — flip trigger at instantiation,
  adopt tolerance, session-id re-key; `dwallet_mpc_metrics.rs` — the
  canonical-version gauge; `validator_metadata.rs` — comment;
  `authority_per_epoch_store.rs`/`authority_perpetual_tables.rs` — reused),
  `dwallet-mpc-types` (`reconstructed_full_network_dkg_output` field +
  `VersionedNetworkDkgOutput::version()`), `ika-upgrade-test` (metrics scrape +
  scenario step + the v118/v118_churn assertions). No `ika-protocol-config`;
  `ika-node` joiner path verify-only.
- **Tests (all green):**
  - Unit/integration: `reconstruct_full_network_dkg_output_gating` (the version
    gate); `already_adopted_key_survives_dkg_output_migration` (the adopt
    tolerance); `internal_presign` (validates the session-id re-key); the
    mainnet-v1.1.8 backward-compat suite incl. `test_v2_to_v3_reconfiguration_migration`.
  - End-to-end on CI: the **v118 upgrade rehearsal** (literal mainnet-v1.1.8 ->
    current build, v3->v4) and **v118 churn** (same, with a mirrored joiner added
    to a 5-member committee) — both assert the canonical DKG-output version
    reaches 3 across the whole committee after the flip (`got=3 expected=3` in the
    run logs; the churn run proves it for the cert-bootstrapped joiner).
