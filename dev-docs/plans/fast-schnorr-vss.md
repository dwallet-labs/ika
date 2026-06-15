# Fast Schnorr (VSS) signing — integration plan

Status: active (2026-06-15) — integrating the VSS Schnorr feature onto
`dev`. Supersedes an earlier integration attempt whose dev merge dropped
the shape-tolerant on-chain decode (see the pitfall below); this plan
keeps that decode load-bearing.

Adds VSS-based Schnorr signing to the dWallet MPC network: Taproot,
EdDSA, and Schnorrkel (Substrate) variants that produce signatures via a
publicly-verifiable-secret-sharing (VSS) presign instead of the existing
additively-homomorphic-encryption (AHE) path. The feature is gated off
until protocol version 4 and, at v4, runs **internal NOA-VSS only** — it
is not yet exposed to end users (the external VSS sign entry points stay
`#[ignore]`d). This document is the contract for the change so a reader
without the original context can extend or debug it safely.

## Why VSS

The AHE Schnorr path encrypts signing shares under the class-groups
threshold key. The VSS path instead distributes shares with a per-curve
PVSS (publicly verifiable secret sharing) scheme keyed by HPKE encryption
keys, which removes a round of class-groups work from the presign and
makes Schnorr presigns cheaper to produce in bulk. The two paths
coexist; a request selects one via its signature algorithm.

## Key material and where it lives

Each validator now publishes, in addition to its class-groups
encryption key, three **per-curve PVSS HPKE keys** (secp256k1, secp256r1,
ristretto plaintext spaces) and one **VSS HPKE key** (curve25519) — all
with UC-secure proofs of knowledge of the matching decryption key. These
are bundled as `ValidatorEncryptionKeysAndProofs`
(`crates/ika-types/src/committee.rs`). One curve25519 VSS HPKE key serves
every VSS signing curve; the three PVSS keys serve the network-DKG /
reconfiguration threshold-encryption sub-protocol.

The VSS HPKE proofs are verified **once, at `Committee` construction**
(`verify_vss_hpke_keys_at_committee_construction`), not per presign
session. Only validators whose proof verifies are admitted to subsequent
VSS presign / sign sessions; a single malformed submission excludes only
that one party.

### On-chain vs off-chain shape — load-bearing

The Move field `MPCDataV1::mpc_data_bytes` can carry **either** shape:

- the **bare** `ClassGroupsEncryptionKeyAndProof` (the mainnet-v1.1.8
  shape — class-groups key only), or
- the **full** `ValidatorEncryptionKeysAndProofs` bundle.

The `become-candidate` / `set-next-epoch-mpc-data` CLI publishes the full
bundle **by default**; the bare shape is published only under
`--legacy-class-groups-only`. The same bundle is also broadcast off-chain
(consensus-signed announcement + P2P blob fetch) and overlaid onto the
`Committee` by the off-chain validator-metadata pipeline.

**Every on-chain read of validator key material MUST be shape-tolerant.**
Use `decode_validator_encryption_keys` (`crates/ika-types/src/committee.rs`),
which accepts either shape — BCS's trailing-byte rejection means a bundle
never silently parses as the bare shape. The committee-construction sites
that read the chain are:

- `crates/ika-core/src/sui_connector/sui_syncer.rs::new_committee`
- `crates/ika-types/src/sui/epoch_start_system.rs` (both
  `get_ika_committee` and `get_ika_committee_with_network_metadata`)

Each decodes the bytes, always populates `class_groups_public_keys_and_proofs`
(both shapes carry it), and populates the per-curve PVSS maps and the VSS
HPKE map only when the bundle shape is present (`Some`). A bare-shape
validator still contributes its class-groups key — it is never dropped.

> Pitfall: a strict `bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>`
> with no fallback at these sites silently drops every validator that
> published the (default) bundle shape from the load-bearing
> `class_groups_public_keys_and_proofs` map — the swarm config publishes
> bare, so no test catches it. Keep the shape-tolerant decode.

## Version axes

Two independent versions move at this feature:

- **Protocol version** (governance, capability vote at an epoch
  boundary): `fast_schnorr_supported` flips on at v4 (internal NOA-VSS
  only); `schnorr_presign_third_round_delay` is set at v4. See
  `crates/ika-protocol-config/src/lib.rs`.
- **Network-key version** (per key): the VSS shamir cache derives only
  from a **V3** network-key output. A pre-existing key is V2 until its
  first v4 reconfiguration, so there is a one-epoch-per-key transition
  window after v4 activation; a fresh v4 genesis never hits it.

## Integration points

- **Types**: `ValidatorEncryptionKeysAndProofs` +
  `VssHpkeEncryptionKeyAndProof` + the shape-tolerant
  `decode_validator_encryption_keys` and `DecodedValidatorEncryptionKeys`
  (`ika-types`); the VSS protocol variants and the `MPCDataV1.mpc_data_bytes`
  reshape (`dwallet-mpc-types`); VSS HPKE keypair derivation from the
  validator root seed (`dwallet-classgroups-types`, `dwallet-rng`).
- **`Committee::new`** gains a `vss_hpke_public_keys_and_proofs` argument
  (between the ristretto PVSS map and the thresholds) and verifies the
  proofs at construction.
- **Cryptographic computations** (`crates/ika-core/src/dwallet_mpc/crytographic_computation/`):
  VSS presign + sign for each curve in `sign.rs` / `presign.rs` /
  `mpc_computations.rs`; the request/round dispatch in
  `protocol_cryptographic_data.rs`.
- **Wiring**: VSS request classification in `request_protocol_data.rs`
  and `dwallet_session_request.rs`; pool sizing + serving in
  `mpc_manager.rs`; the sign-input gate that waits on the VSS shamir
  cache in `mpc_session/input.rs`; the centralized (user-side) VSS sign
  in `dwallet-mpc-centralized-party`.
- **CLI**: `crates/ika/src/validator_commands.rs` publishes the full
  bundle by default.

## Testing

- Integration tests (`crates/ika-core/src/dwallet_mpc/integration_tests/`)
  exercise network DKG + reconfiguration and the VSS internal-presign /
  sign path across curves. Note the network-key public-data
  instantiation is split into a dkg variant and a reconfiguration variant
  behind the `spawn_network_encryption_key_public_data_instantiation`
  dispatcher; test helpers must drive the dispatcher, not the removed
  single-shape entry point.
- `cargo test -p ika-protocol-config` snapshot tests pin the v4 flag set;
  regenerate the `version_4` snapshots when the flag set changes.
- The bundle-on-chain decode path has no end-to-end test because the
  swarm config publishes the bare shape; the decoder itself is covered by
  the round-trip tests in `dwallet-classgroups-types` and the off-chain
  assembly round-trip in `validator_metadata`.
