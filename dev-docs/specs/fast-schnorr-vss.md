# Fast Schnorr (VSS) signing

Status: gated behind `ProtocolConfig::fast_schnorr_supported` (on at protocol
v4). At v4 it is reachable **only** on the internal network-owned-address (NOA)
sign path; the external (user-dWallet-driven) VSS sign path is implemented but
`#[ignore]`d and must not decode externally yet. Pairs with
[`validator-mpc-data-announcements.md`](validator-mpc-data-announcements.md)
(how the key material moves) and
[`cross-binary-upgrade.md`](cross-binary-upgrade.md) (the version boundary).

## What it adds

Three publicly-verifiable-secret-sharing (VSS) Schnorr signature algorithms,
each sharing the curve and base crypto of its non-VSS sibling but using the
VSS protocol and a per-curve VSS Shamir cache:

- `TaprootVSS` — secp256k1
- `EdDSAVSS` — curve25519 (ed25519)
- `SchnorrkelVSS` — ristretto

Each VSS algorithm uses the same hash context as its non-VSS sibling
(`DWalletSignatureAlgorithm::hash_context`).

## Curve / algorithm numbering

The on-chain `(curve, signature_algorithm)` pair maps to a
`DWalletSignatureAlgorithm` in `try_into_signature_algorithm`
(`dwallet-mpc-types/src/mpc_protocol_configuration.rs`):

| curve | algorithm index | algorithm |
|-------|-----------------|-----------|
| 0 Secp256k1  | 0 / 1 / 2 | ECDSASecp256k1 / Taproot / **TaprootVSS** |
| 1 Secp256r1  | 0         | ECDSASecp256r1 |
| 2 Curve25519 | 0 / 1     | EdDSA / **EdDSAVSS** |
| 3 Ristretto  | 0 / 1     | Schnorrkel / **SchnorrkelVSS** |

This map governs **external reachability** — what a user request may name.
`SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES` is the source of
truth; a `(curve, algorithm)` absent from it does not decode externally (a unit
test asserts `EdDSAVSS` does not decode externally). At v4 the only reachable
VSS path is internal NOA-VSS.

## Key material — the version-3 bundle + per-curve PVSS

- At `network_encryption_key_version == 3` (protocol v4) every committee member
  publishes the version-3 bundle, `ValidatorEncryptionKeysAndProofs` = the
  class-groups CRT key + three per-curve PVSS HPKE keys. Below v4 it publishes
  the bare `ClassGroupsEncryptionKeyAndProof` (mainnet-v1.1.8 shape).
- The VSS HPKE keypair is **deterministic from the validator root seed**: the
  published public key (`ValidatorMPCSecrets::from_seed`) and the orchestrator's
  secret (`vss_hpke_secret_key_from_seed`) both derive from the same
  domain-separated stream, `root_seed.vss_hpke_secret_key_rng()`. The published
  public must be the public counterpart of the orchestrator's secret, or the
  dealt shares cannot be decrypted (covered by a determinism unit test in
  `dwallet-classgroups-types`).
- The per-curve VSS Shamir cache (`VssShamirCachePerKey` — `first_` /
  `second_secret_key_polynomial_commitments` per curve) derives **only from a
  version-3 network-key DKG output**. A pre-version-3 key has no VSS cache.

## Transport — how PVSS reaches the network DKG

On-chain carries only the bare class-groups shape (intentional, for
mainnet-v1.1.8 decode compatibility); the per-curve PVSS and the VSS HPKE key
travel **off-chain** via the validator-mpc-data-announcements pipeline. They are
delivered through the current/next-epoch off-chain key channels into the MPC
manager and assembled under the consensus-ordered freeze gate (see that spec for
the freeze decision and next-committee assembly). The genesis (first-epoch)
committee is fed via the dedicated current-epoch delivery path that assembles
against the active committee directly.

## Sign / presign flow

- VSS presigns are always tagged `VersionedPresignOutput::V3`. The global-presign
  pool wraps an internal NOA presign as V3 for an is-VSS algorithm at the
  pool → sign-request seam (`mpc_manager.rs`).
- The validator sign path decodes the V3 VSS presign (`decode_vss_presign_v3`,
  shared by `decode_schnorr_vss_dkg_and_presign` and the combined
  DKG-and-sign builders) and reads the presign private output keyed by
  `vss_public_presign_identity(signature_algorithm, presign)` — the same
  `(session_id, blending_index)` the public- and private-input builders use.
- Decoders are version-strict: the VSS decoders **require** V3; the AHE/ECDSA
  decoders **reject** V3. A non-V3 presign on a VSS path is rejected (fail
  closed).
- Per-curve dispatch is consistent across the protocol public parameters, the
  VSS Shamir cache field, signature parsing (`TaprootVSS → TaprootSignature`,
  `EdDSAVSS → EdDSASignature`, `SchnorrkelVSS → SchnorrkelSignature`), and the
  on-chain curve/algorithm map.
- The centralized party bails on a V3 presign ("not consumable from the
  centralized party") — correct for the internal NOA path, where the
  centralized party does not participate. The external VSS sign path (which
  would feed the centralized party) is `#[ignore]`d.

## Decision rules

- `fast_schnorr_supported` is the master gate (on at protocol v4).
- The is-VSS request gate rejects a VSS request **only** when
  `fast_schnorr_supported` is off; it never parks or rejects an ordinary
  (non-VSS) sign.
- Internal NOA-VSS is reachable at v4; external user-driven VSS sign is not yet
  enabled.

## Invariants

- A VSS presign is always V3; a non-V3 presign on a VSS path is rejected.
- The published VSS HPKE public key equals the public counterpart of the
  orchestrator's secret (same seed-derived RNG stream).
- VSS key material exists only for a version-3 key; the sign path needs the
  per-curve VSS Shamir cache, which is absent pre-version-3.

## Tests

- Reachable (run in CI):
  `network_owned_address_sign_{taproot,eddsa,schnorrkel_substrate}_vss` — the
  internal NOA VSS sign flow, green in release.
- Gated off: `test_external_vss_sign_*` — the external user-driven path, kept
  `#[ignore]`d until it is enabled.
