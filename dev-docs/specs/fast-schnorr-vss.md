# Fast Schnorr (VSS) signing

Status: `ProtocolConfig::fast_schnorr_supported` was turned on in the v4 arm
and `MIN_PROTOCOL_VERSION` is now 7, so it is ON at every supported version.
Nothing reads it any more: the Rust-side reject branch and the conditional
arm of the internal presign pool list were both unreachable and have been
removed, so the VSS algorithms are unconditional. The flag field itself stays
because the flag set is BCS-serialized into the `ProtocolConfig` digest that
rides `AuthorityCapabilitiesV1` through consensus. The feature is reachable
**only** on the internal
network-owned-address (NOA) sign path; the external (user-dWallet-driven) VSS
sign path is implemented but `#[ignore]`d and must not decode externally yet.
That external limit is a code state, not a protocol-version gate. Pairs with
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
test asserts `EdDSAVSS` does not decode externally). The only reachable VSS
path is internal NOA-VSS.

## Key material — the version-3 bundle + per-curve PVSS

**Two different "version 3"s meet in this section; they are separate axes
that happen to coincide.** "Version-3" on its own always means the network
key's CRYPTO version (`ProtocolConfig::network_encryption_key_version`,
raised to 3 at protocol v4) — the bump that introduced
`ValidatorEncryptionKeysAndProofs` and the `decentralized_party` protocols.
A bare `V1`…`V4` always means the BCS wire tag on
`VersionedNetworkDkgOutput` / `VersionedDecryptionKeyReconfigurationOutput`.
Crypto-version-3 outputs were first written with the V3 tag (pre-aggregation,
now undecodable) and are always V4 today, so "a crypto-version-3 key" and "a
V4-tagged output" select the same keys by different routes.

- Every committee member publishes the version-3 bundle OFF-CHAIN,
  `ValidatorEncryptionKeysAndProofs` = the class-groups CRT key + three
  per-curve PVSS HPKE keys. This is not an either/or with the bare
  `ClassGroupsEncryptionKeyAndProof` (mainnet-v1.1.8 shape): that bare shape
  is what is published ON CHAIN, always, while the full bundle always goes
  off-chain. The two coexist by destination, not by version.
  (`ProtocolConfig::network_encryption_key_version` is assigned per version
  but has no getter and no consumer anywhere in the tree — nothing branches
  on it. Do not write code that reads it without first giving it a reader.)
- The VSS HPKE keypair is **deterministic from the validator root seed**: the
  published public key (`ValidatorMPCSecrets::from_seed`) and the orchestrator's
  secret (`vss_hpke_secret_key_from_seed`) both derive from the same
  domain-separated stream, `root_seed.vss_hpke_secret_key_rng()`. The published
  public must be the public counterpart of the orchestrator's secret, or the
  dealt shares cannot be decrypted (covered by a determinism unit test in
  `dwallet-classgroups-types`).
- The per-curve VSS Shamir cache (`VssShamirCachePerKey` — `first_` /
  `second_secret_key_polynomial_commitments` per curve) derives **only from a
  crypto-version-3 network key**. A pre-version-3 key has no VSS cache.
  The full-shape output is the aggregated (V4) wire tag — the only one the
  current crypto crates can decode (the pre-aggregation V3 type was removed
  from inkrypto; a V3-tagged output is a hard derivation failure, and such
  state must have migrated to V4 before this binary runs). The cache
  derivation runs on the aggregated form, so recovering a Shamir share
  costs a single class-group decryption per curve-part.

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
- Decoders are version-strict: the VSS decoders **require** V3; the non-VSS
  (AHE/ECDSA) decoders **reject** V3. A non-V3 presign on a VSS path is
  rejected (fail closed).
- Per-curve dispatch is consistent across the protocol public parameters, the
  VSS Shamir cache field, signature parsing (`TaprootVSS → TaprootSignature`,
  `EdDSAVSS → EdDSASignature`, `SchnorrkelVSS → SchnorrkelSignature`), and the
  on-chain curve/algorithm map.
- The centralized party bails on a V3 presign ("not consumable from the
  centralized party") — correct for the internal NOA path, where the
  centralized party does not participate. The external VSS sign path (which
  would feed the centralized party) is `#[ignore]`d.

## Decision rules

- `fast_schnorr_supported` was the master gate; it is on at every supported
  version, so the VSS algorithms are now unconditional and no code reads the
  flag. The Rust-side is-VSS request rejection is gone — with the flag on
  everywhere it could never fire, and it never parked or rejected an ordinary
  (non-VSS) sign. On-chain `validate_curve_and_signature_algorithm` remains
  the enforcement for external requests.
- Internal NOA-VSS is reachable; external user-driven VSS sign is not yet
  enabled.
- **Epoch-entry parking of VSS presign top-ups.** Internal presign top-up
  batches fire as soon as the network key is installed (fast, from the handoff
  data), which is typically *before* the epoch's consensus-frozen off-chain
  validator key set has been ingested — so the VSS pools' presign input
  construction fails with the not-ready error class
  (`NetworkDecryptionKeyNotReady` / `WaitingForNetworkKey`). Such a request is
  **parked** (`internal_presign_requests_pending_for_network_key_data` on the
  MPC manager), retried once per service iteration, and activated once the key
  data lands — never terminally failed (terminal failure on every validator
  starved the VSS pools after each epoch transition until the stale-batch
  expiry). The session identifier and sequence number are consumed at
  instantiation regardless of parking, so identifier derivation and the
  instantiated/completed batch counters stay committee-uniform — parking is
  local participation deferral, invisible to the top-up guard and the
  stale-batch expiry. Any other input-construction error stays terminal.
- **VSS Shamir-cache outcome tri-state (epoch-tagged).** The per-key cache
  map stores the derivation OUTCOME, not only successes: `Derived` (the
  three-curve cache), `NotApplicable` (every stored output for the key is
  V1/V2-tagged — a pre-crypto-version-3 key; note a V3 tag lands in `Failed`,
  not here), or `Failed` (a real deserialization/derivation failure,
  logged once at insertion). Every variant carries the epoch of the key data
  it was derived from, and the accessor treats an epoch mismatch — terminal
  variants INCLUDED — exactly like a missing entry (the not-ready class,
  park and retry): an entry derived from a superseded key view is
  "re-derivation in flight", not an answer about the current key data.
  Without the epoch tag on the terminal variants, the boundary window where
  the first ingest carries the pre-V3 key view would report terminal
  `NotApplicable` for the whole multi-minute V3 re-derivation, dropping that
  validator out of every VSS sign while its peers sign. A CURRENT-epoch
  terminal entry surfaces as `VssShamirCacheUnavailable` — a named, terminal
  error distinct from the not-ready class. The internal-session failure log
  treats it as an expected error class rather than a should-never-happen
  page. On a live network the only route to it is a genuinely failed
  derivation: the other route, a pre-version-3 key, needed the v3→v4
  boundary epoch, which no supported version can reach.
- **Per-pool sequence counters (multi-key epochs).** The internal-presign
  session sequence number, the instantiated/completed guard counters, and the
  stale-batch-instantiated round are keyed per `(NetworkKeyId, curve,
  signature_algorithm)` POOL — not a single counter shared across all keys.
  The key axis is the key's content-derived `NetworkKeyId` (its flip-invariant
  curve25519 NOA public key), which is the SAME identity bound into the session
  identifier, so the counter and the identifier can never diverge onto
  different key axes. A single shared counter would couple every pool's stream:
  because key ADOPTION completes at a different consensus round on different
  validators (adoption is cert-gated, not round-uniform), a key adopted earlier
  on one validator would shift every other pool's sequence numbers, diverging
  the session identifiers (which bind the sequence number). Per-pool counters
  make each pool's ordinal stream start-time-invariant: a late-adopted key
  starts its own pool's stream fresh at 1 whenever it starts, without
  perturbing any other pool.
  **Scope of the guarantee**: start-time invariance is unconditional only
  while a validator's start skew for a pool stays under ONE BATCH LIFECYCLE.
  A validator whose first top-up of a pool happens only after a full batch
  quorum-completed among its peers (a mid-epoch restart that replays committed
  rounds before adoption re-lands, an extremely late install, an epoch entered
  late, a state-synced store) would otherwise begin that pool's ordinals offset
  from its peers' and never converge — instantiating already-completed
  identifiers and contributing nothing to that pool's live sessions for the
  rest of the epoch, with the pool still served by the peers' quorum until more
  than f validators are in that state simultaneously. Convergence past that
  skew is restored by the ordinal heal in
  `dev-docs/specs/internal-presign-pool.md` ("Ordinal-stream convergence"),
  which fast-forwards the counter from the completed sequence numbers carried
  in consensus outputs. The same exposure existed under the old shared counter,
  with every pool coupled to the divergence instead of one.
- **Deferred instantiation for a not-yet-installed key.** The top-up loop
  iterates every ADOPTED key, but installation into `network_keys` completes
  asynchronously per validator. Because the counters and the session identifier
  both key by the `NetworkKeyId`, the loop resolves it ONCE per key before
  touching either — from the installed key data when present, else from the
  pre-instantiation `ObjectID → NetworkKeyId` mapping (seeded deployed keys,
  registration at DKG output processing, background derivation). An adopted
  key ALWAYS resolves: adoption (`adopt_cert_verified_keys`) defers any key
  whose ObjectID has no mapping — on EVERY adoption branch, cert-anchored or
  cert-less — spawning the background derivation and retrying each tick until
  the registration lands. A `None` in the top-up loop is therefore a
  should-never-happen and the loop SKIPS that key for the iteration rather
  than falling back to a divergent identity axis — it does not park or fail
  it. A validator whose key is adopted and resolvable but not yet installed
  builds the request normally (identity from the mapping), consumes the
  sequence number from that pool's counter, and parks the BUILT request on the
  input's not-ready error; the sequence number is consumed regardless, since
  skipping a top-up that peers perform would desynchronize that pool's counter
  and, with it, every subsequent identifier in that pool. Relatedly, the
  NOA-signing-key choice (oldest key by `dkg_at_epoch`) is made over the
  ADOPTED set (not the wall-clock-installed set) and tie-breaks equal
  `dkg_at_epoch` by key id, so every validator picks the same NOA key and
  applies the same pool configs regardless of install timing.

## Invariants

- A VSS presign is always V3; a non-V3 presign on a VSS path is rejected.
- The published VSS HPKE public key equals the public counterpart of the
  orchestrator's secret (same seed-derived RNG stream).
- VSS key material exists only for a crypto-version-3 key; the sign path
  needs the per-curve VSS Shamir cache, which is absent pre-version-3.

## Tests

- Reachable (run in CI):
  `test_network_owned_address_sign_{taproot,eddsa,schnorrkel_substrate}_vss` —
  the internal NOA VSS sign flow, green in release.
- Gated off: `test_external_vss_sign_eddsa` and `test_external_vss_sign_taproot`,
  the external user-driven path, kept `#[ignore]`d until it is enabled. There
  is deliberately no external SchnorrkelVSS test — it is blocked on a harness
  limitation, not on the feature gate, so do not read the pair as a glob over
  all three algorithms.
