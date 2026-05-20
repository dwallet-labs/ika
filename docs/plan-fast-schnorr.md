# Plan: Add Fast Schnorr (VSS Schnorr) Support

## Context

Today every Schnorr-family signature in ika (Taproot on secp256k1, EdDSA on
curve25519, SchnorrkelSubstrate on ristretto) is signed in **AHE-mode** —
the decentralized party's secret key share is held inside threshold
additively-homomorphic encryption (class groups). The cryptography-private
crate at the current pin (`84fa8da`) ships a fully built alternative:
**VSS-Schnorr** ("Fast Schnorr"), where the decentralized party's secret
key share, presign nonces, and partial signatures are Shamir-secret-shared
across validators instead of homomorphically encrypted. The VSS path is
faster (no AHE arithmetic in the hot path) and operationally cleaner.

The `fast-schnorr` branch already (a) bumped cryptography-private to a rev
that exposes the VSS primitives and (b) shipped the PVSS HPKE per-curve
encryption keys (network DKG / Reconfiguration v3) — both prerequisites
for activating VSS-Schnorr. The activation itself was deliberately deferred
(see `docs/plan-bump-crypto-private-to-main.md` §4d). This plan does that
activation.

**Scope:** add a parallel VSS-mode variant alongside each existing AHE
Schnorr variant, end-to-end across Move contracts, ika-protocol-config,
validator MPC stack, dwallet-mpc-centralized-party (user SDK), and the
TypeScript SDK. AHE-mode variants stay for backward compatibility with
already-deployed dWallets. **Fast Schnorr supports DKG-created dWallets
only — never imported keys** (an imported user secret cannot be Shamir-
shared by the network).

## Upstream API (cryptography-private @ `84fa8da`)

The protocol type aliases already exist in `twopc_mpc`:

```rust
// 2pc-mpc/src/lib.rs
twopc_mpc::secp256k1::class_groups::vss::TaprootVSSProtocol             // line 1422
twopc_mpc::curve25519::class_groups::vss::EdDSAVSSProtocol              // line 1266
twopc_mpc::ristretto::class_groups::vss::SchnorrkelSubstrateVSSProtocol // line 1340
```

All three are `crate::vss::schnorr::Protocol<...>` instantiations. They
implement the same generic `twopc_mpc::dkg::Protocol`,
`twopc_mpc::presign::Protocol`, and `twopc_mpc::sign::Protocol` traits
that ika's existing dispatch consumes — so the routing layer just needs
new match arms, not new traits.

**Key shape differences vs AHE-mode:**

- **DKG output type is the same.** `vss::schnorr::Protocol`'s
  `DecentralizedPartyDKGOutput` resolves to the same
  `DKGDecentralizedPartyVersionedOutput<…>` ika already produces for
  AHE-mode (cryptography-private `lib.rs:1102-1107`). Existing dWallet
  DKG outputs can be reused; no new DKG flow.
- **Sign `PublicInput` differs.** Uses
  `crate::schnorr::vss::sign::decentralized_party::PublicInput<…>`
  (cryptography-private `lib.rs:1101`), wrapping the DKG output, the
  VSS `Presign`, a `PartialSignature`, and the protocol public
  parameters.
- **Presign `PrivateOutput` is non-trivial.** For AHE-mode,
  `<P::PresignParty as mpc::Party>::PrivateOutput = ()`. For VSS-mode,
  it's a per-validator structure holding nonce shares + HPKE blobs that
  the sign session **must read back to construct its `PrivateInput`**.
  This is the largest infrastructure gap (see Phase 5 below).
- **Sign `PrivateInput` derivation.** For AHE it's
  `Option<HashMap<PartyID, SecretKeyShareSizedInteger>>` sourced from
  `decrypt_decryption_key_shares`. For VSS it's
  `schnorr::vss::sign::decentralized_party::PrivateInput<…>` derived
  from the validator's own persisted presign `PrivateOutput`.

## Naming

Mirror upstream: add `TaprootVSS`, `EdDSAVSS`, `SchnorrkelSubstrateVSS`
as new variants of `DWalletSignatureAlgorithm`. Each is a sibling of the
existing AHE variant on the same curve.

## Files to modify (critical paths)

### Move contracts

- `contracts/ika_dwallet_2pc_mpc/sources/coordinator_inner.move` —
  register the three new signature-algorithm IDs.
- `contracts/ika_dwallet_2pc_mpc/sources/` — wherever the
  signature-algorithm allow-list for imported keys lives (must NOT
  include the VSS variants).
- Add `is_fast_schnorr_supported` (or version-gate equivalent) check
  in coordinator state machine.

### Rust types & config

- `crates/dwallet-mpc-types/src/dwallet_mpc.rs:201-212` — extend
  `DWalletSignatureAlgorithm` with `TaprootVSS`, `EdDSAVSS`,
  `SchnorrkelSubstrateVSS`.
- `crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs:45-104`
  — register the three new (curve, algorithm) → hash-scheme entries.
  Match hash sets to the AHE-mode siblings (SHA256 / SHA512 / Merlin).
- `crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs:107-114`
  — add VSS variants to `GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_DKG`.
- `crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs:117-124`
  — **explicitly do NOT add** VSS variants to
  `GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_IMPORTED_KEY`.
  Add a comment documenting why (Shamir shares require DKG-generated
  secret).
- `crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs:185-227,
  229-308` — extend `try_into_signature_algorithm` and
  `try_into_hash_scheme` with the new variant decoders.
- `crates/ika-protocol-config/src/lib.rs` — add
  `fast_schnorr_enabled: Option<bool>` (or
  `fast_schnorr_version: Option<u64>`) feature flag. Gate
  request acceptance and dispatch behind it.

### Protocol type aliases

- `crates/ika-types/src/messages_dwallet_mpc.rs:553-558` — add:
  ```rust
  pub type Secp256k1TaprootVSSProtocol = twopc_mpc::secp256k1::class_groups::vss::TaprootVSSProtocol;
  pub type Curve25519EdDSAVSSProtocol = twopc_mpc::curve25519::class_groups::vss::EdDSAVSSProtocol;
  pub type RistrettoSchnorrkelSubstrateVSSProtocol = twopc_mpc::ristretto::class_groups::vss::SchnorrkelSubstrateVSSProtocol;
  ```

### Validator MPC dispatch

- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/presign.rs:36-148`
  — extend `PresignPublicInputByProtocol` and
  `PresignAdvanceRequestByProtocol` enums with three new variants.
  Add corresponding match arms in `try_new`. Reuse
  `schnorr_presign_second_round_delay` round-2 delay.
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/presign.rs:194-280`
  — extend `try_new_v2` with public-input construction for the three
  VSS protocols. The VSS presign `PublicInput` carries protocol
  public parameters (and possibly per-curve PVSS HPKE keys —
  inspect the upstream `vss::schnorr::presign::decentralized_party::PublicInput`
  to confirm the exact field set).
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/sign.rs`
  — mirror the same three new dispatch arms; replace the
  `decryption_key_shares` (AHE) source with VSS `PrivateInput`
  construction from persisted presign private outputs (see Phase 5).
- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs` — `mpc_session.rs`
  — central session dispatcher; per-(curve, algorithm) state HashMaps
  already key on `DWalletSignatureAlgorithm`, so they pick up the
  new variants automatically. Verify the
  `instantiated_internal_presign_sessions` / `completed_internal_presign_sessions`
  paths.

### Centralized party (user-side) SDK

- `crates/dwallet-mpc-centralized-party/src/lib.rs` — add the
  centralized-party VSS Schnorr counterpart functions:
  `advance_centralized_sign_party_vss`, plus DKG-output reuse
  (centralized DKG is identical between AHE and VSS Schnorr).
- `sdk/typescript/src/` — surface the new signature algorithm IDs
  to TS callers; mirror the per-algorithm sign helpers.
- `sdk/ika-wasm/` / `sdk/dwallet-mpc-wasm/` — re-export the new
  centralized-party functions through WASM if/when used in browser
  contexts.

## Phased work

### Phase 1 — Move contracts: register VSS signature-algorithm IDs

Pick three contiguous IDs starting from the next free number after the
existing five. Document the imported-key exclusion at the schema level
(coordinator_inner.move). Add ID-to-name mappings in any read-side helper
modules. Gate behind a protocol-version constant.

### Phase 2 — Rust types & config

Extend `DWalletSignatureAlgorithm`, the config maps, and the protocol
flag. Add the protocol-version gate field
(`fast_schnorr_version: Option<u64>`) to `ProtocolConfig`. Ship a unit
test asserting:

- New variants present in `GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_DKG`.
- New variants **absent** from `GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_IMPORTED_KEY`.
- Round-trip `try_into_signature_algorithm(curve, algo)` works.

Reuse the existing test pattern at `mpc_protocol_configuration.rs:310-425`.

### Phase 3 — Protocol type aliases

Add the three `…VSSProtocol` type aliases in
`crates/ika-types/src/messages_dwallet_mpc.rs`. No logic — just type
re-exports.

### Phase 4 — Presign dispatch

Extend `PresignPublicInputByProtocol`, `PresignAdvanceRequestByProtocol`,
and the `try_new` / `try_new_v2` constructors with three new arms. Build
each VSS-mode `PublicInput` from the same per-curve protocol public
parameters used today by the AHE-mode sibling. Verify that the existing
`schnorr_presign_second_round_delay` config knob applies to the VSS
presign's round-2 delay (read upstream `vss::schnorr::presign` to confirm
round count).

**Verify field set:** open the upstream
`2pc-mpc/src/schnorr/vss/presign.rs` (in the pinned cryptography-private
checkout) and inspect `decentralized_party::PublicInput` to confirm
exactly which fields it carries (protocol public parameters, DKG
output, PVSS HPKE keys?).

### Phase 5 — **Presign `PrivateOutput` persistence** (the critical infrastructure)

Per `docs/plan-bump-crypto-private-to-main.md` §4d, AHE-mode presign
has `PresignParty::PrivateOutput = ()` so there's nothing to store. VSS
presign output is non-trivial (per-validator nonce shares + HPKE blobs)
and the corresponding sign session needs each validator's own
`PrivateOutput`. Presign and sign are separate consensus sessions
potentially separated in time — this is **session-spanning state ika
does not track today**.

Design choice: keyed by `(presign_id, validator_id)`, persisted in the
validator's local store (NOT in consensus — each validator only knows
its own `PrivateOutput`).

Add:

- A `presign_private_outputs` table to the per-epoch local store
  (`crates/ika-core/src/authority/authority_per_epoch_store.rs` or
  the dwallet-mpc service local DB — confirm location during impl).
- Write hook at presign-finalize:
  `(presign_id, my_validator_id) → bcs(PrivateOutput)`.
- Read hook at sign-start: load the row for this validator, deserialize,
  use it to construct the sign `PrivateInput`.
- Pruning policy: drop after the corresponding sign session finalizes,
  or on epoch boundary (whichever comes first), bounded TTL fallback.
- Failure handling: if the row is missing at sign time (e.g., disk loss
  + state restore), surface as a soft-fail that excludes this validator
  from the sign quorum, **not** a hard error.

This is also where the AHE-mode arms can stop short — the storage path
is VSS-only.

**Existing seam to use:** Phase 4 of the bump plan already documents
that the generic helper signature
`Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>`
abstracts AHE-vs-VSS at the type level. Only the *source* of the value
changes per protocol. Build a small enum:

```rust
enum SignPrivateInputSource {
    AHE,                    // load decryption_key_shares as today
    VSS { presign_id: …},   // load from presign_private_outputs[(presign_id, me)]
}
```

dispatched by signature algorithm.

### Phase 6 — Sign dispatch

Mirror Phase 4 in `sign.rs`. Three new match arms in the
`Sign{Public,Advance}…ByProtocol` enums. The non-trivial part is the
private-input plumbing (Phase 5 wiring).

### Phase 7 — DKG-with-sign path

`compute_dwallet_dkg_and_sign` (`sign.rs:1190`) needs the same VSS
treatment. **Important:** the combined DKG-and-sign session must
persist the presign `PrivateOutput` produced by its internal presign
sub-round, even though there's no externally-visible `presign_id`.
Allocate a synthetic presign id (e.g. session_id + a tag) for that
storage row.

### Phase 8 — Centralized party (user SDK)

Add `advance_centralized_sign_party_vss` mirroring the existing
`advance_centralized_sign_party`. The centralized party DKG output is
unchanged (same `DKGDecentralizedPartyVersionedOutput`); only the sign
flow differs. WASM rebuilds via `sdk/ika-wasm`.

### Phase 9 — TypeScript SDK

Expose the three new signature algorithm IDs as named constants in
`sdk/typescript/src/`. Mirror existing per-algorithm sign-helper
factories. Add SDK-level tests that use the new IDs end-to-end against
a local swarm (Phase 11 verification).

### Phase 10 — Protocol version gate

In `ika-protocol-config`, add `fast_schnorr_version: Option<u64>`.
Cut a new protocol version where it's `Some(1)`. Validators on an older
protocol version must reject sign / presign requests that name a VSS
algorithm. The Move contract gate (Phase 1) is the primary enforcement;
the Rust check is defense-in-depth at the request-acceptance layer in
`crates/ika-core/src/request_protocol_data.rs:156` filtering.

### Phase 11 — Verification (end-to-end)

End-to-end smoke test via local swarm:

```bash
cargo build --release
cargo test --release -p ika-core dwallet_mpc::integration_tests
cargo test --release -p dwallet-mpc-types mpc_protocol_configuration
```

Integration scenario (write or extend an existing test in
`crates/ika-core/src/dwallet_mpc/integration_tests/`):

1. Start local 4-validator swarm at the new protocol version.
2. Run network DKG (verifies PVSS HPKE keys plumbed correctly).
3. Create three dWallets — one each on (secp256k1, curve25519,
   ristretto) — using the AHE-mode Schnorr variants. Sign once with
   each. Existing behavior, regression gate.
4. Create three more dWallets on the same curves using the VSS-mode
   variants. Sign once with each. Verify each signature against the
   curve's standard verifier (`k256`, `ed25519-dalek`, `schnorrkel`).
5. Attempt to import a key with a VSS variant — must be rejected at
   the Move-contract layer **and** at the Rust request-filter layer.
6. Kill one validator between presign and sign for a VSS dWallet;
   sign session must still finalize using the remaining quorum (drops
   the missing validator's `PrivateOutput` row gracefully).
7. Drop the `presign_private_outputs` row for one validator and re-run
   a VSS sign — expect that validator to fall out of the quorum, not
   crash the session.

TypeScript SDK smoke (Phase 9):

```bash
cd sdk/typescript && pnpm test
```

Move build:

```bash
cd contracts/ika_dwallet_2pc_mpc && sui move build
```

Rustfmt + clippy gate before commit:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
```

## Open questions to resolve during implementation

1. **Exact `vss::schnorr::presign::decentralized_party::PublicInput`
   field set** — read upstream during Phase 4. Conservative
   placeholder above assumes same shape as AHE-mode plus per-curve
   PVSS HPKE keys; confirm.
2. **`presign_private_outputs` storage location** — per-epoch store
   vs dedicated table. Decide based on existing `Presign` storage
   placement; co-locate.
3. **Round count for VSS presign vs AHE presign** — if VSS is
   >3 rounds, the existing `schnorr_presign_second_round_delay`
   single-knob may need a per-round delay map. Check upstream round
   count.
4. **`is_fast_schnorr_supported` Move-side check** — surface via
   protocol-version constant or a separate boolean field?
