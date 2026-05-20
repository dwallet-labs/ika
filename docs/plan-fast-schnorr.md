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
shared by the network), and **does not support the combined
DKG-and-sign fast path** (the upstream combined party is an unimplemented
placeholder — see §"Combined DKG-and-sign" below).

This plan was written after reading the pinned upstream crate
(`~/.cargo/git/checkouts/cryptography-private-b809ba535a56ff30/84fa8da/2pc-mpc/`)
and the ika code paths end-to-end. All field sets, round counts, storage
locations, gating mechanisms, and ID assignments below are confirmed
against source — not placeholders. The "Open questions" section is gone;
its contents are resolved inline and summarized in §"Resolved design
decisions".

---

## Upstream API (cryptography-private @ `84fa8da`) — confirmed

### Module-path subtlety (load-bearing)

The three protocol type aliases resolve to a thin `PhantomData` marker
struct `crate::vss::schnorr::Protocol<…>` (`2pc-mpc/src/lib.rs:1125-1135`).
All the round logic, `PublicInput`/`PrivateInput`/`PrivateOutput` structs,
and the `presign::Protocol` / `sign::Protocol` impls live under a *different*
path, `crate::schnorr::vss::{presign,sign}`. **Both paths are real and
distinct**: the alias points at `vss::schnorr::Protocol`; the structs you
construct in dispatch come from `schnorr::vss::*`. Don't conflate them.

The three aliases (confirmed verbatim):

```rust
// 2pc-mpc/src/lib.rs
twopc_mpc::secp256k1::class_groups::vss::TaprootVSSProtocol             // line 1422
twopc_mpc::curve25519::class_groups::vss::EdDSAVSSProtocol              // line 1266
twopc_mpc::ristretto::class_groups::vss::SchnorrkelSubstrateVSSProtocol // line 1340
```

Each is `crate::vss::schnorr::Protocol<SCALAR_LIMBS, FUND_DISC_LIMBS,
NON_FUND_DISC_LIMBS, GroupElement>` — same shape, only the curve's
discriminant-limb constants and `GroupElement` differ. They implement the
same generic `twopc_mpc::dkg::Protocol`, `twopc_mpc::presign::Protocol`,
and `twopc_mpc::sign::Protocol` traits ika's existing dispatch consumes —
so the routing layer needs new match arms, not new traits.

### Hard precondition: weight-1 access structure

Both the VSS presign party (`schnorr/vss/presign/decentralized_party/party.rs:324-334`)
and the VSS sign party (`schnorr/vss/sign/decentralized_party/party.rs:339-348`)
**reject any access structure where some party's weight ≠ 1**:

```rust
// VSS requires a "naive" access structure where each party has exactly weight 1.
if !access_structure.party_to_weight.values().all(|&weight| weight == 1) {
    return Err(Error::from(ErrorKind::InvalidParameters));
}
```

ika satisfies this **today, end-to-end**: the on-chain committee is
count-based (`contracts/ika_common/sources/bls_committee.move:84-85` —
"Each member has equal voting power of 1"), `voting_power` is hardcoded to
`1` per validator (`crates/ika-sui-client/src/lib.rs:454`), and the MPC
access structure is built straight from those voting rights
(`crates/ika-core/src/dwallet_mpc/mod.rs:150-172`), giving exactly one
share per validator (one `PartyID` per validator, bijection at
`mod.rs:62-83`). So VSS Schnorr is compatible with the current access
structure — **no separate flat structure is needed**.

**Risk to record, not a blocker:** the weight-1 property is a property of
the current count-based committee, *not* an invariant the ika MPC layer
asserts. `Weight` is `u16` and `generate_access_structure_from_committee`
(`mod.rs:158-160`) would silently produce weights > 1 if ika ever moved to
genuine stake-weighting (e.g. via the divergent builder
`sui_syncer.rs:363-368` that passes raw stake). If that migration ever
happens, VSS sessions would start failing the upstream guard. **Action:**
add a defensive `debug_assert`/early-return in the VSS dispatch arms that
the access structure is uniform, with a clear error, so a future
stake-weighting change fails loudly at the VSS boundary instead of deep in
the crypto layer.

### Key shape differences vs AHE-mode (all confirmed against source)

- **DKG output type is identical.** Both AHE and VSS declare the *same*
  `type DKGProtocol = crate::class_groups::asynchronous::DKGProtocol<…>`
  (VSS: `schnorr/vss/presign.rs:219-224`; AHE:
  `schnorr/ahe/presign/class_groups.rs:138-143`), so
  `DecentralizedPartyDKGOutput` is byte-for-byte the same
  `DKGDecentralizedPartyVersionedOutput<…>` (`lib.rs:601-610`). Existing
  dWallet DKG outputs are reused as-is; **no new DKG flow.** One
  constraint: VSS sign requires the `UniversalPublicDKGOutput` variant and
  rejects `TargetedPublicDKGOutput` (`sign/decentralized_party/party.rs:357-373`).

- **Presign `PublicInput` differs — it needs the per-party HPKE keys.**
  `schnorr/vss/presign/decentralized_party/party.rs:42-50`:
  ```rust
  pub struct PublicInput<ProtocolPublicParameters> {
      pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
      pub party_encryption_keys: HashMap<PartyID, EncryptionPublicKey>,
      pub parties_with_uc_verified_public_keys: HashSet<PartyID>,
  }
  ```
  AHE presign `PublicInput` (`schnorr/ahe/presign/decentralized_party.rs:9-12`)
  carries **only** `protocol_public_parameters`. So the VSS presign arm
  must additionally supply the collected per-party PVSS HPKE encryption
  keys (`mpc::secret_sharing::shamir::known_order::EncryptionPublicKey` —
  exactly the keys shipped by the network-DKG / Reconfiguration v3 work)
  and the set of parties whose keys passed UC verification. The presign
  `PublicInput` does **not** carry the DKG output (both AHE and VSS ignore
  it: `From<(Arc<PP>, Option<DKGOutput>)>` discards the second element).

- **Presign `PrivateOutput` is non-trivial — this is the whole reason for
  Phase 5.** For AHE, `<PresignParty as mpc::Party>::PrivateOutput = ()`
  (`schnorr/ahe/.../class_groups.rs:112`). For VSS
  (`schnorr/vss/presign/decentralized_party/party.rs:223-224`):
  ```rust
  type PrivateOutput =
      Vec<PrivatePresignOutput<group::Value<GroupElement::Scalar>, GroupElement::Value>>;
  ```
  where (`schnorr/vss/presign.rs:94-114`):
  ```rust
  pub struct PrivatePresignOutput<ScalarValue, GroupElementValue> {
      pub session_id: CommitmentSizedNumber,
      pub presign_blending_index: u16,
      pub nonce_share_first_part: ScalarValue,   // secret [k_0]_i
      pub nonce_share_second_part: ScalarValue,  // secret [k_1]_i
      pub nonce_share_first_part_coefficient_commitments: Vec<GroupElementValue>,  // public
      pub nonce_share_second_part_coefficient_commitments: Vec<GroupElementValue>, // public
  }
  ```
  It holds this validator's **secret Shamir nonce shares** plus public
  coefficient commitments. It is *not* recoverable from any on-chain /
  public data, and the sign party binds to it by `session_id` +
  `presign_blending_index`. It must be persisted per-validator between
  presign and sign. The public counterpart
  (`schnorr::vss::Presign`, `presign.rs:82-91`) carries only `session_id`,
  `presign_blending_index`, and the two public nonce points — this is what
  goes on-chain / to the centralized party. **Crucially, the public
  `Presign` carries `session_id` and `presign_blending_index`**, so the
  sign session can recover the storage key from the public presign bytes it
  already receives (see Phase 5).

- **Sign `PublicInput`** (`schnorr/vss/sign/decentralized_party.rs:497-512`):
  ```rust
  pub struct PublicInput<DKGOutput, Presign, SignMessage, ProtocolPublicParameters, GroupElementValue> {
      pub message: Vec<u8>,
      pub hash_scheme: HashScheme,
      pub dkg_output: DKGOutput,                                  // same versioned DKG output
      pub presign: Presign,                                       // public schnorr::vss::Presign
      pub centralized_party_partial_signature: SignData<…>,       // user's partial sig
      pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
      pub first_secret_key_polynomial_commitments: Vec<GroupElementValue>,
      pub second_secret_key_polynomial_commitments: Vec<GroupElementValue>,
  }
  ```

- **Sign `PrivateInput`** (`schnorr/vss/sign/decentralized_party/party.rs:37-55`):
  ```rust
  pub struct PrivateInput<ScalarValue, GroupElementValue> {
      pub secret_key_share_first_part: ScalarValue,   // [x_0]_i  — from DKG key shares
      pub secret_key_share_second_part: ScalarValue,  // [x_1]_i  — from DKG key shares
      pub session_id: CommitmentSizedNumber,          // ─┐
      pub presign_blending_index: u16,                //  │
      pub nonce_share_first_part: ScalarValue,        //  ├─ from persisted presign PrivateOutput
      pub nonce_share_second_part: ScalarValue,       //  │
      pub first_nonce_polynomial_commitments: Vec<GroupElementValue>,  // │
      pub second_nonce_polynomial_commitments: Vec<GroupElementValue>, // ─┘
  }
  ```
  Sign `PrivateInput` = **(DKG secret key shares) ⊕ (persisted presign
  `PrivateOutput`)**. The `advance` fn asserts the `session_id` /
  `presign_blending_index` match the public presign
  (`sign/.../party.rs:332-337`) — the binding that makes Phase 5 mandatory.
  For AHE, `SignDecentralizedPartyPrivateInput =
  HashMap<PartyID, SecretKeyShareSizedInteger>` (key-share material only;
  the nonce lives encrypted inside the AHE on-chain `Presign`).

### Round counts (confirmed) — the delay knob must change

| protocol            | rounds | shape                                  |
|---------------------|--------|----------------------------------------|
| AHE schnorr presign | 2      | Advance → Finalize                     |
| **VSS presign**     | **3**  | Dealing → Accusation → Aggregation     |
| AHE schnorr sign    | 3      |                                        |
| **VSS sign**        | **2**  | compute+broadcast share → finalize     |

(Slice-length match arms: presign `schnorr/vss/.../party.rs:336-440`; sign
`party.rs:377-434`.) VSS presign has **3** heterogeneous rounds (a *new*
Accusation round and a third Aggregation round), so the single
`schnorr_presign_second_round_delay` knob — which assumes "the second
round" is the last — does **not** map. See Phase 4 for the resolution
(per-round delay handling for VSS presign).

---

## Naming & IDs (corrected — there is no flat global ID space)

Add `TaprootVSS`, `EdDSAVSS`, `SchnorrkelSubstrateVSS` as new variants of
`DWalletSignatureAlgorithm` (Rust). On-chain, signature-algorithm IDs are
**per-curve `u32` values inside a nested `curve → {sig_algo → [hash]}`
map** — there is no global ID registry and no Move constant for them. The
same numeric ID is reused across curves. The next free per-curve ID:

| new variant              | curve (id)        | existing ids        | **new id** | hash scheme |
|--------------------------|-------------------|---------------------|-----------|-------------|
| `TaprootVSS`             | secp256k1 (0)     | 0=ECDSA, 1=Taproot  | **2**     | SHA256      |
| `EdDSAVSS`               | curve25519 (2)    | 0=EdDSA             | **1**     | SHA512      |
| `SchnorrkelSubstrateVSS` | ristretto (3)     | 0=SchnorrkelSubstr. | **1**     | Merlin      |

Hash schemes mirror the AHE sibling on the same curve.

---

## Files to modify (critical paths)

### Move contracts (DOCUMENTED HERE — implemented separately)

> Note: this planning task does not edit Move sources. The changes below
> are the spec for the Move work item.

- `contracts/ika_dwallet_2pc_mpc/sources/support_config.move` — the
  per-curve ID assignment is **runtime VecMap data**
  (`SupportConfig.supported_curves_to_signature_algorithms_to_hash_schemes`,
  `support_config.move:26-39`), populated post-deploy via
  `coordinator.move:159` `set_supported_and_pricing(...)` (gated by
  `VerifiedProtocolCap`). There is **no Move constant** to add. Adding VSS
  = the protocol-cap holder writes the three new `(curve, id) → [hash]`
  entries into that map. Validation
  (`validate_curve_and_signature_algorithm`, `support_config.move:100-117`)
  then accepts them automatically.
- **Imported-key DKG-only enforcement requires a NEW Move check.** The
  existing `curve_to_signature_algorithms_for_imported_key` map
  (`support_config.move:46-55`, read at `is_global_presign_for_imported_key`,
  `:174-180`) is only a *global-vs-targeted presign toggle*, **not** an
  allow/deny gate — an algorithm absent from it is still signable for
  imported keys, just with targeted presigns. Imported-key *creation*
  (`request_imported_key_dwallet_verification`, `coordinator_inner.move:3242`)
  validates only the curve, not the algorithm. The algorithm is gated at
  sign-approval time in `approve_imported_key_message`
  (`coordinator_inner.move:2526`). **Therefore:** to make VSS truly
  non-importable on the Move side, add an explicit deny in
  `approve_imported_key_message` — e.g. a
  `imported_key_forbidden_signature_algorithms` set on `SupportConfig`, or
  a per-algorithm `dkg_only` flag — and reject if the requested algorithm
  is a VSS variant. Do **not** rely solely on omitting VSS from the
  imported-key map; that is necessary but not sufficient.
- **No Move version gate.** Move has no protocol-version concept to gate on
  (grep confirms `coordinator_inner.move` has no version comparison or
  `is_X_supported` boolean). Feature gating in ika-Move is "is the key in
  the supported map (and not paused)". So **do not** add
  `is_fast_schnorr_supported` to Move. The version gate lives in Rust
  (Phase 10); the Move layer enables VSS purely by the map population
  above plus the new imported-key deny.

### Rust types & config

- `crates/dwallet-mpc-types/src/dwallet_mpc.rs:201-212` — extend
  `DWalletSignatureAlgorithm` with `TaprootVSS`, `EdDSAVSS`,
  `SchnorrkelSubstrateVSS` (with `#[strum(to_string = "…")]` names).
- `crates/dwallet-mpc-types/src/mpc_protocol_configuration.rs:45-104`
  — add the three `(curve, new-id) → [hash]` entries to
  `SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES`: secp256k1→
  `2 = [SHA256]`, curve25519→`1 = [SHA512]`, ristretto→`1 = [Merlin]`,
  mirroring the AHE siblings at lines 58-63 / 81-88 / 90-99.
- `mpc_protocol_configuration.rs:107-114` — add VSS ids to
  `GLOBAL_PRESIGN_SUPPORTED_CURVE_TO_SIGNATURE_ALGORITHMS_FOR_DKG`
  (`0 => [0,1,2]`, `2 => [0,1]`, `3 => [0,1]`).
- `mpc_protocol_configuration.rs:117-124` — **do NOT add** VSS ids to
  `..._FOR_IMPORTED_KEY`. Add a comment explaining the Shamir-share reason
  *and* noting that this map alone does not enforce DKG-only (the real
  guard is the new Move check + the Phase-10 Rust filter).
- `mpc_protocol_configuration.rs:185-227` (`try_into_signature_algorithm`)
  — add match arms `(0,2)→TaprootVSS`, `(2,1)→EdDSAVSS`,
  `(3,1)→SchnorrkelSubstrateVSS`.
- `mpc_protocol_configuration.rs:229-308` (`try_into_hash_scheme`) — add
  the three arms mirroring Taproot (SHA256, ~255-261), EdDSA (SHA512,
  ~275-284), SchnorrkelSubstrate (Merlin, ~286-296).
- `mpc_protocol_configuration.rs:310-425` test — the existing test asserts
  exact per-curve key sets (`vec![0,1]`, `vec![0]`, …). Adding VSS **will
  break these assertions**; update them to `vec![0,1,2]` (secp256k1),
  `vec![0,1]` (curve25519, ristretto), and add round-trip assertions for
  the new variants.
- `crates/ika-protocol-config/src/lib.rs` — add a **plain `bool`**
  feature flag `fast_schnorr_supported` to `FeatureFlags` (lib.rs:124-170),
  matching the `internal_presign_sessions` / `noa_checkpoints` convention
  (lib.rs:159-169) — **not** `Option<bool>` and **not** `Option<u64>`
  (those conventions are for versioned payloads, which this is not). Add
  getter `fast_schnorr_supported(&self) -> bool` (lib.rs:~361). Bump
  `MAX_PROTOCOL_VERSION` 4→5 (lib.rs:20) and add a `5 => { cfg.feature_flags
  .fast_schnorr_supported = true; }` arm in the version loop (lib.rs:670-699).
  Do not mutate any existing version's values (lib.rs:558-559 warning).

### Protocol type aliases

- `crates/ika-types/src/messages_dwallet_mpc.rs:553-558` — add:
  ```rust
  pub type Secp256k1TaprootVSSProtocol = twopc_mpc::secp256k1::class_groups::vss::TaprootVSSProtocol;
  pub type Curve25519EdDSAVSSProtocol = twopc_mpc::curve25519::class_groups::vss::EdDSAVSSProtocol;
  pub type RistrettoSchnorrkelSubstrateVSSProtocol = twopc_mpc::ristretto::class_groups::vss::SchnorrkelSubstrateVSSProtocol;
  ```

### Validator MPC dispatch

- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/presign.rs`
  — extend `PresignPublicInputByProtocol` (lines 35-51, 5 variants today)
  and `PresignAdvanceRequestByProtocol` (lines 53-69) with three VSS
  variants. Add arms in `try_new` (71-148) and the public-input builders
  `try_new_v1`/`try_new_v2` (150-282). The VSS arm builds
  `schnorr::vss::presign::decentralized_party::PublicInput {
  protocol_public_parameters, party_encryption_keys,
  parties_with_uc_verified_public_keys }` — note the latter two fields are
  **new wiring**: source the per-party PVSS HPKE keys + UC-verified set
  from the network-encryption-key public data (the v3 PVSS keys already
  plumbed). AHE Schnorr arms today build only `{ protocol_public_parameters }`
  (presign.rs:218-243, 267-277) and explicitly discard the DKG output —
  VSS does the same with the DKG output.
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/sign.rs`
  — extend `SignPublicInputByProtocol` / `SignAdvanceRequestByProtocol`
  (lines 41-105) with three VSS arms. Build the VSS sign `PublicInput`
  (the 8-field struct above) from the DKG output, public presign,
  centralized partial signature, protocol public params, and the
  secret-key polynomial commitments. The private-input source changes —
  see Phase 5/6.
- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs` — the per-(curve,
  algorithm) counters `instantiated_internal_presign_sessions` /
  `completed_internal_presign_sessions` are `HashMap<(DWalletCurve,
  DWalletSignatureAlgorithm), u64>` (mpc_manager.rs:179-187), so they pick
  up the new variants automatically. **But the per-algorithm presign-pool
  tables are NOT automatic** (see Phase 5 storage) — they are one DBMap
  field per algorithm. If VSS uses the internal/NOA presign pool, three
  new pool tables are required.

### Centralized party (user-side) SDK — simpler than expected

- `crates/dwallet-mpc-centralized-party/src/lib.rs` — **no new
  `advance_centralized_sign_party_vss` function is needed.** The existing
  generic helpers `advance_sign_with_decentralized_party_dkg_output<P, D>`
  (lib.rs:668) → `advance_sign_with_rng<P, D, R>` (lib.rs:800) are
  parameterized purely on `P: sign::Protocol + presign::Protocol<DKGProtocol
  = D>` with a 5-tuple `From` bound for the sign public input. The upstream
  VSS sign module is explicitly *"VSS-specific wrappers around the shared
  centralized party sign implementation"* — the centralized party's
  `PrivateInput` (`SecretKeyShare`), `OutgoingMessage` (`PartialSignature`),
  and `SignCentralizedPartyPublicInput` (the same 5-tuple) are unchanged;
  VSS differs only on the **decentralized** side. So: add three sign
  protocol type aliases near lib.rs:45-48, and three match arms in the
  `VersionedPresignOutput::V2` block (lib.rs:589-657, and its
  centralized-output twin) keyed on the new `DWalletSignatureAlgorithm`
  variants, dispatching to the same generic helper with the same per-curve
  `D` (`Secp256k1DKGProtocol` / `Curve25519DKGProtocol` /
  `RistrettoDKGProtocol`). DKG and presign centralized-party functions are
  reused unchanged (there is **no** VSS presign centralized party — presign
  is validator-only).
- `parse_signature_from_sign_output_inner` (centralized-party lib.rs:~1450)
  — verify the signature-output decode arms cover the VSS variants; the
  produced signature object types may differ from AHE. Confirm during impl.

### TypeScript SDK — pure data-table edits

- `sdk/typescript/src/client/types.ts:215` — add the three names to the
  `SignatureAlgorithm` const object.
- `sdk/typescript/src/client/hash-signature-validation.ts` — add entries
  to `VALID_HASH_SIGNATURE_COMBINATIONS` (line 7),
  `SIGNATURE_ALGORITHM_TO_CURVE` (16),
  `SIGNATURE_ALGORITHM_ABSOLUTE_NUMBERS` (25), `CURVE_SIGNATURE_HASH_CONFIG`
  (44 — this *mirrors* the Rust supported map; use per-curve ids 2/1/1),
  the static type helpers `ValidSignatureAlgorithmForCurve` (196) /
  `ValidHashForSignature` (207), and the `getSignatureAlgorithmName`
  switch (123). The sign path
  (`cryptography.ts` `createUserSignMessageWith*`) is fully generic over
  the algorithm — **no new sign-helper functions.**
- `sdk/ika-wasm/` — **no new WASM binding needed.** The existing
  `create_sign_centralized_party_message` (ika-wasm `src/lib.rs:250`, twin
  at :276) passes `signature_algorithm: u32` straight through to
  `advance_centralized_sign_party`, which resolves the VSS variant
  internally once the Rust arms exist. `sdk/dwallet-mpc-wasm` referenced in
  CLAUDE.md does not exist on disk; bindings are all in `sdk/ika-wasm`.
  Rebuild ika-wasm separately (`cd sdk/ika-wasm && rm -rf target dist &&
  PROFILE=release pnpm build`) — it is excluded from the workspace (root
  `Cargo.toml:5`), and a stale `dist` against a different crypto rev
  produces silent BCS mismatches.

---

## Phased work

### Phase 1 — Move contracts: register VSS algorithms (spec only here)

Per-curve VSS ids: TaprootVSS=2 (secp256k1), EdDSAVSS=1 (curve25519),
SchnorrkelSubstrateVSS=1 (ristretto). These are written into the on-chain
`supported_curves_to_signature_algorithms_to_hash_schemes` VecMap via
`set_supported_and_pricing`. Add the new imported-key deny check in
`approve_imported_key_message` (coordinator_inner.move:2526) — see Move
section. No version constant; no `is_fast_schnorr_supported` bool.

### Phase 2 — Rust types & config

Extend `DWalletSignatureAlgorithm`, the four config maps, and the two
decoders. Add `fast_schnorr_supported: bool` to `FeatureFlags`, bump
`MAX_PROTOCOL_VERSION` to 5, set the flag in the `5 =>` arm. Update the
existing `mpc_protocol_configuration.rs` test key-set assertions (they will
break) and add round-trip assertions for the new (curve, id) pairs and the
DKG-yes / imported-key-no membership checks.

### Phase 3 — Protocol type aliases

Add the three `…VSSProtocol` aliases in `messages_dwallet_mpc.rs`. No logic.

### Phase 4 — Presign dispatch (incl. delay handling)

Add the three VSS arms to the presign enums and constructors. Build the VSS
presign `PublicInput` with `protocol_public_parameters` + the per-party
PVSS HPKE `party_encryption_keys` + `parties_with_uc_verified_public_keys`.
Add the weight-1 defensive assert (see §"Hard precondition").

**Delay knob:** VSS presign is **3 rounds** (Dealing → Accusation →
Aggregation), not 2. The current `schnorr_presign_second_round_delay`
single knob is insufficient. Resolution: introduce a small per-round delay
selector for VSS presign — reuse `schnorr_presign_second_round_delay` for
the Accusation (round 2) delay and add a `schnorr_presign_third_round_delay`
(default = the same value) for the Aggregation round, gated to VSS
protocols only. AHE presign keeps the existing single-knob behavior. Place
the new config knob next to the existing one and document that it applies
to VSS presign exclusively.

### Phase 5 — Presign `PrivateOutput` persistence (the critical infra)

**Storage location — decided.** Co-locate a new table in
`AuthorityEpochTables` (`crates/ika-core/src/authority/authority_per_epoch_store.rs`,
the `#[derive(DBMapUtils)]` struct at ~674), next to `used_presigns`
(`:805`) and `assigned_presigns_*` (`:812-820`). Rationale, all confirmed:
every existing per-validator presign artifact (pool, used-marker, assigned)
lives here and nowhere else; there is **no** MPC-service-private RocksDB in
ika-core; per-epoch tables open at a per-epoch physical path
(`AuthorityEpochTables::path`, `:902-904`) and are physically dropped on
epoch rotation, so the table **self-prunes** with no extra teardown code.

**Key — decided.** Key by the presign's `session_id`
(`CommitmentSizedNumber`), which is present in **both** the private
`PrivatePresignOutput` (written at presign finalize) and the **public**
`schnorr::vss::Presign` (available at sign time, whether inline in the sign
event or popped from the pool). This avoids any new `presign_id (ObjectID)
→ SessionIdentifier` on-chain plumbing — the lookup key is recovered by
deserializing the public presign bytes the sign session already has. A
single presign session produces a `Vec<PrivatePresignOutput>` (one per
blending index), so store the whole `Vec` as one row keyed by `session_id`
and select the matching entry by `presign_blending_index` at sign time.

Concretely:
```rust
// in AuthorityEpochTables
presign_private_outputs: DBMap<CommitmentSizedNumber, Vec<u8>>,
//                              ^ presign session_id    ^ bcs(Vec<PrivatePresignOutput>)
```

**Write hook.** The presign `PrivateOutput` is currently *dropped on the
floor* for all sessions at the single finalize handler
`crates/ika-core/src/dwallet_mpc/dwallet_mpc_service.rs:1550-1554`
(`private_output: _`). For VSS presign sessions, instead of discarding,
serialize and write `presign_private_outputs[session_id] =
bcs(private_output)` before forwarding the public output to consensus.
Branch on protocol/algorithm so AHE keeps discarding `()`.

**Read hook.** AHE sources its sign `PrivateInput` (`decryption_key_shares`)
in `crytographic_computation/mpc_computations.rs` (e.g. lines 195-196,
226-227, 257-258, 328-329) via `DwalletMPCNetworkKeys::decryption_key_shares`.
For VSS, at the same dispatch point, deserialize the public presign to get
`(session_id, presign_blending_index)`, load
`presign_private_outputs[session_id]`, pick the entry for that blending
index, and combine it with the validator's DKG secret key shares to build
the VSS sign `PrivateInput` (the 8-field struct). Encapsulate the
AHE-vs-VSS source choice in:
```rust
enum SignPrivateInputSource {
    Ahe,                                  // load decryption_key_shares (today)
    Vss { presign_session_id: CommitmentSizedNumber, blending_index: u16 },
}
```
dispatched by signature algorithm. This rides the **existing generic seam**
`Option<<SignParty<P> as AsynchronouslyAdvanceable>::PrivateInput>`
(sign.rs:1132 / 1197): the helper threads the value opaquely into
`advance_with_guaranteed_output` and never inspects it, so only the
*source* changes per protocol — no trait change. (The seam already carries
a `TODO(vss)` doc-comment at sign.rs:1112-1125 pointing here.)

**Pruning.** Per-epoch DB drop handles the common case. Additionally drop
the row when the corresponding sign finalizes (or mark via the existing
`used_presigns` mechanism). Bounded by the epoch-end physical drop as a
hard backstop.

**Failure handling.** If the row is missing at sign time (disk loss + state
restore, or presign produced in a prior epoch), the validator must fall out
of the sign quorum gracefully — surface as a soft-fail that excludes this
validator's contribution, **not** a hard session error. (The 2f+1 quorum
absorbs it, exactly as the upstream `round_causing_threshold_not_reached`
machinery expects.)

**Cross-epoch caveat to document.** Because the table is per-epoch, a VSS
presign produced in epoch N cannot be consumed by a sign in epoch N+1. This
is **not new** — AHE `assigned_presigns_*` already expire at the epoch
boundary (doc at authority_per_epoch_store.rs:807-810) — so VSS inherits an
existing invariant. State it explicitly so the pool-refill logic doesn't
carry VSS presigns across epochs.

**NOA / internal-pool tables.** If VSS presigns flow through the internal
presign pool (the NOA path), three new per-algorithm pool tables are
required in `AuthorityEpochTables`, mirroring the existing
`internal_presign_pool_{ecdsa_secp256k1,…,schnorrkel_substrate}` set
(`:763-775`) plus the matching `assigned_presigns_*` (`:812-820`) and a
`internal_presign_pool_sizes` (`:779`) entry per new algorithm:
`internal_presign_pool_taproot_vss`, `internal_presign_pool_eddsa_vss`,
`internal_presign_pool_schnorrkel_substrate_vss`. **Decision:** include
these — VSS supports the internal pool on par with AHE, and the
`presign_private_outputs` key (`session_id`) is recoverable from the pooled
`SessionIdentifier`/public-presign at pop time. Use the
`#[default_options_override_fn = "internal_presign_pool_table_default_config"]`
pattern (`:865-869`) for the new pool tables.

### Phase 6 — Sign dispatch

Add the three VSS arms to the sign enums and `compute_sign`. The only
non-trivial part is the Phase-5 private-input wiring (the `PublicInput`
construction is mechanical). Add the weight-1 defensive assert here too.

### Phase 7 — Combined DKG-and-sign: **VSS is excluded**

The upstream combined `DKGSignParty` for VSS is an **unimplemented
placeholder** (`schnorr/vss/sign/decentralized_party/party.rs:438` —
"placeholder - not yet implemented for VSS"). There is no atomic VSS
DKG-and-sign to dispatch to. **Decision:** VSS Schnorr does **not** support
the combined DKG-and-sign fast path in this activation. A DKG-and-sign
request that names a VSS algorithm must be **rejected** — at the Move layer
(don't expose VSS through the combined entrypoint) and at the Rust
request-acceptance filter (Phase 10). VSS dWallets follow the separate
DKG → presign → sign path. (If the combined flow is wanted later, it is a
separate upstream-crypto work item, not part of this plan.) Therefore
`compute_dwallet_dkg_and_sign` (sign.rs:1190) gets **no** VSS arm; instead
the gate rejects VSS there with a clear error.

### Phase 8 — Centralized party (user SDK)

Add the three sign-protocol type aliases and the three
`VersionedPresignOutput::V2` match arms in
`dwallet-mpc-centralized-party/src/lib.rs` (no new function — see Files
section). Verify `parse_signature_from_sign_output_inner` covers the VSS
signature outputs. Rebuild WASM via `sdk/ika-wasm` (separate build).

### Phase 9 — TypeScript SDK

Pure data-table edits in `types.ts` and `hash-signature-validation.ts` (see
Files section). No new sign-helper factories; no new WASM bindings. Add
SDK-level tests that use the new IDs end-to-end against a local swarm
(Phase 11).

### Phase 10 — Protocol version gate (Rust defense-in-depth)

The `fast_schnorr_supported` flag (Phase 2) at protocol version 5 is the
Rust gate. The forcing function is the **exhaustive, non-defaulted match**
on `DWalletSignatureAlgorithm` in `is_global_presign`
(`crates/ika-core/src/request_protocol_data.rs:214-246`) — adding three
variants causes a compile error there, which is the cue to handle them
(VSS variants are global-presign Schnorr ⇒ `=> true`). Add the version
guard in the `*_protocol_data` constructors right after
`try_into_signature_algorithm` resolves the algorithm (request_protocol_data.rs
~309-312 and the sign/presign constructors ~369-453): if the resolved
algorithm is a VSS variant and `protocol_config.fast_schnorr_supported()`
is `false`, reject. This requires threading `&ProtocolConfig` into those
constructors if not already present — confirm and wire during impl. Also
reject VSS in the DKG-and-sign constructor unconditionally (Phase 7). The
Move map population + imported-key deny (Phase 1) is the primary
enforcement; this Rust check is defense-in-depth.

### Phase 11 — Verification (end-to-end)

```bash
cargo build --release
cargo test --release -p dwallet-mpc-types mpc_protocol_configuration
cargo test --release -p ika-core dwallet_mpc::integration_tests
```

Integration scenario (extend an existing test in
`crates/ika-core/src/dwallet_mpc/integration_tests/`):

1. Start a local 4-validator swarm at protocol version 5 (uniform weight-1
   committee — confirm the access structure is flat, exercising the
   weight-1 path).
2. Run network DKG (verifies PVSS HPKE keys are plumbed into the VSS
   presign `PublicInput`).
3. Create three dWallets — one each on (secp256k1, curve25519, ristretto) —
   using the **AHE-mode** Schnorr variants; sign once with each. Regression
   gate.
4. Create three more dWallets on the same curves using the **VSS-mode**
   variants; sign once with each. Verify each signature against the curve's
   standard verifier (`k256` BIP-340, `ed25519-dalek`, `schnorrkel`).
   This exercises the full presign-`PrivateOutput`-persist → sign-read path.
5. Attempt to import a key and sign with a VSS variant — must be rejected
   at the Move imported-key deny **and** the Rust request filter.
6. Attempt a combined DKG-and-sign naming a VSS variant — must be rejected
   (Phase 7).
7. Kill one validator between presign and sign for a VSS dWallet; the sign
   must still finalize on the remaining quorum (the dead validator's
   `presign_private_outputs` row is simply absent — soft-fail, not crash).
8. Delete the `presign_private_outputs` row for one live validator and
   re-run a VSS sign — that validator falls out of the quorum, session
   still finalizes.
9. (Negative) On an older protocol version (4), a VSS presign/sign request
   is rejected by the Rust gate.

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

---

## Resolved design decisions (was "Open questions")

1. **VSS presign `PublicInput` field set** — `protocol_public_parameters`,
   `party_encryption_keys: HashMap<PartyID, EncryptionPublicKey>` (the PVSS
   HPKE keys), `parties_with_uc_verified_public_keys: HashSet<PartyID>`. No
   DKG output. (`schnorr/vss/presign/decentralized_party/party.rs:42-50`.)
2. **`presign_private_outputs` storage** — new per-epoch `DBMap<CommitmentSizedNumber,
   Vec<u8>>` in `AuthorityEpochTables`, keyed by the presign `session_id`
   (recoverable from the public presign at sign time), holding
   `bcs(Vec<PrivatePresignOutput>)`; self-prunes on epoch rotation; soft-
   fail on missing row. Co-located with `used_presigns` / `assigned_presigns_*`.
3. **Round counts** — VSS presign = 3 rounds (Dealing, Accusation,
   Aggregation), VSS sign = 2. The single `schnorr_presign_second_round_delay`
   knob is insufficient; add a VSS-only third-round (Aggregation) delay
   (defaulting to the same value).
4. **`is_fast_schnorr_supported` on Move** — **no.** Move has no version
   gate; VSS is enabled by populating the supported VecMap. The gate is the
   Rust `fast_schnorr_supported: bool` feature flag at protocol version 5.
5. **Sig-algo IDs** — per-curve, not global: TaprootVSS=2 (secp256k1),
   EdDSAVSS=1 (curve25519), SchnorrkelSubstrateVSS=1 (ristretto).
6. **Combined DKG-and-sign** — **excluded** for VSS (upstream placeholder);
   rejected at the gate.
7. **Centralized party / WASM** — no new function and no new WASM binding;
   reuse the generic helpers via three new type aliases + match arms.
8. **Imported-key DKG-only** — requires a **new explicit Move deny check**
   in `approve_imported_key_message`; the existing imported-key map is only
   a presign-scope toggle and does not enforce it.
9. **Weight-1 access structure** — required by upstream; satisfied by
   ika's current count-based committee. Add a defensive uniform-weight
   assert in the VSS dispatch arms to fail loudly if ika ever moves to
   stake-weighting.
