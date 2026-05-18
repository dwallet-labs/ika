# Backward-compatibility with mainnet-v1.1.8 — plan

## Status (as of 2026-05-18)

**Committed on `dev_backward_compatability`**:

- ✅ Item 1 (`23ba5e5f3d` + pending pin bump to `7795eb45`): cryptography-private 9d35fa76 → a8fe6c6a → 7795eb45 (upstream PR #524 added the Reconfig PublicInput constructors).
- ✅ Item 2 (`23ba5e5f3d`): `decode_validator_encryption_keys` + tests; 3 decode sites rewired.
- ✅ Item 3 (`567bb73a96`): `--legacy-class-groups-only` CLI flag on `ika validator make-validator-info` and `set-next-epoch-mpc-data`.
- ✅ Item 4 (`23ba5e5f3d`): `ProtocolConfig` MAX → 5, `is_*_version_v3()` helpers, v5 snapshot fixtures.
- ✅ Item 6 (next commit): `advance_network_dkg_bwd_compat` + `network_dkg_bwd_compat_public_input`, wired into DKG dispatch.
- ✅ Item 7 (next commit): `reconfiguration_bwd_compat_public_input` + `advance_network_reconfiguration_bwd_compat` calling upstream's new `decentralized_party_backward_compatible::reconfiguration::PublicInput::new_from_{dkg,reconfiguration}_output` constructors. Wired into Reconfig dispatch.
- ✅ Item 8 (next commit): `PublicInput::NetworkEncryptionKey{Dkg, Reconfiguration}` wrapped in `…PublicInput::{BwdCompat, Main}` enums; `&ProtocolConfig` threaded into `session_input_from_request`; `ProtocolCryptographicData::NetworkEncryptionKey{Dkg, Reconfiguration}` holds `…AdvanceArgs::{BwdCompat, Main}`; `ready_to_advance` and `compute_mpc` match each enum. Dispatch is on `is_{network_encryption_key, reconfiguration_message}_version_v3()`.
- ✅ PR #1707 review item 3 file rename (`23ba5e5f3d`).

**Remaining**:

- 🛠 Item 9 (v2→v3 reconfig migration arm): the existing cross-version arm at
  `reconfiguration.rs:115-167` handles the pre-mainnet v1→v2 transition. Once we're
  ready to upgrade a live network from `network_encryption_key_version == 2` (v2 DKG
  output bytes) to `version == 3`, add a symmetric arm that decodes the V2-tagged
  DKG bytes and feeds them into the **main** `decentralized_party::reconfiguration::Party::PublicInput::new_from_dkg_output`, writing the result as V2 still (DKG output is wire-stable; only Party impl + Message shape differ). Currently the bwd-compat reconfig dispatcher's `(V2 dkg, None reconfig)` arm already handles the genesis-equivalent case under the bwd-compat Party; the upgrade arm would dispatch into the main Party instead. Practically tied to ProtocolConfig activation logic that the user's operations team controls.
- 🛠 Item 10: integration tests for bwd-compat DKG/Reconfig swarms + v2→v3 migration —
  the decode round-trip tests shipped in `23ba5e5f3d`; the swarm tests need writing
  now that dispatch is wired end-to-end.

## Context

The `dev_backward_compatability` branch (HEAD `396af2647e`) is built on top of PR #1707's crypto bump (`cryptography-private` pinned at `9d35fa76`). PR #1707 added per-curve PVSS HPKE keys to the new bundled struct `ValidatorEncryptionKeysAndProofs` (`crates/ika-types/src/committee.rs:559`) and now writes its bytes into the same Move-side validator field that mainnet-v1.1.8 used for the bare `ClassGroupsEncryptionKeyAndProof`. The field's outer envelope is unchanged — both sides write `VersionedMPCData::V1(MPCDataV1 { class_groups_public_key_and_proof: Vec<u8> })` (`crates/dwallet-mpc-types/src/dwallet_mpc.rs:286-293`, byte-identical in mainnet-v1.1.8). Only the bytes inside that vec differ.

Today's decode (`crates/ika-types/src/sui/epoch_start_system.rs:152-157, 209-225`) blindly tries `bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>` and on failure either drops the validator (`error!` + filter_map) or silently sets all four key fields to `None`. A mainnet-v1.1.8 binary running against this branch's payload — or vice versa — sees zero validators.

`cryptography-private @ a8fe6c6a` (one commit ahead of `9d35fa76`, PR #519 *"Add backward-compat DKG + Reconfiguration sub-protocols"*) ships:

- `twopc_mpc::decentralized_party_backward_compatible::dkg::{Party, Message, PublicInput, PublicOutput}` — wire-identical to old inkrypto decentralized DKG. `PublicInput::new(access_structure, encryption_keys_and_proofs_per_crt_prime)` — no PVSS HPKE keys; works against old-shape validator keys.
- `twopc_mpc::decentralized_party_backward_compatible::reconfiguration::{Party, Message, PublicInput, PublicOutput}` — wire-identical to old inkrypto Reconfig.
- `group::bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound_backward_compatible`.

PR #1707 already handled `SignData` (`sign.rs:692-721`); presign and Schnorr-AHE are wire-stable per the audit at `/Users/jcscaly/projects/cryptography-private/breaking-changes-inkrypto-to-main.md`.

## Architectural axis (user-directed framing)

The boundary that drives every dispatch in this plan is **the shape of the bytes inside `MPCDataV1.class_groups_public_key_and_proof`**. The Move-side field stays an opaque `vector<u8>`; the dispatch is purely Rust-side.

| When | Bytes published by validator | DKG / Reconfig path used | `VersionedNetworkDkgOutput` tag on finalized output |
|---|---|---|---|
| `protocol_version ≤ 4` (mainnet-v1.1.8 era; this branch's HEAD today) | `bcs::to_bytes(&ClassGroupsEncryptionKeyAndProof)` — old shape, class-groups only | `decentralized_party_backward_compatible::*::Party` — old-shape upstream | `V2` (= old-shape bytes) |
| `protocol_version ≥ 5` (post-upgrade) | `bcs::to_bytes(&ValidatorEncryptionKeysAndProofs)` — new shape, class-groups + per-curve PVSS HPKE | `decentralized_party::*::Party` — new-shape upstream (PR #1707's wiring) | `V3` (NEW; = new-shape bytes) |

Two non-negotiables that follow:

1. **Decode is shape-tolerant on read.** A node running this branch must decode both shapes (we may be reading a payload published before the upgrade activation epoch, or by a still-mainnet-shape peer). PVSS fields land as `None` per-validator when the old shape is detected.
2. **Encode is version-gated on write.** A validator publishes the shape that matches `current_protocol_version`. Pre-upgrade: old shape. Post-upgrade: new shape. No mixed publication within a single epoch in steady state.

DKG/Reconfig Party dispatch is then *consequential* of the published shape: at `protocol_version ≤ 4` every validator has only old-shape keys → only the bwd-compat Party can run; at `protocol_version ≥ 5` every validator has new-shape keys → the main Party runs. The `VersionedNetworkDkgOutput`/`VersionedDecryptionKeyReconfigurationOutput` `V2`/`V3` tags exist for the cross-epoch case where a stored `V2` DKG output (from the pre-upgrade epoch) is consumed by a `V3` reconfig (the first post-upgrade epoch). PR #1707's `V2` mapping (which currently labels the new-shape bytes as `V2`) is corrected so `V2` ≡ old-shape and `V3` ≡ new-shape.

## Items

### 1. Bump cryptography-private pin

`Cargo.toml:76-82` — change all seven `cryptography-private` deps from `rev = "9d35fa76"` to `rev = "a8fe6c6a"`:

```toml
mpc = { git = "…/cryptography-private", rev = "a8fe6c6a" }
proof = { git = "…/cryptography-private", rev = "a8fe6c6a" }
class_groups = { git = "…/cryptography-private", rev = "a8fe6c6a", features = ["threshold"] }
commitment = { git = "…/cryptography-private", rev = "a8fe6c6a" }
twopc_mpc = { git = "…/cryptography-private", rev = "a8fe6c6a" }
group = { git = "…/cryptography-private", features = ["os_rng"], rev = "a8fe6c6a" }
homomorphic_encryption = { git = "…/cryptography-private", rev = "a8fe6c6a" }
```

`cargo update -p mpc -p proof -p class_groups -p commitment -p twopc_mpc -p group -p homomorphic_encryption`. `sdk/ika-wasm/Cargo.lock` is locked separately — bump it the same way (use the established pattern from PR #1707 commit `de107ced21`).

Single-commit delta (PR #519 upstream) — purely additive `decentralized_party_backward_compatible` module + one widened `pub(crate)` field on `class_groups::reconfiguration::PublicInput` + the `new_with_randomizer_upper_bound_backward_compatible` ctor on `bounded_integers_group::PublicParameters`.

### 2. Validator-key DECODE: tolerate both shapes

This is the load-bearing item per user direction. The two decode sites under `crates/ika-types/src/sui/epoch_start_system.rs` (L152-157, L209-225) currently try only the new shape. Replace with a single shared decoder that tries new, then falls back to old.

Add to `crates/ika-types/src/committee.rs` (next to `ValidatorEncryptionKeysAndProofs` at L559):

```rust
/// Decode the bytes from `MPCDataV1.class_groups_public_key_and_proof()` accepting
/// either shape:
///   * `ValidatorEncryptionKeysAndProofs` — the post-PR-#1707 bundle (class-groups
///     CRT key + 3 per-curve PVSS HPKE keys). Validators publish this at
///     `protocol_version ≥ 5`.
///   * `ClassGroupsEncryptionKeyAndProof` — the mainnet-v1.1.8 shape (class-groups
///     CRT key only). Validators publish this at `protocol_version ≤ 4`.
/// On old-shape input the three PVSS halves come back as `None`; downstream DKG/
/// Reconfig dispatch picks the bwd-compat Party (which needs no PVSS keys).
pub fn decode_validator_encryption_keys(
    bytes: &[u8],
) -> Option<DecodedValidatorEncryptionKeys> {
    if let Ok(bundle) = bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>(bytes) {
        return Some(DecodedValidatorEncryptionKeys {
            class_groups: bundle.class_groups,
            secp256k1_pvss: Some(bundle.secp256k1_pvss),
            secp256r1_pvss: Some(bundle.secp256r1_pvss),
            ristretto_pvss: Some(bundle.ristretto_pvss),
        });
    }
    if let Ok(class_groups) = bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(bytes) {
        return Some(DecodedValidatorEncryptionKeys {
            class_groups,
            secp256k1_pvss: None,
            secp256r1_pvss: None,
            ristretto_pvss: None,
        });
    }
    None
}

pub struct DecodedValidatorEncryptionKeys {
    pub class_groups: ClassGroupsEncryptionKeyAndProof,
    pub secp256k1_pvss: Option<Secp256k1PvssEncryptionKeyAndProof>,
    pub secp256r1_pvss: Option<Secp256r1PvssEncryptionKeyAndProof>,
    pub ristretto_pvss: Option<RistrettoPvssEncryptionKeyAndProof>,
}
```

The try-new-then-old order matters: `ValidatorEncryptionKeysAndProofs` BCS bytes are a superset of `ClassGroupsEncryptionKeyAndProof` bytes followed by 3 PVSS tuples. There is no way for old-shape bytes to accidentally parse as new-shape (the trailing PVSS bytes are absent, so bcs hits an early EOF) — but the reverse parse path (new-shape bytes as old-shape) would succeed at parsing the first 7-prime CRT array and leave trailing bytes. **Therefore the trailing-bytes guard is required**: `bcs::from_bytes` rejects trailing bytes by default — verify in the project's bcs version. If it does not (some bcs configurations allow), use `bcs::from_bytes_seed` or check residual length and reject manually.

Update both call sites to call `decode_validator_encryption_keys`:

- `epoch_start_system.rs:152-172` (`get_ika_committee_with_network_metadata`): replace the `match combined { Some(v) => (Some(v.class_groups), Some(v.secp256k1_pvss), …), None => (None, …) }` with the destructure of `DecodedValidatorEncryptionKeys`, which already has the right Option shape on each PVSS field.
- `epoch_start_system.rs:209-225` (`get_ika_committee`): change `filter_map` body to call `decode_validator_encryption_keys`; the resulting `DecodedValidatorEncryptionKeys` already supplies optional PVSS halves. Then the four per-curve HashMap builders (L227-242) push to PVSS maps **only when `Some`** rather than unconditionally — old-shape validators are absent from PVSS HashMaps; class-groups HashMap is fully populated.
- `crates/ika-core/src/sui_connector/sui_syncer.rs:337` (third decode site): replace `bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>` with `decode_validator_encryption_keys`. The `Committee` builder accepts partial PVSS HashMaps per the change in `get_ika_committee` above.

**Delete the wire-incompat warnings** at `epoch_start_system.rs:143-151`, `epoch_start_system.rs:204-205`, and `committee.rs:537-554`'s `⚠️ MAINNET WIRE-FORMAT INCOMPATIBILITY ⚠️` block — they're stale after this item. Replace with a short note pointing at `decode_validator_encryption_keys` as the canonical entry.

### 3. Validator-key ENCODE: gate publication shape by protocol_version

Three write sites under `crates/ika/src/validator_commands.rs` currently emit only the new shape:

- L430-437 (initial validator onboarding via `ika validator generate`).
- L959-973 (epoch MPC-data rotation via `ika validator set-mpc-data`).
- (Verify a third site if any via grep `set_next_epoch_mpc_data_bytes\|ClassGroupsAndPvssKeyPairAndProof::from_seed.*\.validator_encryption_keys_and_proofs`.)

Pattern at each site:

```rust
let mpc_data = VersionedMPCData::V1(MPCDataV1 {
    class_groups_public_key_and_proof: bcs::to_bytes(
        &class_groups_public_key_and_proof.validator_encryption_keys_and_proofs(),
    )?,
});
```

Change to query `current_protocol_version` (fetched via `SuiClient::get_protocol_config()` or already-loaded `ProtocolConfig`) and branch:

```rust
let mpc_data_bytes = if protocol_config.is_network_encryption_key_version_v3() {
    bcs::to_bytes(&keys.validator_encryption_keys_and_proofs())?  // new shape
} else {
    bcs::to_bytes(keys.class_groups.encryption_key_and_proof())?  // old shape
};
let mpc_data = VersionedMPCData::V1(MPCDataV1 {
    class_groups_public_key_and_proof: mpc_data_bytes,
});
```

`keys.class_groups.encryption_key_and_proof()` accessor exists on `ClassGroupsKeyPairAndProof` post-PR-#1707-item-7 split (`crates/dwallet-classgroups-types/src/lib.rs:80`); already pre-emptively shaped for this path.

`is_network_encryption_key_version_v3()` is the new helper from item 4. At first call (before the v5 upgrade activates), the protocol config returns `v == 2` and we publish the old shape — matching mainnet-v1.1.8 binaries exactly. After the v5 upgrade activates, validators that re-run `set-mpc-data` (a routine epoch action) will publish the new shape.

### 4. ProtocolConfig: bump MAX to 5; add version-3 helpers

`crates/ika-protocol-config/src/lib.rs`:

- L19 `const MAX_PROTOCOL_VERSION: u64 = 4;` → `5`.
- L24 add comment: `// Version 5: validator key publication switches from ClassGroupsEncryptionKeyAndProof (mainnet-v1.1.8 shape) to ValidatorEncryptionKeysAndProofs (class-groups + per-curve PVSS HPKE). DKG / Reconfiguration switch to twopc_mpc::decentralized_party::* (PR #1707 upstream).`
- After `is_reconfiguration_message_version_v2` (L318) add:

```rust
pub fn is_network_encryption_key_version_v3(&self) -> bool {
    self.network_encryption_key_version.is_some_and(|v| v == 3)
}
pub fn is_reconfiguration_message_version_v3(&self) -> bool {
    self.reconfiguration_message_version.is_some_and(|v| v == 3)
}
```

- L647 inside the `for cur in 2..=version.0 { match cur { … } }` block, add:

```rust
5 => {
    cfg.network_encryption_key_version = Some(3);
    cfg.reconfiguration_message_version = Some(3);
}
```

- Snapshot fixtures: regenerate the version_5 snapshot via `cargo insta review`.

### 5. Re-allocate the wire-tag enums for DKG/Reconfig output

`crates/dwallet-mpc-types/src/dwallet_mpc.rs:329-346`:

- `VersionedNetworkDkgOutput`: add `V3(MPCPublicOutput)`. Update `as_bytes()` match (L334-340).
- `VersionedDecryptionKeyReconfigurationOutput`: add `V3(MPCPublicOutput)`. Update consumers.

Semantics post-rename (PR #1707 currently wraps new-shape bytes as `V2`; this corrects that):
- `V1` — pre-mainnet (deprecated, never on chain). Keep the existing "no longer supported" error arm.
- `V2` — mainnet-v1.1.8 shape (bytes from `decentralized_party_backward_compatible::dkg::Party::PublicOutput`). Write at `protocol_version ≤ 4`; decode under the bwd-compat Party type.
- `V3` — new shape (bytes from `decentralized_party::dkg::Party::PublicOutput`). Write at `protocol_version ≥ 5`; decode under the main Party type.

Note: per audit §4 the DKG `PublicOutput` bytes are wire-stable across the bump, so a `V2`-tagged blob and a `V3`-tagged blob CAN technically decode under either Party type. The tag is still required because it tells the deserializer which `Party::PublicOutput` Rust type to construct; both have the same byte representation but are distinct nominal types in Rust.

### 6. Network DKG: split advance + public-input by version

`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs`:

**Rename existing** (PR #1707 wired new-shape; rename to `_v3`):

- L257 `advance_network_dkg_v2` → `advance_network_dkg_v3`. Body unchanged except L286 serialize site writes `VersionedNetworkDkgOutput::V3(public_output_value)`.
- L300 `network_dkg_v2_public_input` → `network_dkg_v3_public_input`. Unchanged (4 HashMap args).

**Add new old-shape pair** above the renamed v3 pair (`use twopc_mpc::decentralized_party_backward_compatible::dkg as bwd_compat_dkg;` at file top):

```rust
/// Advances network DKG using the mainnet-v1.1.8-shape decentralized party
/// (`twopc_mpc::decentralized_party_backward_compatible::dkg::Party`). Used when
/// the active `ProtocolConfig` reports `network_encryption_key_version() == 2`.
pub(crate) fn advance_network_dkg_v2(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <bwd_compat_dkg::Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<bwd_compat_dkg::Party as mpc::Party>::Message>,
    decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = Party::<bwd_compat_dkg::Party>::advance_with_guaranteed_output(
        session_id, party_id, access_structure, advance_request,
        Some(decryption_key_per_crt_prime), &public_input, rng,
    );
    // Wrap finalize as VersionedNetworkDkgOutput::V2(...); pattern identical to v3 sibling.
    …
}

pub(crate) fn network_dkg_v2_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, KnowledgeOfDiscreteLogUCProof); MAX_PRIMES],
    >,
) -> DwalletMPCResult<<bwd_compat_dkg::Party as mpc::Party>::PublicInput> {
    bwd_compat_dkg::PublicInput::new(access_structure, encryption_keys_and_proofs_per_crt_prime)
        .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))
}
```

The v2 constructor takes only `access_structure + encryption_keys_and_proofs_per_crt_prime` (no PVSS maps) per `decentralized_party_backward_compatible/dkg.rs:142-186`.

**Decode dispatch** at `get_decryption_key_shares_from_public_output` (L78-94, L102-120): replace the existing `V1(_) => Err("V1 Network keys no longer supported")` arms with real arms that decode `V2` under `bwd_compat_dkg::Party::PublicOutput` and `V3` under `dkg::Party::PublicOutput`. The `V1` arm stays errored (V1 was never on mainnet).

### 7. Network Reconfiguration: split advance + public-input by version

`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/reconfiguration.rs`:

Same pattern as item 6. The current dispatcher at L114-242 calls the new-shape `decentralized_party::reconfiguration::Party::PublicInput::new_from_*` with 3 trailing PVSS HPKE map args. Rename its body to the `_v3_public_input` path; add a sibling `_v2_public_input` that calls `bwd_compat_reconfig::PublicInput::new_from_dkg_output` / `new_from_reconfiguration_output` with NO trailing PVSS args (old-shape ctor signature).

Advance functions:

- Rename existing `advance_network_reconfiguration_v2` (caller at `mpc_computations.rs:1102-1132`) → `advance_network_reconfiguration_v3`. Wraps output as `V3`.
- New `advance_network_reconfiguration_v2` calls `Party::<bwd_compat_reconfig::Party>::advance_with_guaranteed_output`, wraps as `V2`.

Decode dispatch in `network_dkg.rs:102-120` mirrors item 6 for `VersionedDecryptionKeyReconfigurationOutput`.

### 8. Dispatch at session-input + advance call sites

`crates/ika-core/src/dwallet_mpc/mpc_session/input.rs`:

- **DKG public-input dispatch** (L153 in `session_input_from_request`): the active call into `network_dkg_v2_public_input(…)` becomes:

```rust
if protocol_config.is_network_encryption_key_version_v3() {
    network_dkg_v3_public_input(access_structure, class_groups_keys,
        pvss_secp256k1, pvss_ristretto, pvss_secp256r1)?
} else {
    // PVSS maps are unused on the v2 path; the bwd-compat ctor takes only class-groups keys.
    network_dkg_v2_public_input(access_structure, class_groups_keys_per_crt_prime)?
}
```

`protocol_config` is in scope on `DWalletMPCManager` (`mpc_manager.rs:134`); thread to this site if not already reachable.

- **Reconfig public-input dispatch** (L175): branch on `is_reconfiguration_message_version_v3()`. The cross-version reconfig migration (item 9) handles the v2-DKG-output → v3-reconfig case at the dispatcher level.

`crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations.rs`:

- **DKG advance dispatch** (L1087): the current `Party::<dkg::Party>::advance_with_guaranteed_output` becomes a `match` on `is_network_encryption_key_version_v3()`. To avoid threading two parallel `(public_input, advance_request)` types, wrap them at construction time in `enum NetworkDkgAdvanceArgs { V2(…), V3(…) }`; the dispatcher just unwraps.
- **Reconfig advance dispatch** (L1102): same.

**PrivateInput shape**: v3 uses `dkg::PrivateInput { decryption_key_per_crt_prime: ClassGroupsDecryptionKey }`; v2 uses bare `[Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]`. The dispatch enum carries both.

### 9. Cross-version transition arm in Reconfiguration

The existing `reconfiguration.rs:115-167` arm `(VersionedNetworkDkgOutput::V1, VersionedDecryptionKeyReconfigurationOutput::V2)` is a precedent for cross-version reconfig (it handled the pre-mainnet v1→v2 transition). We add a symmetric arm for v2→v3:

- `(VersionedNetworkDkgOutput::V2(dkg_bytes), VersionedDecryptionKeyReconfigurationOutput::V2(reconfig_bytes), protocol_v ≥ 5)` → decode `dkg_bytes` under the bwd-compat DKG `PublicOutput` (or main DKG `PublicOutput` since they're byte-stable per audit §4; reuse the existing `.into()` pattern at L230), call the **new-shape** `decentralized_party::reconfiguration::Party::PublicInput::new_from_reconfiguration_output` with the 3 trailing PVSS HPKE map args from the upcoming committee, write the output as `V3`.

Runs exactly once per network at the v4→v5 upgrade boundary; subsequent reconfigs are pure `(V3, V3)`.

### 10. Tests

`crates/ika-core/src/dwallet_mpc/integration_tests/`:

- **New `validator_key_decode.rs`** (`crates/ika-types/src/committee.rs`'s `mod tests`): round-trip both encodings through `decode_validator_encryption_keys`. Test: old-shape bytes → `class_groups: Some, pvss_*: None`; new-shape bytes → all four `Some`. Negative test: random bytes → `None`. Edge: old-shape bytes with trailing junk → `None` (the trailing-bytes-guard property).
- **New `dwallet_network_dkg_bwd_compat.rs`**: 4-node swarm at protocol_version 4. Validators publish old-shape keys (item 3 publishes old at v≤4). Run network DKG; assert wire bytes deserialize as `bwd_compat_dkg::Party::Message`, finalized output is `VersionedNetworkDkgOutput::V2`, `decrypt_decryption_key_shares` succeeds on every validator.
- **New `network_reconfiguration_bwd_compat.rs`**: same swarm, DKG then reconfig at protocol_v 4. Assert reconfig output is `VersionedDecryptionKeyReconfigurationOutput::V2`.
- **New `network_reconfiguration_v2_to_v3_migration.rs`**: start at protocol_v 4, DKG (publishes `V2` DKG output). Advance the protocol_version to 5 via ProtocolConfig machinery (validators re-publish new-shape keys per item 3). Run reconfig; assert output is `V3` and the new-shape `decentralized_party::reconfiguration::Party::PublicOutput` decodes correctly, and shares re-decrypt cleanly.
- **Existing** `malicious_behavior.rs`, `missing_network_key.rs`, `message_before_event.rs`, `threshold_not_reached.rs`: parameterize the round-count helper (PR #1707's `EXPECTED_NETWORK_DKG_ROUND_COUNT` becomes `_V3_ROUND_COUNT = 7`; add `_V2_ROUND_COUNT = 4`). Each test runs both versions.

### 11. PR-#1707-feedback reconciliation

`/Users/jcscaly/.claude/plans/you-need-to-do-wondrous-origami.md` is the PR #1707 review-feedback plan; commit `396af2647e` already addresses its items. No fields renamed by that plan (`ValidatorMpcKeysByPartyId`, `get_validator_mpc_keys_by_party_id`, the struct-split landing as `ClassGroupsAndPvssKeyPairAndProof`) need re-touching here — this plan layers on top.

The `ClassGroupsAndPvssKeyPairAndProof::class_groups.encryption_key_and_proof()` accessor (item 3 above) is the post-PR-#1707-item-7 accessor; available because PR #1707 review item 7 split the struct.

## Critical files

Modified:

- `Cargo.toml` (workspace root) — item 1: crypto rev pin to `a8fe6c6a`.
- `Cargo.lock`, `sdk/ika-wasm/Cargo.lock` — item 1: relock.
- `crates/ika-types/src/committee.rs` — item 2: `decode_validator_encryption_keys` + `DecodedValidatorEncryptionKeys`; warning surgery.
- `crates/ika-types/src/sui/epoch_start_system.rs` — item 2: rewire both decode sites to `decode_validator_encryption_keys`; PVSS HashMap builders push only when `Some`; warning surgery.
- `crates/ika-core/src/sui_connector/sui_syncer.rs` — item 2: third decode site rewired.
- `crates/ika/src/validator_commands.rs` — item 3: gate publication shape by `is_network_encryption_key_version_v3()` at L430, L959 (and any third site found by grep).
- `crates/ika-protocol-config/src/lib.rs` — item 4: MAX bump, v5 match arm, v3 helpers. Snapshot fixtures regenerated.
- `crates/dwallet-mpc-types/src/dwallet_mpc.rs` — item 5: `V3` variants on both Versioned enums.
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/network_dkg.rs` — item 6 + item 9 decode dispatch.
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations/reconfiguration.rs` — items 7, 9.
- `crates/ika-core/src/dwallet_mpc/crytographic_computation/mpc_computations.rs` — item 8: advance dispatch enum wrap (L1087, L1102).
- `crates/ika-core/src/dwallet_mpc/mpc_session/input.rs` — item 8: public-input dispatch (L153, L175).
- `crates/ika-core/src/dwallet_mpc/integration_tests/utils.rs` — item 10: dual round-count constants.

New:

- `crates/ika-core/src/dwallet_mpc/integration_tests/dwallet_network_dkg_bwd_compat.rs`
- `crates/ika-core/src/dwallet_mpc/integration_tests/network_reconfiguration_bwd_compat.rs`
- `crates/ika-core/src/dwallet_mpc/integration_tests/network_reconfiguration_v2_to_v3_migration.rs`
- `crates/ika-core/src/dwallet_mpc/integration_tests.rs` — register three new modules.
- `mod tests` block in `crates/ika-types/src/committee.rs` for `decode_validator_encryption_keys`.

Existing utilities to reuse:

- `Party::<…>::advance_with_guaranteed_output` (mpc crate) — used by both v2 and v3 advance paths, parameterized by Party.
- `current_tangible_party_id_to_upcoming` (`reconfiguration.rs:246`) — shared by both paths.
- `extract_class_groups_encryption_keys_from_committee` (`reconfiguration.rs`, post-PR-#1707 item 8 rename) — class-groups extraction only; reused under v2 and v3.
- `get_validator_mpc_keys_by_party_id` (`mod.rs`, post-PR-#1707 item 9 rename) — only the v3 path consumes the PVSS halves.
- `EXPECTED_NETWORK_DKG_ROUND_COUNT` (`integration_tests/utils.rs`, from PR #1707 review item 4) — becomes `_V3_ROUND_COUNT`; v2 sibling added.
- `bwd_compat::dkg::PublicInput::new` (`cryptography-private @ a8fe6c6a:2pc-mpc/src/decentralized_party_backward_compatible/dkg.rs:142-186`) — sole v2 DKG public-input constructor.
- `bwd_compat::reconfiguration::PublicInput::new_from_dkg_output` / `new_from_reconfiguration_output` — sole v2 reconfig public-input constructors.
- `ClassGroupsAndPvssKeyPairAndProof::class_groups.encryption_key_and_proof()` (`crates/dwallet-classgroups-types/src/lib.rs:80`, post-PR-#1707 item 7 split) — the old-shape publication payload.

## Verification

1. `cargo fmt --all` + `cargo build --release` clean after item 1 (crypto bump).
2. `cargo build --release` clean after each subsequent item; commit per item.
3. `cargo clippy --all-targets --all-features` clean at end.
4. `cargo test --release -p ika-protocol-config` — snapshot tests pass for v5; v4 snapshot unchanged.
5. `cargo test --release -p ika-types committee::tests::decode_validator_encryption_keys` — round-trip both shapes; negative tests; trailing-bytes guard.
6. `cargo test --release -p ika-core --lib -- --test-threads=1 dwallet_mpc::integration_tests::dwallet_network_dkg_bwd_compat dwallet_mpc::integration_tests::network_reconfiguration_bwd_compat dwallet_mpc::integration_tests::network_reconfiguration_v2_to_v3_migration`.
7. `cargo test --release -p ika-core --lib -- --test-threads=1 dwallet_mpc::integration_tests::{malicious_behavior, missing_network_key, message_before_event, threshold_not_reached}` — both v2 and v3 parameterizations pass; v3 asserts 7 rounds (per PR #1707), v2 asserts 4 rounds.
8. Sanity greps:
   - `grep -rn 'VersionedNetworkDkgOutput::V2\|VersionedNetworkDkgOutput::V3' crates/` — both variants reached.
   - `grep -rn 'decentralized_party_backward_compatible' crates/` — referenced only in network_dkg.rs, reconfiguration.rs, integration tests.
   - `grep -rn 'bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>' crates/` — **zero hits** (all sites go through `decode_validator_encryption_keys`).
   - `grep -rn 'MAINNET WIRE-FORMAT INCOMPATIBILITY' crates/` — zero hits (warning surgery in item 2).
   - `grep -rn 'advance_network_dkg_v2\|advance_network_dkg_v3' crates/` — exactly the renamed pair plus dispatcher in mpc_computations.rs.
9. **Smoke test on a 4-node local swarm at protocol_v 4**: validators publish old-shape keys (item 3 gate); run DKG → reconfig → DKG; all outputs land as `V2`; `decode_validator_encryption_keys` round-trips on every read.
10. **Cross-version interop smoke** (the bug we're preventing): take a mainnet-v1.1.8 binary on 2 nodes + this branch's binary on 2 nodes (all at protocol_v 3-4). The v1.1.8 nodes publish bare `ClassGroupsEncryptionKeyAndProof`; this-branch nodes (at v4, gated by item 3) publish the same shape. All 4 nodes decode each other's `ValidatorInfo`; DKG completes; output is `VersionedNetworkDkgOutput::V2`, byte-identical between v1.1.8-produced and this-branch-produced.
11. **Upgrade smoke**: continue the v4 smoke test by bumping all 4 (this-branch) nodes' protocol_version through the ProtocolConfig upgrade machinery to v5; each validator re-runs `ika validator set-mpc-data` (or the analogous in-test helper); next reconfig produces a `V3` output. v1.1.8 nodes naturally fall out at this point (they can't keep up with v5 and their stake should be slashed / they should upgrade their binary).
12. Commit + push on `dev_backward_compatability` (CLAUDE.md: never push to main/dev). One commit per item ideally.

## What this plan does NOT cover

- ECDSA Sign cross-version interop: out of scope. PR #1707 already wired `SignData::{ToBeEmulated, Unverified, Verified}` locally (`sign.rs:692-721`); user-side wire is just `SignMessage` under `VersionedUserSignedMessage::V1`. Confirmed by user.
- Move-side schema changes: none. The `mpc_data_bytes` field stays opaque `vector<u8>`; the outer `VersionedMPCData::V1(MPCDataV1)` envelope stays put (byte-identical to mainnet-v1.1.8). All dispatch is Rust-side.
- ECDSA Presign, Schnorr-AHE Presign + Sign: wire-stable per audit §4 + §3.6; no code change.
- Validator slashing / removal policy for stuck-on-old-shape validators after the v5 upgrade activates: governance/ops concern, not in scope here. The framework here is "validators who haven't republished new-shape keys at v5 are excluded from PVSS-bearing committees"; what happens next is policy.
- Mid-epoch protocol_version bump: not supported by the existing ProtocolConfig machinery (bumps happen at epoch boundary) and not introduced here.
