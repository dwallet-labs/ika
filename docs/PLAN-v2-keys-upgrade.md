# Plan: Add HPKE + PVSS Encryption Keys to ika Validators (Stage 1)

## Context

The cryptography-private library is adding VSS protocols and extended 7-round DKG
that require validators to have HPKE encryption keys (Curve25519) and PVSS encryption
keys per curve (class groups elements). This is the prerequisite key distribution step —
no protocol changes yet, just getting the keys on-chain so a future protocol version
bump can use them.

The on-chain storage is opaque `vector<u8>` in Move, and the Rust side already has
`VersionedMPCData::V1`. No Move contract changes needed.

**Rollout sequence:**
1. Ship code that reads both V1 and V2 MPC data
2. Validators upgrade software at their own pace
3. Upgraded validators publish V2 keys (class groups + HPKE + PVSS) at next epoch
4. Non-upgraded validators still publish V1 (class groups only) — no errors
5. Once all committee members have V2 keys, future protocol upgrade can activate

## Changes

### 1. `dwallet-mpc-types/src/dwallet_mpc.rs` — Add V2 format

Add `MPCDataV2` with the existing class groups field plus HPKE and PVSS fields
(all as `Vec<u8>` — BCS-serialized opaque bytes). Add `V2(MPCDataV2)` variant to
`VersionedMPCData`. Add accessor methods on `VersionedMPCData` returning `Option`
for the new fields (`None` for V1, `Some` for V2).

### 2. `dwallet-rng/src/lib.rs` — Add seed derivation for new keys

Add `hpke_key_rng()` and `pvss_encryption_key_rng(curve_index)` to `RootSeed`,
using distinct Merlin transcript labels for domain separation.

### 3. `dwallet-classgroups-types/src/lib.rs` — Generate new keys

Add `ValidatorCryptoKeys` struct and `from_seed()` that generates class groups
keys (existing), HPKE keypair, and PVSS keypairs per curve — all from the root seed.

### 4. `ika-types/src/committee.rs` — Extend Committee

Add `hpke_public_keys_and_proofs: HashMap<AuthorityName, HpkeEncryptionKeyAndProof>`
and `pvss_encryption_keys_and_proofs: HashMap<AuthorityName, [PvssEncryptionKeyAndProof; 4]>`
to `Committee`. Add `all_validators_have_v2_keys()` method. Update `Committee::new()`
signature. Update test helpers to pass empty maps.

### 5. `ika-types/src/sui/epoch_start_system.rs` — Parse V2 keys

In `get_ika_committee()`, after deserializing class groups keys (existing),
check for HPKE and PVSS bytes via the `Option` accessors. Deserialize if present,
skip gracefully if not. Pass all three maps to `Committee::new()`.

### 6. `ika/src/validator_commands.rs` — Publish V2 data

In `MakeValidatorInfo` and `SetNextEpochMPCData`, generate `ValidatorCryptoKeys`
from root seed, construct `VersionedMPCData::V2(MPCDataV2 { ... })`, publish.

### 7. `ika-core/src/dwallet_mpc/mpc_manager.rs` and `mod.rs` — Surface keys

Add `validators_hpke_public_keys_and_proofs` and
`validators_pvss_encryption_keys_and_proofs` to `DWalletMPCManager`.
Add `all_validators_have_v2_keys` flag. Populate at init from Committee.

## Key design decisions

- **No Move changes** — on-chain storage is opaque `Vec<u8>`, Rust controls versioning
- **Fallback deserialization** — V1 validators' data still parses fine; new fields are `Option`
- **No protocol changes in this step** — old protocols keep running, new keys are unused
- **All private keys re-derivable from root seed** — no new persistence needed
- **`enum_dispatch` caveat** — add accessors directly on `VersionedMPCData` impl block
  rather than default trait methods, since `enum_dispatch` may not support defaults

## Verification

1. Build ika with new code — ensure existing tests pass (V1 backward compat)
2. Test V2 key generation: `ValidatorCryptoKeys::from_seed()` produces valid keys
3. Test mixed committee: some validators V1, some V2 — committee constructs without error,
   `all_validators_have_v2_keys()` returns false
4. Test all-V2 committee: `all_validators_have_v2_keys()` returns true
5. Test BCS round-trip: V2 data serializes and deserializes correctly
6. Test V1 binary reading V2 data: deserialization fails gracefully (logged, validator skipped)

## Files to modify

- `/mnt/nvme0n1p1/ika/crates/dwallet-mpc-types/src/dwallet_mpc.rs`
- `/mnt/nvme0n1p1/ika/crates/dwallet-rng/src/lib.rs`
- `/mnt/nvme0n1p1/ika/crates/dwallet-classgroups-types/src/lib.rs`
- `/mnt/nvme0n1p1/ika/crates/ika-types/src/committee.rs`
- `/mnt/nvme0n1p1/ika/crates/ika-types/src/sui/epoch_start_system.rs`
- `/mnt/nvme0n1p1/ika/crates/ika/src/validator_commands.rs`
- `/mnt/nvme0n1p1/ika/crates/ika-core/src/dwallet_mpc/mpc_manager.rs`
- `/mnt/nvme0n1p1/ika/crates/ika-core/src/dwallet_mpc/mod.rs`
