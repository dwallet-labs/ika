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

---

## Changes

### 1. `dwallet-mpc-types/src/dwallet_mpc.rs` — Add V2 format

Add `MPCDataV2` and a `V2` variant to the existing enum. The new struct carries
the same class groups field as V1, plus HPKE and PVSS fields (all `Vec<u8>`).

```rust
// --- dwallet-mpc-types/src/dwallet_mpc.rs ---

pub type HpkePublicKeyAndProofBytes = Vec<u8>;
pub type PvssEncryptionKeyAndProofBytes = Vec<u8>;

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct MPCDataV2 {
    pub class_groups_public_key_and_proof: ClassGroupsPublicKeyAndProofBytes,
    pub hpke_public_key_and_proof: HpkePublicKeyAndProofBytes,
    /// One PVSS encryption key+proof per curve (secp256k1, ristretto, secp256r1).
    pub pvss_encryption_keys_and_proofs: Vec<PvssEncryptionKeyAndProofBytes>,
}

#[enum_dispatch(MPCDataTrait)]
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub enum VersionedMPCData {
    V1(MPCDataV1),
    V2(MPCDataV2),
}

// V2 implements the existing trait so all existing code that only needs
// class_groups_public_key_and_proof keeps working without changes.
impl MPCDataTrait for MPCDataV2 {
    fn class_groups_public_key_and_proof(&self) -> ClassGroupsPublicKeyAndProofBytes {
        self.class_groups_public_key_and_proof.clone()
    }
}

// New accessors on VersionedMPCData (not on the trait, since enum_dispatch
// may not support default methods returning None for V1).
impl VersionedMPCData {
    pub fn hpke_public_key_and_proof(&self) -> Option<&HpkePublicKeyAndProofBytes> {
        match self {
            Self::V1(_) => None,
            Self::V2(v2) => Some(&v2.hpke_public_key_and_proof),
        }
    }

    pub fn pvss_encryption_keys_and_proofs(&self) -> Option<&Vec<PvssEncryptionKeyAndProofBytes>> {
        match self {
            Self::V1(_) => None,
            Self::V2(v2) => Some(&v2.pvss_encryption_keys_and_proofs),
        }
    }
}
```

### 2. `dwallet-rng/src/lib.rs` — Add seed derivation for new keys

Add two new derivation methods following the existing `class_groups_decryption_key_seed`
pattern: distinct Merlin transcript labels for domain separation.

```rust
// --- dwallet-rng/src/lib.rs, inside impl RootSeed ---

fn hpke_key_seed(&self) -> [u8; Self::SEED_LENGTH] {
    let mut transcript = Transcript::new(b"HPKE Encryption Key Seed");
    transcript.append_message(b"root seed", &self.0);
    let mut seed = [0u8; Self::SEED_LENGTH];
    transcript.challenge_bytes(b"seed", &mut seed);
    seed
}

fn pvss_encryption_key_seed(&self, curve_index: u8) -> [u8; Self::SEED_LENGTH] {
    let mut transcript = Transcript::new(b"PVSS Encryption Key Seed");
    transcript.append_message(b"root seed", &self.0);
    transcript.append_message(b"curve index", &[curve_index]);
    let mut seed = [0u8; Self::SEED_LENGTH];
    transcript.challenge_bytes(b"seed", &mut seed);
    seed
}

pub fn hpke_key_rng(&self) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(self.hpke_key_seed())
}

pub fn pvss_encryption_key_rng(&self, curve_index: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(self.pvss_encryption_key_seed(curve_index))
}
```

### 3. `dwallet-classgroups-types/src/lib.rs` — Key generation bundle

Add a struct that generates all three key types from a single root seed. The HPKE and
PVSS key generation functions depend on the cryptography-private library upgrade (not
available at ika's current pin `babbb483`), so the exact calls will be filled in when
we bump the dependency. The structure is:

```rust
// --- dwallet-classgroups-types/src/lib.rs ---

/// All cryptographic keys a validator needs, generated deterministically from RootSeed.
pub struct ValidatorCryptoKeys {
    pub class_groups: ClassGroupsKeyPairAndProof,
    /// BCS-serialized HPKE public key + proof of knowledge.
    pub hpke_public_key_and_proof: Vec<u8>,
    /// BCS-serialized PVSS encryption key + proof per curve.
    /// Index 0 = secp256k1, 1 = ristretto, 2 = secp256r1.
    pub pvss_encryption_keys_and_proofs: Vec<Vec<u8>>,
    // Private keys are NOT stored here — they are re-derived from RootSeed
    // at protocol time via hpke_key_rng() / pvss_encryption_key_rng().
}

impl ValidatorCryptoKeys {
    pub fn from_seed(root_seed: &RootSeed) -> Self {
        let class_groups = ClassGroupsKeyPairAndProof::from_seed(root_seed);

        // HPKE key generation (Curve25519-based).
        // Exact API depends on cryptography-private upgrade.
        // Placeholder — will call the HPKE keygen from the upgraded lib:
        let mut hpke_rng = root_seed.hpke_key_rng();
        let hpke_public_key_and_proof = Vec::new(); // TODO: generate_hpke_keypair(&mut hpke_rng)

        // PVSS encryption keys per curve.
        // Each curve gets its own deterministic RNG.
        let pvss_encryption_keys_and_proofs = (0u8..3)
            .map(|curve_index| {
                let mut pvss_rng = root_seed.pvss_encryption_key_rng(curve_index);
                Vec::new() // TODO: generate_pvss_encryption_key(&mut pvss_rng, curve_index)
            })
            .collect();

        ValidatorCryptoKeys {
            class_groups,
            hpke_public_key_and_proof,
            pvss_encryption_keys_and_proofs,
        }
    }
}
```

### 4. `ika-types/src/committee.rs` — Extend Committee

Add two new optional key maps. They're `HashMap` (not every validator will have V2 keys
during the gradual rollout). Add a readiness check.

```rust
// --- ika-types/src/committee.rs ---

// New type aliases (or use the bytes types from dwallet-mpc-types)
pub type HpkeEncryptionKeyAndProof = Vec<u8>;
pub type PvssEncryptionKeyAndProof = Vec<u8>;

#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct Committee {
    pub epoch: EpochId,
    pub voting_rights: Vec<(AuthorityName, StakeUnit)>,
    pub class_groups_public_keys_and_proofs:
        HashMap<AuthorityName, ClassGroupsEncryptionKeyAndProof>,
    // --- NEW FIELDS ---
    pub hpke_public_keys_and_proofs:
        HashMap<AuthorityName, HpkeEncryptionKeyAndProof>,
    pub pvss_encryption_keys_and_proofs:
        HashMap<AuthorityName, Vec<PvssEncryptionKeyAndProof>>,
    // --- END NEW FIELDS ---
    pub quorum_threshold: u64,
    pub validity_threshold: u64,
    expanded_keys: HashMap<AuthorityName, AuthorityPublicKey>,
    index_map: HashMap<AuthorityName, usize>,
}

impl Committee {
    pub fn new(
        epoch: EpochId,
        voting_rights: Vec<(AuthorityName, StakeUnit)>,
        class_groups_public_keys_and_proofs: HashMap<
            AuthorityName,
            ClassGroupsEncryptionKeyAndProof,
        >,
        hpke_public_keys_and_proofs: HashMap<AuthorityName, HpkeEncryptionKeyAndProof>,
        pvss_encryption_keys_and_proofs: HashMap<AuthorityName, Vec<PvssEncryptionKeyAndProof>>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        // ... existing validation ...
        let (expanded_keys, index_map) = Self::load_inner(&voting_rights);
        Committee {
            epoch,
            voting_rights,
            class_groups_public_keys_and_proofs,
            hpke_public_keys_and_proofs,
            pvss_encryption_keys_and_proofs,
            expanded_keys,
            index_map,
            quorum_threshold,
            validity_threshold,
        }
    }

    /// Returns true iff every validator in the committee has published V2 keys
    /// (HPKE + PVSS). Used to gate future protocol upgrades.
    pub fn all_validators_have_v2_keys(&self) -> bool {
        self.voting_rights.iter().all(|(name, _)| {
            self.hpke_public_keys_and_proofs.contains_key(name)
                && self.pvss_encryption_keys_and_proofs.contains_key(name)
        })
    }
}
```

All existing callers of `Committee::new()` (tests, helpers) pass `HashMap::new()` for
the two new parameters — no behavioral change.

### 5. `ika-types/src/sui/epoch_start_system.rs` — Deserialization fallback

**This is where the deserialization fallback logic lives.** The existing
`get_ika_committee()` method (line 170) already handles V1 data. The change adds
extraction of V2 fields when present, and gracefully falls back when they're absent.

```rust
// --- ika-types/src/sui/epoch_start_system.rs, in get_ika_committee() ---

fn get_ika_committee(&self) -> Committee {
    let voting_rights = self
        .active_validators
        .iter()
        .map(|validator| (validator.authority_name(), validator.voting_power))
        .collect();

    // --- Existing: always extract class groups keys (works for both V1 and V2) ---
    let class_groups_public_keys_and_proofs = self
        .active_validators
        .iter()
        .filter_map(|validator| {
            validator.mpc_data.clone().and_then(|mpc_data| {
                // class_groups_public_key_and_proof() is on MPCDataTrait,
                // dispatched by enum_dispatch — works for V1 AND V2.
                match bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(
                    &mpc_data.class_groups_public_key_and_proof(),
                ) {
                    Ok(key) => Some((validator.authority_name(), key)),
                    Err(e) => {
                        error!("Failed to deserialize class groups key: {}", e);
                        None
                    }
                }
            })
        })
        .collect();

    // --- NEW: extract HPKE keys (only present in V2) ---
    let hpke_public_keys_and_proofs = self
        .active_validators
        .iter()
        .filter_map(|validator| {
            validator.mpc_data.as_ref().and_then(|mpc_data| {
                // Returns None for V1 validators → filter_map skips them.
                // Returns Some(&bytes) for V2 validators.
                mpc_data.hpke_public_key_and_proof().map(|bytes| {
                    (validator.authority_name(), bytes.clone())
                })
            })
        })
        .collect();

    // --- NEW: extract PVSS keys (only present in V2) ---
    let pvss_encryption_keys_and_proofs = self
        .active_validators
        .iter()
        .filter_map(|validator| {
            validator.mpc_data.as_ref().and_then(|mpc_data| {
                // Returns None for V1 validators → filter_map skips them.
                mpc_data.pvss_encryption_keys_and_proofs().map(|keys| {
                    (validator.authority_name(), keys.clone())
                })
            })
        })
        .collect();

    Committee::new(
        self.epoch,
        voting_rights,
        class_groups_public_keys_and_proofs,
        hpke_public_keys_and_proofs,          // empty HashMap if no V2 validators
        pvss_encryption_keys_and_proofs,       // empty HashMap if no V2 validators
        self.quorum_threshold,
        self.validity_threshold,
    )
}
```

**Deserialization fallback summary:**
- `VersionedMPCData` is a BCS-serialized enum. BCS encodes enum variants with a
  variant index prefix (0 = V1, 1 = V2).
- A V1-only binary receiving V2 data: BCS deserialization of the `VersionedMPCData`
  enum itself fails (unknown variant index 1). The existing `filter_map` + `and_then`
  pattern in `get_ika_committee()` already handles this — the validator is skipped
  with an error log, same as if `mpc_data` were `None`.
- A V2-capable binary receiving V1 data: BCS deserializes into `VersionedMPCData::V1`
  successfully. The `Option`-returning accessors (`hpke_public_key_and_proof()`,
  `pvss_encryption_keys_and_proofs()`) return `None`, so that validator simply
  doesn't appear in the HPKE/PVSS `HashMap`s. No error, no skip.
- **Net effect during mixed rollout:** all validators' class groups keys work as
  before; HPKE/PVSS maps are progressively populated as validators upgrade.

### 6. `ika/src/validator_commands.rs` — Publish V2 data

Both `MakeValidatorInfo` and `SetNextEpochMPCData` currently construct
`VersionedMPCData::V1`. Change them to construct V2 using `ValidatorCryptoKeys`:

```rust
// --- ika/src/validator_commands.rs ---
// Replace the MakeValidatorInfo block (currently at line 429-435):

let crypto_keys = ValidatorCryptoKeys::from_seed(&root_seed);
let mpc_data = VersionedMPCData::V2(MPCDataV2 {
    class_groups_public_key_and_proof: bcs::to_bytes(
        &crypto_keys.class_groups.encryption_key_and_proof(),
    )?,
    hpke_public_key_and_proof: crypto_keys.hpke_public_key_and_proof,
    pvss_encryption_keys_and_proofs: crypto_keys.pvss_encryption_keys_and_proofs,
});

// Replace the SetNextEpochMPCData block (currently at line 949-956):

let mpc_root_seed = RootSeed::random_seed();
let crypto_keys = ValidatorCryptoKeys::from_seed(&mpc_root_seed);
let mpc_data = VersionedMPCData::V2(MPCDataV2 {
    class_groups_public_key_and_proof: bcs::to_bytes(
        &crypto_keys.class_groups.encryption_key_and_proof(),
    )?,
    hpke_public_key_and_proof: crypto_keys.hpke_public_key_and_proof,
    pvss_encryption_keys_and_proofs: crypto_keys.pvss_encryption_keys_and_proofs,
});
```

Also update `read_or_generate_root_seed` (line 1213) to return `ValidatorCryptoKeys`
instead of `Box<ClassGroupsKeyPairAndProof>`:

```rust
fn read_or_generate_root_seed(seed_path: PathBuf) -> Result<(RootSeed, ValidatorCryptoKeys)> {
    let seed = match RootSeed::from_file(seed_path.clone()) {
        Ok(seed) => {
            println!("Use existing seed: {seed_path:?}.");
            seed
        }
        Err(_) => {
            let seed = RootSeed::random_seed();
            seed.save_to_file(seed_path.clone())?;
            println!("Generated root seed file: {seed_path:?}.");
            seed
        }
    };
    let crypto_keys = ValidatorCryptoKeys::from_seed(&seed);
    Ok((seed, crypto_keys))
}
```

### 7. `ika-core/src/dwallet_mpc/mpc_manager.rs` and `mod.rs` — Surface keys

Add HPKE/PVSS fields to `DWalletMPCManager` and populate from Committee at init.
Add a helper function parallel to `get_validators_class_groups_public_keys_and_proofs`.

```rust
// --- ika-core/src/dwallet_mpc/mod.rs ---

pub(crate) fn get_validators_hpke_public_keys_and_proofs(
    committee: &Committee,
) -> HashMap<PartyID, HpkeEncryptionKeyAndProof> {
    committee
        .voting_rights
        .iter()
        .filter_map(|(name, _)| {
            let party_id = authority_name_to_party_id_from_committee(committee, name).ok()?;
            committee
                .hpke_public_keys_and_proofs
                .get(name)
                .map(|key| (party_id, key.clone()))
        })
        .collect()
}

pub(crate) fn get_validators_pvss_encryption_keys_and_proofs(
    committee: &Committee,
) -> HashMap<PartyID, Vec<PvssEncryptionKeyAndProof>> {
    committee
        .voting_rights
        .iter()
        .filter_map(|(name, _)| {
            let party_id = authority_name_to_party_id_from_committee(committee, name).ok()?;
            committee
                .pvss_encryption_keys_and_proofs
                .get(name)
                .map(|keys| (party_id, keys.clone()))
        })
        .collect()
}
```

```rust
// --- ika-core/src/dwallet_mpc/mpc_manager.rs ---

pub(crate) struct DWalletMPCManager {
    // ... existing fields ...
    pub(crate) validators_class_groups_public_keys_and_proofs:
        HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
    // --- NEW ---
    pub(crate) validators_hpke_public_keys_and_proofs:
        HashMap<PartyID, HpkeEncryptionKeyAndProof>,
    pub(crate) validators_pvss_encryption_keys_and_proofs:
        HashMap<PartyID, Vec<PvssEncryptionKeyAndProof>>,
    /// True when every committee member has published V2 keys.
    pub(crate) all_validators_have_v2_keys: bool,
    // --- END NEW ---
    // ... rest of existing fields ...
}

// In try_new(), after the existing class groups initialization:
//   validators_class_groups_public_keys_and_proofs:
//       get_validators_class_groups_public_keys_and_proofs(&committee)?,
// Add:
//   validators_hpke_public_keys_and_proofs:
//       get_validators_hpke_public_keys_and_proofs(&committee),
//   validators_pvss_encryption_keys_and_proofs:
//       get_validators_pvss_encryption_keys_and_proofs(&committee),
//   all_validators_have_v2_keys: committee.all_validators_have_v2_keys(),
```

---

## Deserialization Fallback — Detailed Walkthrough

The fallback lives in **`epoch_start_system.rs::get_ika_committee()`** (step 5 above).

There are two distinct scenarios during gradual rollout:

### Scenario A: V2-capable node reads V1 validator data

```
On-chain bytes: [0x00, ...V1 payload...]    (BCS variant index 0 = V1)
                 ^^^^
                 BCS enum variant prefix

Deserialization: bcs::from_bytes::<VersionedMPCData>(...) → Ok(VersionedMPCData::V1(MPCDataV1 {...}))

class_groups_public_key_and_proof()  → returns bytes (via MPCDataTrait, works for V1)
hpke_public_key_and_proof()          → returns None  (V1 match arm)
pvss_encryption_keys_and_proofs()    → returns None  (V1 match arm)

Result: validator appears in class_groups map, absent from HPKE/PVSS maps.
        all_validators_have_v2_keys() = false.
```

### Scenario B: V1-only node reads V2 validator data

```
On-chain bytes: [0x01, ...V2 payload...]    (BCS variant index 1 = V2)
                 ^^^^
                 V1-only code doesn't know variant index 1

Deserialization of VersionedMPCData itself fails → the existing filter_map
in get_ika_committee() catches the error (or mpc_data is None for that
validator in the EpochStartValidatorInfoV1 deserialization).

Result: validator is skipped entirely from all key maps.
        Protocols that need this validator's class groups key will be missing it,
        but this is the same behavior as if a validator hasn't published MPC data
        at all — it's already handled.
```

### Scenario C: All validators are V2

```
All validators in hpke/pvss maps.
committee.all_validators_have_v2_keys() = true.
Future protocol version bump can activate VSS/extended-DKG protocols.
```

---

## Key Design Decisions

- **No Move changes** — on-chain storage is opaque `Vec<u8>`, Rust controls versioning
- **Fallback via enum variant dispatch** — V1 data deserializes into the V1 variant;
  `Option`-returning accessors on `VersionedMPCData` return `None` for V1
- **No protocol changes in this step** — old protocols keep running, new keys are unused
- **All private keys re-derivable from root seed** — no new persistence needed
- **`enum_dispatch` caveat** — new accessors are `impl VersionedMPCData` methods (not
  trait methods), because `enum_dispatch` may not support default methods returning `None`

## Verification

1. Build ika with new code — ensure existing tests pass (V1 backward compat)
2. Test V2 key generation: `ValidatorCryptoKeys::from_seed()` produces valid keys
3. Test mixed committee: some validators V1, some V2 — committee constructs without error,
   `all_validators_have_v2_keys()` returns false
4. Test all-V2 committee: `all_validators_have_v2_keys()` returns true
5. Test BCS round-trip: V2 data serializes and deserializes correctly
6. Test V1 binary reading V2 data: deserialization fails gracefully (logged, validator skipped)

## Files to Modify

- `crates/dwallet-mpc-types/src/dwallet_mpc.rs`
- `crates/dwallet-rng/src/lib.rs`
- `crates/dwallet-classgroups-types/src/lib.rs`
- `crates/ika-types/src/committee.rs`
- `crates/ika-types/src/sui/epoch_start_system.rs`
- `crates/ika/src/validator_commands.rs`
- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs`
- `crates/ika-core/src/dwallet_mpc/mod.rs`
