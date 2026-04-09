# Plan: Broadcast Validator Encryption Keys via Consensus

## Context

The cryptography-private library upgrade requires validators to have HPKE encryption
keys (Curve25519) and PVSS encryption keys per curve, in addition to the existing
class groups keys. These are needed for the extended 7-round DKG and VSS protocols.

## Design

Instead of stuffing new keys into the existing on-chain `mpc_data_bytes` path (which
is a generic `TableVec<vector<u8>>` used for many purposes), validators broadcast a
new `ValidatorPublicMPCData` message via Mysticeti consensus at epoch start.

**Why consensus broadcast, not on-chain storage:**
- A protocol version bump requires all validators to upgrade their binary.
- The new binary broadcasts `ValidatorPublicMPCData`; old binaries can't.
- Therefore every validator in the committee has the new keys — no mixed V1/V2
  committees, no fallback deserialization, no `Option` fields.

## Changes

### 1. Define `ValidatorPublicMPCData`

**File:** `crates/dwallet-mpc-types/src/dwallet_mpc.rs`

A flat struct — no versioned enum needed, since the protocol version bump guarantees
all validators are on the new binary.

```rust
use serde::{Deserialize, Serialize};

/// All public encryption keys and proofs a validator broadcasts at epoch start.
/// Every validator in the committee must broadcast this before MPC sessions begin.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ValidatorPublicMPCData {
    /// BCS-serialized ClassGroupsEncryptionKeyAndProof.
    pub class_groups_public_key_and_proof: Vec<u8>,
    /// BCS-serialized HPKE (Curve25519) public key and proof of knowledge.
    pub hpke_public_key_and_proof: Vec<u8>,
    /// BCS-serialized PVSS encryption key and proof, one per curve.
    /// Index: 0 = secp256k1, 1 = ristretto, 2 = secp256r1.
    pub pvss_encryption_keys_and_proofs: Vec<Vec<u8>>,
}
```

### 2. Add consensus message variant

**File:** `crates/ika-types/src/messages_consensus.rs`

Add a new variant to `ConsensusTransactionKind` and its key:

```rust
// In ConsensusTransactionKind enum (line 172):
pub enum ConsensusTransactionKind {
    DWalletCheckpointSignature(Box<DWalletCheckpointSignatureMessage>),
    SystemCheckpointSignature(Box<SystemCheckpointSignatureMessage>),
    CapabilityNotificationV1(AuthorityCapabilitiesV1),
    EndOfPublish(AuthorityName),
    DWalletMPCMessage(DWalletMPCMessage),
    DWalletMPCOutput(DWalletMPCOutput),
    ValidatorPublicMPCData(AuthorityName, ValidatorPublicMPCData),  // NEW
}

// In ConsensusTransactionKey enum (line 45):
pub enum ConsensusTransactionKey {
    // ... existing variants ...
    ValidatorPublicMPCData(AuthorityName),  // NEW — one per validator per epoch
}
```

Add factory method:

```rust
// In impl ConsensusTransaction:
pub fn new_validator_public_mpc_data(
    authority: AuthorityName,
    data: ValidatorPublicMPCData,
) -> Self {
    let mut hasher = DefaultHasher::new();
    authority.hash(&mut hasher);
    let tracking_id = hasher.finish().to_le_bytes();
    Self {
        tracking_id,
        kind: ConsensusTransactionKind::ValidatorPublicMPCData(authority, data),
    }
}
```

### 3. Broadcast at epoch start

**File:** `crates/ika-core/src/dwallet_mpc/dwallet_mpc_service.rs` (or a new sender
analogous to `EndOfPublishSender`)

At epoch start, after the `DWalletMPCManager` is initialized, each validator generates
its keys from the root seed and submits the consensus message:

```rust
// Generate all keys from root seed (same seed already used for class groups).
let class_groups = ClassGroupsKeyPairAndProof::from_seed(&root_seed);
let data = ValidatorPublicMPCData {
    class_groups_public_key_and_proof: bcs::to_bytes(
        &class_groups.encryption_key_and_proof(),
    )?,
    hpke_public_key_and_proof: todo!("generate from root_seed.hpke_key_rng()"),
    pvss_encryption_keys_and_proofs: todo!("generate per curve from root_seed.pvss_encryption_key_rng(i)"),
};

let tx = ConsensusTransaction::new_validator_public_mpc_data(self.name, data);
consensus_adapter.submit_to_consensus(&[tx], &epoch_store).await?;
```

### 4. Handle incoming broadcasts

**File:** `crates/ika-core/src/authority/authority_per_epoch_store.rs`

Add a match arm in `process_consensus_transactions_and_commit_boundary` (line 1340)
to collect `ValidatorPublicMPCData` from each validator:

```rust
SequencedConsensusTransactionKind::External(ConsensusTransaction {
    kind: ConsensusTransactionKind::ValidatorPublicMPCData(authority, data),
    ..
}) => {
    self.record_validator_public_mpc_data(authority, data)?;
    Ok(ConsensusCertificateResult::ConsensusMessage)
}
```

`record_validator_public_mpc_data` stores the data in a map on the epoch store
(or directly on the MPC manager). Once all committee members have submitted,
the MPC manager can begin sessions.

### 5. Wire into `DWalletMPCManager`

**File:** `crates/ika-core/src/dwallet_mpc/mpc_manager.rs`

Add storage for the received keys and a readiness gate:

```rust
pub(crate) struct DWalletMPCManager {
    // ... existing fields ...

    /// Public MPC data received from each validator via consensus.
    /// Populated as ValidatorPublicMPCData messages arrive.
    pub(crate) validators_public_mpc_data: HashMap<PartyID, ValidatorPublicMPCData>,

    // ... rest of existing fields ...
}
```

Add a method to record incoming data and check readiness:

```rust
impl DWalletMPCManager {
    pub fn record_validator_public_mpc_data(
        &mut self,
        authority: &AuthorityName,
        data: &ValidatorPublicMPCData,
    ) -> DwalletMPCResult<()> {
        let party_id = authority_name_to_party_id_from_committee(&self.committee, authority)?;
        self.validators_public_mpc_data.insert(party_id, data.clone());
        Ok(())
    }

    pub fn all_validators_submitted_public_mpc_data(&self) -> bool {
        self.committee
            .voting_rights
            .iter()
            .all(|(name, _)| {
                authority_name_to_party_id_from_committee(&self.committee, name)
                    .map(|pid| self.validators_public_mpc_data.contains_key(&pid))
                    .unwrap_or(false)
            })
    }
}
```

### 6. Add seed derivation for new keys

**File:** `crates/dwallet-rng/src/lib.rs`

Same as before — add `hpke_key_rng()` and `pvss_encryption_key_rng(curve_index)`
to `RootSeed` using distinct Merlin transcript labels:

```rust
// In impl RootSeed:

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

### 7. Update metrics and validation

**File:** `crates/ika-core/src/consensus_handler.rs`

Add to `classify` (line 429):

```rust
ConsensusTransactionKind::ValidatorPublicMPCData(..) => "validator_public_mpc_data",
```

**File:** `crates/ika-core/src/consensus_validator.rs`

Add to the `validate_transactions` match (line 72) — no special validation needed
beyond what consensus provides (the authority is authenticated by consensus):

```rust
ConsensusTransactionKind::ValidatorPublicMPCData(..) => {}
```

## What stays unchanged

- **Move contracts** — `mpc_data_bytes` on-chain path is untouched
- **`VersionedMPCData`** — stays as-is, used for other MPC data
- **`Committee` struct** — no new fields; keys live on `DWalletMPCManager` instead
- **`validator_commands.rs`** — the on-chain MPC data path stays as V1; the consensus
  broadcast handles the new keys separately
- **`epoch_start_system.rs`** — existing class groups deserialization from on-chain
  can eventually be removed once the consensus path is fully active, but not in this PR

## Open questions

1. **Should MPC sessions block until all validators have submitted?** Or proceed with
   a quorum threshold? Currently the manager starts sessions based on the committee;
   we'd need a gate that waits for `all_validators_submitted_public_mpc_data()`.

2. **Crypto dependency bump** — the HPKE and PVSS keygen APIs don't exist at ika's
   current pin (`babbb483`). This work needs to happen in parallel or first.

## Files to modify

- `crates/dwallet-mpc-types/src/dwallet_mpc.rs` — add `ValidatorPublicMPCData` struct
- `crates/dwallet-rng/src/lib.rs` — add HPKE/PVSS seed derivation
- `crates/ika-types/src/messages_consensus.rs` — add consensus variant + factory
- `crates/ika-core/src/consensus_handler.rs` — add to `classify`
- `crates/ika-core/src/consensus_validator.rs` — add to validation match
- `crates/ika-core/src/authority/authority_per_epoch_store.rs` — add handler
- `crates/ika-core/src/dwallet_mpc/mpc_manager.rs` — add storage + readiness gate
- `crates/ika-core/src/dwallet_mpc/dwallet_mpc_service.rs` — broadcast at epoch start
