// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{Element, ExtendedField, SystemInnerTrait};
use crate::committee::StakeUnit;
use crate::crypto::{AuthorityPublicKey, AuthorityPublicKeyBytes};
use fastcrypto::error::FastCryptoError;
use fastcrypto::traits::ToFromBytes;
use serde::{Deserialize, Serialize};
use sui_types::balance::Balance;
use sui_types::base_types::ObjectID;
use sui_types::coin::TreasuryCap;
use sui_types::collection_types::{Bag, Table, VecMap, VecSet};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct BlsCommitteeMember {
    pub validator_id: ObjectID,
    pub protocol_pubkey: Element,
}

impl BlsCommitteeMember {
    /// Parses this member's BLS protocol public key as recorded in the frozen
    /// on-chain committee.
    ///
    /// This — not the validator's `ValidatorInfo` record — is the key the
    /// committee is verified against for the epoch it serves. The committee is
    /// snapshotted mid-epoch from whatever key was current then, while
    /// `rotate_next_epoch_info` installs a staged rotation into the validator
    /// record at the epoch boundary, so for a validator that rotated its
    /// protocol key the two disagree for that whole epoch. The chain's frozen
    /// committee is the authority, so every reader must derive the verification
    /// basis from here.
    pub fn parsed_protocol_pubkey(&self) -> Result<AuthorityPublicKey, FastCryptoError> {
        AuthorityPublicKey::from_bytes(self.protocol_pubkey.bytes.as_ref())
    }
}

/// Represents the current committee in the system.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct BlsCommittee {
    pub members: Vec<BlsCommitteeMember>,
    pub aggregated_protocol_pubkey: Element,
    pub quorum_threshold: u64,
    pub validity_threshold: u64,
}

pub type ObjectTable = Table;

/// Rust version of the Move ika_system::validator_set::ValidatorSet type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorSetV1 {
    pub total_stake: u64,
    pub reward_slashing_rate: u16,
    pub validators: ObjectTable, // This now holds StakingPool objects
    pub active_committee: BlsCommittee,
    pub next_epoch_committee: Option<BlsCommittee>,
    pub previous_committee: BlsCommittee,
    pub pending_active_set: ExtendedField,
    pub validator_report_records: VecMap<ObjectID, VecSet<ObjectID>>,
    pub extra_fields: Bag,
}

/// Rust version of the Move sui::package::UpgradeCap.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct UpgradeCap {
    pub id: ObjectID,
    pub package: ObjectID,
    pub version: u64,
    pub policy: u8,
}
/// Rust version of the Move ika_common::system_object_cap::SystemObjectCap.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SystemObjectCap {
    pub id: ObjectID,
}

/// Rust version of the Move ika::ika_system::SystemInner type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SystemInnerV1 {
    pub epoch: u64,
    pub epoch_start_tx_digest: Vec<u8>,
    pub system_object_cap: SystemObjectCap,
    pub protocol_version: u64,
    pub next_protocol_version: Option<u64>,
    pub upgrade_caps: Vec<UpgradeCap>,
    pub approved_upgrades: VecMap<ObjectID, Vec<u8>>,
    pub validator_set: ValidatorSetV1,
    pub epoch_duration_ms: u64,
    pub stake_subsidy_start_epoch: u64,
    pub protocol_treasury: ProtocolTreasuryV1,
    pub epoch_start_timestamp_ms: u64,
    pub last_processed_checkpoint_sequence_number: u64,
    pub previous_epoch_last_checkpoint_sequence_number: u64,
    pub total_messages_processed: u64,
    pub remaining_rewards: Balance,
    pub authorized_protocol_cap_ids: Vec<ObjectID>,
    pub witness_approving_advance_epoch: Vec<String>,
    pub received_end_of_publish: bool,
    pub extra_fields: Bag,
    // TODO: Use getters instead of all pub.
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfo {
    pub pricing_map: VecMap<PricingInfoKey, PricingInfoValue>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoKey {
    pub curve: u32,
    pub signature_algorithm: Option<u32>,
    pub protocol: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoValue {
    pub fee_ika: u64,
    pub gas_fee_reimbursement_sui: u64,
    pub gas_fee_reimbursement_sui_for_system_calls: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoCalculationVotes {
    pub bls_committee: BlsCommittee,
    pub default_pricing: PricingInfo,
    pub working_pricing: PricingInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SessionsKeeper {
    pub sessions: ObjectTable,
    pub session_events: Bag,
    pub started_sessions_count: u64,
    pub completed_sessions_count: u64,
    pub next_session_sequence_number: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SessionsManager {
    pub registered_user_session_identifiers: Table,
    pub user_sessions_keeper: SessionsKeeper,
    pub system_sessions_keeper: SessionsKeeper,
    pub last_user_initiated_session_to_complete_in_current_epoch: u64,
    pub locked_last_user_initiated_session_to_complete_in_current_epoch: bool,
    pub max_active_sessions_buffer: u64,
}

impl SessionsManager {
    /// Rust mirror of the on-chain `sessions_manager::all_current_epoch_sessions_completed`
    /// assertion gating `advance_epoch`: the user-completion target must be locked,
    /// the locked batch of user sessions must be fully completed, and every system
    /// session (network-key DKG/reconfiguration) must have finished. The notifier
    /// checks this against the just-synced state before submitting `advance_epoch`,
    /// so a transient "still draining" window never becomes a doomed transaction.
    pub fn all_current_epoch_sessions_completed(&self) -> bool {
        let user_sessions_completed = self.user_sessions_keeper.completed_sessions_count
            == self.last_user_initiated_session_to_complete_in_current_epoch;
        let system_sessions_completed = self.system_sessions_keeper.started_sessions_count
            == self.system_sessions_keeper.completed_sessions_count;
        self.locked_last_user_initiated_session_to_complete_in_current_epoch
            && user_sessions_completed
            && system_sessions_completed
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SupportConfig {
    pub supported_curves_to_signature_algorithms_to_hash_schemes:
        VecMap<u32, VecMap<u32, Vec<u32>>>,
    pub paused_curves: Vec<u32>,
    pub paused_signature_algorithms: Vec<u32>,
    pub paused_hash_schemes: Vec<u32>,
    pub signature_algorithms_allowed_global_presign: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingAndFeeManagement {
    pub current: PricingInfo,
    pub default: PricingInfo,
    pub validator_votes: Table,
    pub calculation_votes: Option<PricingInfoCalculationVotes>,
    pub gas_fee_reimbursement_sui_system_call_value: u64,
    pub gas_fee_reimbursement_sui_system_call_balance: Balance,
    pub fee_charged_ika: Balance,
}

/// Rust version of the Move DWalletCoordinatorInner type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct DWalletCoordinatorInnerV1 {
    pub current_epoch: u64,
    pub sessions_manager: SessionsManager,
    pub dwallets: ObjectTable,
    pub dwallet_network_encryption_keys: ObjectTable,
    pub epoch_dwallet_network_encryption_keys_reconfiguration_completed: u64,
    pub encryption_keys: ObjectTable,
    pub presigns: ObjectTable,
    pub partial_centralized_signed_messages: ObjectTable,
    pub pricing_and_fee_management: PricingAndFeeManagement,
    pub active_committee: BlsCommittee,
    pub next_epoch_active_committee: Option<BlsCommittee>,
    pub total_messages_processed: u64,
    pub last_processed_checkpoint_sequence_number: u64,
    pub previous_epoch_last_checkpoint_sequence_number: u64,
    pub support_config: SupportConfig,
    pub received_end_of_publish: bool,
    pub extra_fields: Bag,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ProtocolTreasuryV1 {
    /// TreasuryCap of IKA tokens.
    pub treasury_cap: TreasuryCap,

    /// Count of the number of times stake subsidies have been distributed.
    pub stake_subsidy_distribution_counter: u64,

    /// The rate at which the amount per distribution is calculated based on
    /// period nad total supply. Expressed in basis points.
    pub stake_subsidy_rate: u16,

    /// The amount of stake subsidy to be destructured per distribution.
    /// This amount changes based on `stake_subsidy_rate`.
    pub stake_subsidy_amount_per_distribution: u64,

    /// Number of distributions to occur before the amount per distribution will be recalculated.
    pub stake_subsidy_period_length: u64,

    /// The total supply of IKA tokens at the start of the current period.
    pub total_supply_at_period_start: u64,

    /// Any extra fields that's not defined statically.
    pub extra_fields: Bag,
}

impl SystemInnerTrait for SystemInnerV1 {
    fn epoch(&self) -> u64 {
        self.epoch
    }
    fn epoch_start_tx_digest(&self) -> Vec<u8> {
        self.epoch_start_tx_digest.clone()
    }
    fn protocol_version(&self) -> u64 {
        self.protocol_version
    }

    fn next_protocol_version(&self) -> Option<u64> {
        self.next_protocol_version
    }

    fn last_processed_checkpoint_sequence_number(&self) -> u64 {
        self.last_processed_checkpoint_sequence_number
    }

    fn previous_epoch_last_checkpoint_sequence_number(&self) -> u64 {
        self.previous_epoch_last_checkpoint_sequence_number
    }

    fn upgrade_caps(&self) -> &Vec<UpgradeCap> {
        &self.upgrade_caps
    }

    fn epoch_start_timestamp_ms(&self) -> u64 {
        self.epoch_start_timestamp_ms
    }

    fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    fn get_ika_next_epoch_committee(&self) -> Option<BlsCommittee> {
        self.validator_set.next_epoch_committee.clone()
    }

    fn get_ika_active_committee(&self) -> BlsCommittee {
        self.validator_set.active_committee.clone()
    }

    fn read_bls_committee(
        &self,
        bls_committee: &BlsCommittee,
    ) -> Vec<(ObjectID, (AuthorityPublicKeyBytes, StakeUnit))> {
        bls_committee
            .members
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    (
                        // The on-chain committee carries BLS protocol keys, not
                        // committee identities: an `AuthorityName` is the Ed25519
                        // consensus key, which is NOT on `BlsCommittee`. Callers
                        // re-key by validator id (`rekey_committee_to_consensus_names`).
                        // Registration validates these bytes, so the parse is safe.
                        (&AuthorityPublicKey::from_bytes(v.protocol_pubkey.clone().bytes.as_ref())
                            .unwrap())
                            .into(),
                        1,
                    ),
                )
            })
            .collect()
    }

    fn read_bls_committee_lossy(
        &self,
        bls_committee: &BlsCommittee,
    ) -> Vec<(ObjectID, (AuthorityPublicKeyBytes, StakeUnit))> {
        bls_committee
            .members
            .iter()
            .filter_map(|v| {
                match AuthorityPublicKey::from_bytes(v.protocol_pubkey.bytes.as_ref()) {
                    Ok(pubkey) => Some((v.validator_id, ((&pubkey).into(), 1))),
                    // A prior-committee member with an unparseable protocol
                    // pubkey is dropped, not fatal — panicking here would
                    // crash-loop a bootstrapping validator on a chain-record
                    // fault it cannot fix. BUT the drop is NOT graceful
                    // degradation: the member is absent from the built
                    // committee's `voting_rights` (weight 0), and handoff-cert
                    // verification HARD-REJECTS a certificate carrying a
                    // signature from a weight-0 signer ("signer is not a
                    // member of the verifying committee"). Since the member's
                    // node runs fine (its local keys are intact) and its
                    // signature lands in every aggregated cert, every served
                    // cert then fails verification — surfacing as
                    // `BootstrapOutcome::Rejected`. An operator seeing
                    // Rejected together with this log line should suspect a
                    // corrupt prior-committee record, not wrong peers.
                    Err(_) => None,
                }
            })
            .collect()
    }

    fn validator_set(&self) -> &ValidatorSetV1 {
        &self.validator_set
    }
}

/// Rust version of the Move ika_system::validator_cap::ValidatorCap type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorCapV1 {
    pub id: ObjectID,
    pub validator_id: ObjectID,
}

/// Rust version of the Move ika_system::validator_cap::ValidatorOperationCap type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorOperationCapV1 {
    pub id: ObjectID,
    pub validator_id: ObjectID,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keeper(started: u64, completed: u64) -> SessionsKeeper {
        SessionsKeeper {
            sessions: Table::default(),
            session_events: Bag::default(),
            started_sessions_count: started,
            completed_sessions_count: completed,
            next_session_sequence_number: started,
        }
    }

    fn sessions_manager(
        locked: bool,
        user_completed: u64,
        user_target: u64,
        system_started: u64,
        system_completed: u64,
    ) -> SessionsManager {
        SessionsManager {
            registered_user_session_identifiers: Table::default(),
            user_sessions_keeper: keeper(user_target, user_completed),
            system_sessions_keeper: keeper(system_started, system_completed),
            last_user_initiated_session_to_complete_in_current_epoch: user_target,
            locked_last_user_initiated_session_to_complete_in_current_epoch: locked,
            max_active_sessions_buffer: 100,
        }
    }

    #[test]
    fn all_current_epoch_sessions_completed_truth_table() {
        // Locked, all user + system sessions completed → ready to advance.
        assert!(sessions_manager(true, 10, 10, 3, 3).all_current_epoch_sessions_completed());

        // Not locked → never ready, even if every count lines up.
        assert!(!sessions_manager(false, 10, 10, 3, 3).all_current_epoch_sessions_completed());

        // A user session in the locked batch is still pending.
        assert!(!sessions_manager(true, 9, 10, 3, 3).all_current_epoch_sessions_completed());

        // A system session started after end-of-publish but not yet completed:
        // exactly the transient that made `advance_epoch` MoveAbort with code 6.
        assert!(!sessions_manager(true, 10, 10, 4, 3).all_current_epoch_sessions_completed());

        // No sessions at all in a freshly-locked epoch → trivially ready.
        assert!(sessions_manager(true, 0, 0, 0, 0).all_current_epoch_sessions_completed());
    }

    // === Layout pins for the untagged chain mirrors ===
    //
    // `DWalletCoordinatorInnerV1` and `SystemInnerV1` carry no version tag: their
    // field order IS the wire format of bytes a deployed Move package already
    // wrote, and nothing in those bytes identifies the layout that produced them
    // (`crate::chain_mirror`). Changing either struct does not fail closed
    // anywhere — it silently re-interprets live chain state.
    //
    // Two things pin them, and the cheaper one is the struct literal itself:
    // every field is written out, with no `..Default::default()`, so adding or
    // removing a Rust field fails to COMPILE here. The digest assertion covers
    // what compilation cannot see — a reorder or a retype — which is why every
    // field gets a distinct value: with zeroes everywhere, swapping two `u64`s
    // would encode identically and slip through.
    //
    // These are the Rust half of the guard. The Move half is
    // `scripts/check-chain-mirror-layout.sh`, and the two must be updated in the
    // same change, because either side moving alone is exactly the drift.
    // Rationale and the update procedure: dev-docs/conventions/chain-mirror-layout.md.

    use crate::chain_mirror::test_support::assert_pinned_layout;
    use crate::chain_mirror::{DWALLET_COORDINATOR_INNER_V1, SYSTEM_INNER_V1};
    use sui_types::balance::Supply;
    use sui_types::collection_types::Entry;
    use sui_types::id::UID;

    /// A distinct 32-byte id per seed, so a reordered pair of `ObjectID` fields
    /// changes the encoding.
    fn oid(seed: u8) -> ObjectID {
        ObjectID::new([seed; 32])
    }

    fn table(seed: u8) -> Table {
        Table {
            id: oid(seed),
            size: u64::from(seed),
        }
    }

    fn bag(seed: u8) -> Bag {
        Bag {
            id: UID::new(oid(seed)),
            size: u64::from(seed),
        }
    }

    fn element(seed: u8) -> Element {
        Element {
            bytes: vec![seed, seed.wrapping_add(1)],
        }
    }

    fn bls_committee(seed: u8) -> BlsCommittee {
        BlsCommittee {
            members: vec![BlsCommitteeMember {
                validator_id: oid(seed),
                protocol_pubkey: element(seed.wrapping_add(1)),
            }],
            aggregated_protocol_pubkey: element(seed.wrapping_add(2)),
            quorum_threshold: u64::from(seed) + 300,
            validity_threshold: u64::from(seed) + 400,
        }
    }

    fn pricing_info(seed: u8) -> PricingInfo {
        PricingInfo {
            pricing_map: VecMap {
                contents: vec![Entry {
                    key: PricingInfoKey {
                        curve: u32::from(seed) + 1,
                        signature_algorithm: Some(u32::from(seed) + 2),
                        protocol: u32::from(seed) + 3,
                    },
                    value: PricingInfoValue {
                        fee_ika: u64::from(seed) + 4,
                        gas_fee_reimbursement_sui: u64::from(seed) + 5,
                        gas_fee_reimbursement_sui_for_system_calls: u64::from(seed) + 6,
                    },
                }],
            },
        }
    }

    fn sessions_keeper_populated(seed: u8) -> SessionsKeeper {
        SessionsKeeper {
            sessions: table(seed),
            session_events: bag(seed.wrapping_add(1)),
            started_sessions_count: u64::from(seed) + 10,
            completed_sessions_count: u64::from(seed) + 20,
            next_session_sequence_number: u64::from(seed) + 30,
        }
    }

    /// A fully-populated coordinator inner: every field distinct, every
    /// collection non-empty, every `Option` `Some`. An empty `Vec` or a `None`
    /// hides the shape of what it contains, and the shape of what it contains is
    /// what is being pinned.
    fn populated_coordinator_inner() -> DWalletCoordinatorInnerV1 {
        DWalletCoordinatorInnerV1 {
            current_epoch: 1,
            sessions_manager: SessionsManager {
                registered_user_session_identifiers: table(2),
                user_sessions_keeper: sessions_keeper_populated(3),
                system_sessions_keeper: sessions_keeper_populated(5),
                last_user_initiated_session_to_complete_in_current_epoch: 7,
                locked_last_user_initiated_session_to_complete_in_current_epoch: true,
                max_active_sessions_buffer: 8,
            },
            dwallets: table(9),
            dwallet_network_encryption_keys: table(10),
            epoch_dwallet_network_encryption_keys_reconfiguration_completed: 11,
            encryption_keys: table(12),
            presigns: table(13),
            partial_centralized_signed_messages: table(14),
            pricing_and_fee_management: PricingAndFeeManagement {
                current: pricing_info(15),
                default: pricing_info(16),
                validator_votes: table(17),
                calculation_votes: Some(PricingInfoCalculationVotes {
                    bls_committee: bls_committee(18),
                    default_pricing: pricing_info(21),
                    working_pricing: pricing_info(22),
                }),
                gas_fee_reimbursement_sui_system_call_value: 23,
                gas_fee_reimbursement_sui_system_call_balance: Balance::new(24),
                fee_charged_ika: Balance::new(25),
            },
            active_committee: bls_committee(26),
            next_epoch_active_committee: Some(bls_committee(29)),
            total_messages_processed: 32,
            last_processed_checkpoint_sequence_number: 33,
            previous_epoch_last_checkpoint_sequence_number: 34,
            support_config: SupportConfig {
                supported_curves_to_signature_algorithms_to_hash_schemes: VecMap {
                    contents: vec![Entry {
                        key: 35,
                        value: VecMap {
                            contents: vec![Entry {
                                key: 36,
                                value: vec![37, 38],
                            }],
                        },
                    }],
                },
                paused_curves: vec![39],
                paused_signature_algorithms: vec![40],
                paused_hash_schemes: vec![41],
                signature_algorithms_allowed_global_presign: vec![42],
            },
            received_end_of_publish: true,
            extra_fields: bag(43),
        }
    }

    /// A fully-populated system inner; same construction rules as
    /// [`populated_coordinator_inner`].
    fn populated_system_inner() -> SystemInnerV1 {
        SystemInnerV1 {
            epoch: 1,
            epoch_start_tx_digest: vec![2, 3, 4],
            system_object_cap: SystemObjectCap { id: oid(5) },
            protocol_version: 6,
            next_protocol_version: Some(7),
            upgrade_caps: vec![UpgradeCap {
                id: oid(8),
                package: oid(9),
                version: 10,
                policy: 11,
            }],
            approved_upgrades: VecMap {
                contents: vec![Entry {
                    key: oid(12),
                    value: vec![13, 14],
                }],
            },
            validator_set: ValidatorSetV1 {
                total_stake: 15,
                reward_slashing_rate: 16,
                validators: table(17),
                active_committee: bls_committee(18),
                next_epoch_committee: Some(bls_committee(21)),
                previous_committee: bls_committee(24),
                pending_active_set: ExtendedField { id: oid(27) },
                validator_report_records: VecMap {
                    contents: vec![Entry {
                        key: oid(28),
                        value: VecSet {
                            contents: vec![oid(29)],
                        },
                    }],
                },
                extra_fields: bag(30),
            },
            epoch_duration_ms: 31,
            stake_subsidy_start_epoch: 32,
            protocol_treasury: ProtocolTreasuryV1 {
                treasury_cap: TreasuryCap {
                    id: UID::new(oid(33)),
                    total_supply: Supply { value: 34 },
                },
                stake_subsidy_distribution_counter: 35,
                stake_subsidy_rate: 36,
                stake_subsidy_amount_per_distribution: 37,
                stake_subsidy_period_length: 38,
                total_supply_at_period_start: 39,
                extra_fields: bag(40),
            },
            epoch_start_timestamp_ms: 41,
            last_processed_checkpoint_sequence_number: 42,
            previous_epoch_last_checkpoint_sequence_number: 43,
            total_messages_processed: 44,
            remaining_rewards: Balance::new(45),
            authorized_protocol_cap_ids: vec![oid(46)],
            witness_approving_advance_epoch: vec!["witness".to_string()],
            received_end_of_publish: true,
            extra_fields: bag(47),
        }
    }

    #[test]
    fn dwallet_coordinator_inner_v1_layout_is_pinned() {
        assert_pinned_layout(
            DWALLET_COORDINATOR_INNER_V1,
            &populated_coordinator_inner(),
            968,
            "ef75b1f13bb56bde94de39667e2b1881a626779169d45bc98aa71512148d6a5b",
        );
    }

    #[test]
    fn system_inner_v1_layout_is_pinned() {
        assert_pinned_layout(
            SYSTEM_INNER_V1,
            &populated_system_inner(),
            778,
            "b68ac624de60d0f14c7842af6e2bb205e8b4a7f94ce8d77f03d292b7b20d7382",
        );
    }
}
