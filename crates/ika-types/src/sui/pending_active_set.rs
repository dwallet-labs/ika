// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rust mirror of the on-chain `pending_active_set` Move type so its BCS bytes
//! — read as the single `Key()` dynamic field under the `ExtendedField` wrapper
//! `SystemInner.validator_set.pending_active_set` — can be decoded.
//!
//! Kept field-for-field, in order, with
//! `contracts/ika_system/sources/staking/pending_active_set.move`. Move `ID` is
//! a Rust `ObjectID` (identical 32-byte BCS).

use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;
use sui_types::collection_types::VecSet;

/// One staged validator in the pending active set.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PendingActiveSetEntry {
    pub validator_id: ObjectID,
    pub staked_amount: u64,
}

/// The staging set of validators for the next epoch — updated continuously as
/// validators join/leave, so a freshly-registered joiner appears here before it
/// reaches `next_epoch_committee`. Mirrors `pending_active_set::PendingActiveSet`.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PendingActiveSet {
    pub min_validator_count: u64,
    pub max_validator_count: u64,
    pub min_validator_joining_stake: u64,
    pub max_validator_change_count: u64,
    pub validators: Vec<PendingActiveSetEntry>,
    pub total_stake: u64,
    pub validator_changes: VecSet<ObjectID>,
}

impl PendingActiveSet {
    /// The `validator_id`s of every staged validator, in order.
    pub fn validator_ids(&self) -> Vec<ObjectID> {
        self.validators.iter().map(|e| e.validator_id).collect()
    }
}
