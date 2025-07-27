// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::advance_epoch_approver;

use ika::ika::IKA;
use ika_common::system_object_cap::SystemObjectCap;
use std::string::String;
use std::type_name;
use sui::balance::Balance;

// === Structs ===

/// This struct is an Hot-Potato that is passed around during epoch advancement.
public struct AdvanceEpochApprover {
    new_epoch: u64,
    remaining_witnesses_to_approve: vector<String>,
    balance_ika: Balance<IKA>,
}

// === Errors ===

/// Witness is not in the approver.
const EWitnessIsNotInApprover: u64 = 0;

// === Package Functions ===

public fun create(
    new_epoch: u64,
    remaining_witnesses_to_approve: vector<String>,
    balance_ika: Balance<IKA>,
    _: &SystemObjectCap,
): AdvanceEpochApprover {
    AdvanceEpochApprover {
        new_epoch,
        remaining_witnesses_to_approve,
        balance_ika,
    }
}

public fun new_epoch(self: &AdvanceEpochApprover): u64 {
    self.new_epoch
}

public fun assert_all_witnesses_approved(self: &AdvanceEpochApprover) {
    assert!(self.remaining_witnesses_to_approve.is_empty(), EWitnessIsNotInApprover);
}

public fun destroy(self: AdvanceEpochApprover, _: &SystemObjectCap): Balance<IKA> {
    let AdvanceEpochApprover {
        balance_ika,
        ..,
    } = self;
    balance_ika
}

// === Public Functions ===

public fun approve_advance_epoch_by_witness<Witness: drop>(
    advance_epoch_approver: &mut AdvanceEpochApprover,
    _: Witness,
    balance_ika: Balance<IKA>,
) {
    let witness_type = type_name::get_with_original_ids<Witness>();
    let witness_type_name = witness_type.into_string().to_string();
    let (is_found, index) = advance_epoch_approver
        .remaining_witnesses_to_approve
        .index_of(&witness_type_name);
    assert!(is_found, EWitnessIsNotInApprover);
    advance_epoch_approver.remaining_witnesses_to_approve.remove(index);
    advance_epoch_approver.balance_ika.join(balance_ika);
}
