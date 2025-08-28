// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::upgrade_package_approver;

use ika_common::system_object_cap::SystemObjectCap;
use std::string::String;
use std::type_name;
use sui::package::UpgradeReceipt;

// === Structs ===

/// This struct is an Hot-Potato that is passed around during upgrade package approval.
public struct UpgradePackageApprover {
    upgrade_cap_id: ID,
    remaining_witnesses_to_approve: vector<String>,
    old_package_id: ID,
    new_package_id: Option<ID>,
    migration_epoch: u64,
}

// === Errors ===

/// Witness is not in the approver.
const EWitnessIsNotInApprover: u64 = 0;

/// Commit upgrade first.
const ECommitUpgradeFirst: u64 = 1;

/// Upgrade cap mismatch.
const EUpgradeCapMismatch: u64 = 2;

// === Package Functions ===

public fun create(
    upgrade_cap_id: ID,
    remaining_witnesses_to_approve: vector<String>,
    old_package_id: ID,
    migration_epoch: u64,
    _: &SystemObjectCap,
): UpgradePackageApprover {
    UpgradePackageApprover {
        upgrade_cap_id,
        remaining_witnesses_to_approve,
        old_package_id,
        new_package_id: option::none(),
        migration_epoch,
    }
}

public fun assert_all_witnesses_approved(self: &UpgradePackageApprover) {
    assert!(self.remaining_witnesses_to_approve.is_empty(), EWitnessIsNotInApprover);
}

public fun new_package_id(self: &UpgradePackageApprover): Option<ID> {
    self.new_package_id
}

public fun old_package_id(self: &UpgradePackageApprover): ID {
    self.old_package_id
}

public fun migration_epoch(self: &UpgradePackageApprover): u64 {
    self.migration_epoch
}

public fun destroy(self: UpgradePackageApprover, _: &SystemObjectCap) {
    let UpgradePackageApprover { .. } = self;
}

public fun commit(self: &mut UpgradePackageApprover, receipt: &UpgradeReceipt, _: &SystemObjectCap) {
    assert!(self.upgrade_cap_id == receipt.cap(), EUpgradeCapMismatch);
    self.new_package_id = option::some(receipt.package());
}

// === Public Functions ===

public fun approve_upgrade_package_by_witness<Witness: drop>(
    upgrade_package_approver: &mut UpgradePackageApprover,
    _: Witness,
): ID {
    assert!(upgrade_package_approver.new_package_id.is_some(), ECommitUpgradeFirst);
    let witness_type = type_name::get_with_original_ids<Witness>();
    let witness_type_name = witness_type.into_string().to_string();
    let (is_found, index) = upgrade_package_approver
        .remaining_witnesses_to_approve
        .index_of(&witness_type_name);
    assert!(is_found, EWitnessIsNotInApprover);
    upgrade_package_approver.remaining_witnesses_to_approve.remove(index);
    *upgrade_package_approver.new_package_id.borrow()
}
