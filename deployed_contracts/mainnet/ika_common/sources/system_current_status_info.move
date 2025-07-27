// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::system_current_status_info;

use ika_common::bls_committee::BlsCommittee;
use ika_common::system_object_cap::SystemObjectCap;

// === Structs ===

public struct SystemCurrentStatusInfo has drop {
    current_epoch: u64,
    is_mid_epoch_time: bool,
    is_end_epoch_time: bool,
    current_epoch_active_committee: BlsCommittee,
    next_epoch_active_committee: Option<BlsCommittee>,
}

// === Public Functions ===

public fun create(
    current_epoch: u64,
    is_mid_epoch_time: bool,
    is_end_epoch_time: bool,
    current_epoch_active_committee: BlsCommittee,
    next_epoch_active_committee: Option<BlsCommittee>,
    _: &SystemObjectCap,
): SystemCurrentStatusInfo {
    SystemCurrentStatusInfo {
        current_epoch,
        is_mid_epoch_time,
        is_end_epoch_time,
        current_epoch_active_committee,
        next_epoch_active_committee,
    }
}

public fun current_epoch(self: &SystemCurrentStatusInfo): u64 {
    self.current_epoch
}

public fun is_mid_epoch_time(self: &SystemCurrentStatusInfo): bool {
    self.is_mid_epoch_time
}

public fun is_end_epoch_time(self: &SystemCurrentStatusInfo): bool {
    self.is_end_epoch_time
}

public fun current_epoch_active_committee(self: &SystemCurrentStatusInfo): BlsCommittee {
    self.current_epoch_active_committee
}

public fun next_epoch_active_committee(self: &SystemCurrentStatusInfo): Option<BlsCommittee> {
    self.next_epoch_active_committee
}
