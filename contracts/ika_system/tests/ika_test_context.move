// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Implements the `IkaTestContext` struct which is used to store the current
/// state of the system. For testing and readability of signatures.
module ika_system::ika_test_context;

use ika_system::bls_committee::BlsCommittee;

/// Represents the current values in the Ika system. Helps to
/// allow for easier testing.
public struct IkaTestContext has drop {
    /// Current Ika epoch
    epoch: u64,
    /// Whether the committee has been selected for the next epoch.
    committee_selected: bool,
    /// The current committee in the system.
    bls_committee: BlsCommittee,
}

/// Create a new `IkaTestContext` object.
public(package) fun new(
    epoch: u64,
    committee_selected: bool,
    bls_committee: BlsCommittee,
): IkaTestContext {
    IkaTestContext { epoch, committee_selected, bls_committee }
}

/// Read the current `epoch` from the context.
public(package) fun epoch(self: &IkaTestContext): u64 { self.epoch }

/// Read the current `committee_selected` from the context.
public(package) fun committee_selected(self: &IkaTestContext): bool { self.committee_selected }

/// Read the current `bls_committee` from the context.
public(package) fun bls_committee(self: &IkaTestContext): &BlsCommittee { &self.bls_committee }
