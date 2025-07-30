// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// This module provides structures and functions for managing pricing information for a dWallet.
/// Each operation (e.g., DKG, re-encrypt user share, ECDSA presign, etc.) has its own pricing data,
/// represented by a `PricingPerOperation`. Each `PricingPerOperation` holds three values:
///   - **fee_ika**: The IKA fee for the operation.
///   - **gas_fee_reimbursement_sui**: The SUI reimbursement.
///   - **gas_fee_reimbursement_sui_for_system_calls**: The SUI reimbursement for system calls.
///
/// The main struct, `PricingInfo`, now holds one `PricingPerOperation` per operation.
/// The DKG operation is split into two separate rounds:
///   - `dkg_first_round`
///   - `dkg_second_round`
module ika_dwallet_2pc_mpc::pricing;

use ika_common::bls_committee::BlsCommittee;
use sui::priority_queue::{Self, PriorityQueue};
use sui::vec_map::{Self, VecMap};

// === Structs ===

/// Holds pricing information for a dWallet.
/// The vector is indexed by the curve and signature algorithm and protocol.
public struct PricingInfo has copy, drop, store {
    /// The pricing for each curve and signature algorithm and protocol.
    /// The first key is the curve, the second is the signature algorithm, the third is the protocol.
    pricing_map: VecMap<PricingInfoKey, PricingInfoValue>,
}

public struct PricingInfoKey has copy, drop, store {
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
}

/// Holds pricing information for a single operation.
/// The fields are ordered so that the consensus validation price is first.
public struct PricingInfoValue has copy, drop, store {
    fee_ika: u64,
    gas_fee_reimbursement_sui: u64,
    gas_fee_reimbursement_sui_for_system_calls: u64,
}

public struct PricingInfoCalculationVotes has copy, drop, store {
    bls_committee: BlsCommittee,
    default_pricing: PricingInfo,
    working_pricing: PricingInfo,
}

// === Public Functions ===

/// Creates a new [`PricingInfo`] object.
///
/// Initializes the table with the given pricing values for each operation.
///
/// # Parameters
///
/// - `ctx`: The transaction context.
///
/// # Returns
///
/// A newly created instance of `PricingInfo`.
public fun empty(): PricingInfo {
    PricingInfo {
        pricing_map: vec_map::empty(),
    }
}

/// Inserts pricing information for a specific operation into the [`PricingInfo`] table.
///
/// # Parameters
///
/// - `self`: The [`PricingInfo`] object.
/// - `key`: The key for the operation.
/// - `value`: The pricing information for the operation.
///
/// # Returns
///
/// The [`PricingInfo`] object.
public fun insert_or_update_pricing(
    self: &mut PricingInfo,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
    fee_ika: u64,
    gas_fee_reimbursement_sui: u64,
    gas_fee_reimbursement_sui_for_system_calls: u64,
) {
    self.insert_or_update_pricing_value(
        curve,
        signature_algorithm,
        protocol,
        PricingInfoValue {
            fee_ika,
            gas_fee_reimbursement_sui,
            gas_fee_reimbursement_sui_for_system_calls,
        },
    )
}

/// Returns the pricing information for a specific operation from the [`PricingInfo`] table.
///
/// # Parameters
///
/// - `self`: The [`PricingInfo`] object.
/// - `key`: The key for the operation.
///
/// # Returns
///
/// The pricing information for the operation.
public(package) fun try_get_pricing_value(
    self: &PricingInfo,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
): Option<PricingInfoValue> {
    let key = PricingInfoKey {
        curve,
        signature_algorithm,
        protocol,
    };
    self.pricing_map.try_get(&key)
}

/// Getter for the fee_ika field of a PricingInfoValue.
public fun fee_ika(self: &PricingInfoValue): u64 {
    self.fee_ika
}

/// Getter for the gas_fee_reimbursement_sui field of a PricingInfoValue.
public fun gas_fee_reimbursement_sui(self: &PricingInfoValue): u64 {
    self.gas_fee_reimbursement_sui
}

/// Getter for the gas_fee_reimbursement_sui_for_system_calls field of a PricingInfoValue.
public fun gas_fee_reimbursement_sui_for_system_calls(self: &PricingInfoValue): u64 {
    self.gas_fee_reimbursement_sui_for_system_calls
}

public(package) fun new_pricing_calculation(
    bls_committee: BlsCommittee,
    default_pricing: PricingInfo,
): PricingInfoCalculationVotes {
    PricingInfoCalculationVotes {
        bls_committee,
        default_pricing,
        working_pricing: empty(),
    }
}

public(package) fun committee_members_for_pricing_calculation_votes(
    calculation: &PricingInfoCalculationVotes,
): vector<ID> {
    calculation.bls_committee.members().map_ref!(|member| {
        member.validator_id()
    })
}

public(package) fun calculate_pricing_quorum_below(
    calculation: &mut PricingInfoCalculationVotes,
    pricing: vector<PricingInfo>,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
) {
    let mut values = vector[];
    pricing.do_ref!(|pricing| {
        let value = pricing.try_get_pricing_value(curve, signature_algorithm, protocol);
        values.push_back(value.get_with_default(calculation
            .default_pricing
            .try_get_pricing_value(curve, signature_algorithm, protocol)
            .extract()));
    });
    let value = pricing_value_quorum_below(calculation.bls_committee, values);
    calculation
        .working_pricing
        .insert_or_update_pricing_value(curve, signature_algorithm, protocol, value);
}

public(package) fun pricing_value_quorum_below(
    bls_committee: BlsCommittee,
    values: vector<PricingInfoValue>,
): PricingInfoValue {
    let mut fee_ika = priority_queue::new(vector[]);
    let mut gas_fee_reimbursement_sui = priority_queue::new(vector[]);
    let mut gas_fee_reimbursement_sui_for_system_calls = priority_queue::new(vector[]);
    values.do_ref!(|value| {
        fee_ika.insert(value.fee_ika(), 1);
        gas_fee_reimbursement_sui.insert(value.gas_fee_reimbursement_sui(), 1);
        gas_fee_reimbursement_sui_for_system_calls.insert(
            value.gas_fee_reimbursement_sui_for_system_calls(),
            1,
        );
    });
    let fee_ika_quorum_below = quorum_below(bls_committee, &mut fee_ika);
    let gas_fee_reimbursement_sui_quorum_below = quorum_below(
        bls_committee,
        &mut gas_fee_reimbursement_sui,
    );
    let gas_fee_reimbursement_sui_for_system_calls_quorum_below = quorum_below(
        bls_committee,
        &mut gas_fee_reimbursement_sui_for_system_calls,
    );
    PricingInfoValue {
        fee_ika: fee_ika_quorum_below,
        gas_fee_reimbursement_sui: gas_fee_reimbursement_sui_quorum_below,
        gas_fee_reimbursement_sui_for_system_calls: gas_fee_reimbursement_sui_for_system_calls_quorum_below,
    }
}

public(package) fun is_calculation_completed(calculation: &PricingInfoCalculationVotes): bool {
    let mut i = 0;
    let (keys, _) = calculation.default_pricing.pricing_map.into_keys_values();
    while (i < keys.length()) {
        let key = keys[i];
        if (calculation.working_pricing.pricing_map.try_get(&key).is_none()) {
            return false
        };
        i = i + 1;
    };
    true
}

public(package) fun calculated_pricing(calculation: &PricingInfoCalculationVotes): PricingInfo {
    calculation.working_pricing
}

// === Private Functions ===

fun insert_or_update_pricing_value(
    self: &mut PricingInfo,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
    value: PricingInfoValue,
) {
    let key = PricingInfoKey {
        curve,
        signature_algorithm,
        protocol,
    };
    if (self.pricing_map.contains(&key)) {
        let existing_value = &mut self.pricing_map[&key];
        *existing_value = value;
    } else {
        self.pricing_map.insert(key, value);
    };
}

/// Take the lowest value, s.t. a quorum  (2f + 1) voted for a value lower or equal to this.
fun quorum_below(bls_committee: BlsCommittee, vote_queue: &mut PriorityQueue<u64>): u64 {
    let mut sum_votes = bls_committee.total_voting_power();
    // We have a quorum initially, so we remove nodes until doing so breaks the quorum.
    // The value at that point is the minimum value with support from a quorum.
    loop {
        let (value, votes) = vote_queue.pop_max();
        sum_votes = sum_votes - votes;
        if (!bls_committee.is_quorum_threshold(sum_votes)) {
            return value
        };
    }
}
