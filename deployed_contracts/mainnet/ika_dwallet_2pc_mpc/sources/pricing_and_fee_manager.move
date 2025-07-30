// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_dwallet_2pc_mpc::pricing_and_fee_manager;

use ika::ika::IKA;
use ika_common::bls_committee::BlsCommittee;
use ika_common::validator_cap::VerifiedValidatorOperationCap;
use ika_dwallet_2pc_mpc::pricing::{
    Self,
    PricingInfo,
    PricingInfoValue,
    PricingInfoCalculationVotes
};
use sui::balance::{Self, Balance};
use sui::sui::SUI;
use sui::table::{Self, Table};

// === Errors ===

/// Pricing configuration missing for protocol
const EMissingProtocolPricing: u64 = 1;
/// Pricing calculation votes have not been initiated
const EPricingCalculationVotesHasNotBeenStarted: u64 = 2;
/// Pricing calculation votes must complete before epoch advance
const EPricingCalculationVotesMustBeCompleted: u64 = 3;
/// Cannot modify settings during active pricing calculation
const ECannotSetDuringVotesCalculation: u64 = 4;

// === Structs ===

/// Pricing and fee management data for the dWallet coordinator.
public struct PricingAndFeeManager has store {
    /// Pricing for the current epoch
    current: PricingInfo,
    /// Default pricing configuration
    default: PricingInfo,
    /// Validator votes for pricing (validator ID -> pricing vote)
    validator_votes: Table<ID, PricingInfo>,
    /// Pricing calculation votes - if set, must complete before epoch advance
    pricing_calculation_votes: Option<PricingInfoCalculationVotes>,
    /// Gas fee reimbursement value for system calls
    gas_fee_reimbursement_sui_system_call_value: u64,
    /// SUI balance for gas fee reimbursement to fund network tx responses
    gas_fee_reimbursement_sui_system_call_balance: Balance<SUI>,
    /// IKA fees charged for consensus validation
    fee_charged_ika: Balance<IKA>,
}

// === Package Functions ===

/// Creates a new PricingAndFeeManager instance with initial configuration.
///
/// ### Parameters
/// - `pricing`: Default pricing configuration
/// - `ctx`: Transaction context for object creation
///
/// ### Returns
/// A new PricingAndFeeManager instance ready for use
public(package) fun create(pricing: PricingInfo, ctx: &mut TxContext): PricingAndFeeManager {
    PricingAndFeeManager {
        current: pricing,
        default: pricing,
        validator_votes: table::new(ctx),
        pricing_calculation_votes: option::none(),
        gas_fee_reimbursement_sui_system_call_value: 0,
        gas_fee_reimbursement_sui_system_call_balance: balance::zero(),
        fee_charged_ika: balance::zero(),
    }
}

/// Charges gas fee reimbursement for system-initiated operations.
///
/// Allocates SUI from the coordinator's gas reimbursement pool to cover
/// transaction costs for system operations like network DKG and reconfiguration.
///
/// ### Parameters
/// - `self`: Mutable reference to the coordinator
///
/// ### Returns
/// SUI balance to reimburse gas costs for system operations
///
/// ### Logic
/// - Returns zero if no reimbursement funds or value configured
/// - Takes the minimum of available funds and configured system call value
/// - Ensures system operations don't exhaust the entire reimbursement pool
public(package) fun charge_gas_fee_reimbursement_sui_for_system_calls(
    self: &mut PricingAndFeeManager,
): Balance<SUI> {
    let gas_fee_reimbursement_sui_value = self
        .gas_fee_reimbursement_sui_system_call_balance
        .value();
    let gas_fee_reimbursement_sui_system_call_value = self.gas_fee_reimbursement_sui_system_call_value;
    if (gas_fee_reimbursement_sui_value > 0 && gas_fee_reimbursement_sui_system_call_value > 0) {
        if (gas_fee_reimbursement_sui_value > gas_fee_reimbursement_sui_system_call_value) {
            self
                .gas_fee_reimbursement_sui_system_call_balance
                .split(gas_fee_reimbursement_sui_system_call_value)
        } else {
            self
                .gas_fee_reimbursement_sui_system_call_balance
                .split(gas_fee_reimbursement_sui_value)
        }
    } else {
        balance::zero()
    }
}

public(package) fun initiate_pricing_calculation(
    self: &mut PricingAndFeeManager,
    next_epoch_active_committee: BlsCommittee,
) {
    let pricing_calculation_votes = pricing::new_pricing_calculation(
        next_epoch_active_committee,
        self.default,
    );
    self.pricing_calculation_votes = option::some(pricing_calculation_votes);
}

/// Calculates the pricing votes for a given curve, signature algorithm and protocol.
///
/// ### Parameters
/// - **`self`**: Mutable reference to the PricingAndFeeManager
/// - **`curve`**: The curve to calculate the pricing votes for.
/// - **`signature_algorithm`**: The signature algorithm to calculate the pricing votes for.
/// - **`protocol`**: The protocol to calculate the pricing votes for.
public(package) fun calculate_pricing_votes(
    self: &mut PricingAndFeeManager,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
) {
    assert!(self.pricing_calculation_votes.is_some(), EPricingCalculationVotesHasNotBeenStarted);
    let pricing_calculation_votes = self.pricing_calculation_votes.borrow_mut();
    let pricing_votes = pricing_calculation_votes
        .committee_members_for_pricing_calculation_votes()
        .map!(|id| {
            if (self.validator_votes.contains(id)) {
                self.validator_votes[id]
            } else {
                self.default
            }
        });
    pricing_calculation_votes.calculate_pricing_quorum_below(
        pricing_votes,
        curve,
        signature_algorithm,
        protocol,
    );
    if (pricing_calculation_votes.is_calculation_completed()) {
        self.current = pricing_calculation_votes.calculated_pricing();
        self.pricing_calculation_votes = option::none();
    }
}

/// Advances the epoch and returns the IKA balance charged for consensus validation.
///
/// ### Logic
/// - Aborts if pricing calculation votes are still in progress
/// - Withdraws all IKA balance from the fee charged IKA balance
///
/// ### Parameters
/// - `self`: Mutable reference to the PricingAndFeeManager
///
/// ### Returns
/// IKA balance charged for consensus validation
public(package) fun advance_epoch(self: &mut PricingAndFeeManager): Balance<IKA> {
    assert!(self.pricing_calculation_votes.is_none(), EPricingCalculationVotesMustBeCompleted);
    self.fee_charged_ika.withdraw_all()
}

/// Returns the pricing value for a given curve, signature algorithm and protocol.
///
/// ### Parameters
/// - **`self`**: Mutable reference to the PricingAndFeeManager
/// - **`curve`**: The curve to get the pricing value for.
/// - **`signature_algorithm`**: The signature algorithm to get the pricing value for.
/// - **`protocol`**: The protocol to get the pricing value for.
///
/// ### Returns
/// The pricing value for the given curve, signature algorithm and protocol
public(package) fun get_pricing_value_for_protocol(
    self: &PricingAndFeeManager,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
): PricingInfoValue {
    let mut pricing_value = self
        .current
        .try_get_pricing_value(curve, signature_algorithm, protocol);
    assert!(pricing_value.is_some(), EMissingProtocolPricing);
    pricing_value.extract()
}

/// Joins the fee charged IKA balance.
///
/// ### Parameters
/// - **`self`**: Mutable reference to the PricingAndFeeManager
/// - **`fee_charged_ika`**: The fee charged IKA balance to join.
public(package) fun join_fee_charged_ika(
    self: &mut PricingAndFeeManager,
    fee_charged_ika: Balance<IKA>,
) {
    self.fee_charged_ika.join(fee_charged_ika);
}

/// Joins the gas fee reimbursement SUI system call balance.
///
/// ### Parameters
/// - **`self`**: Mutable reference to the PricingAndFeeManager
/// - **`gas_fee_reimbursement_sui_for_system_calls`**: The gas fee reimbursement SUI system call balance to join.
public(package) fun join_gas_fee_reimbursement_sui_system_call_balance(
    self: &mut PricingAndFeeManager,
    gas_fee_reimbursement_sui_for_system_calls: Balance<SUI>,
) {
    self
        .gas_fee_reimbursement_sui_system_call_balance
        .join(gas_fee_reimbursement_sui_for_system_calls);
}

/// Sets the gas fee reimbursement SUI system call value.
///
/// ### Parameters
/// - **`gas_fee_reimbursement_sui_system_call_value`**: The gas fee reimbursement SUI system call value.
public(package) fun set_gas_fee_reimbursement_sui_system_call_value(
    self: &mut PricingAndFeeManager,
    gas_fee_reimbursement_sui_system_call_value: u64,
) {
    self.gas_fee_reimbursement_sui_system_call_value = gas_fee_reimbursement_sui_system_call_value;
}

/// Sets the default pricing.
///
/// This function is used to set the default pricing.
///
/// ### Parameters
/// - **`default_pricing`**: The default pricing to use if pricing is missing for a protocol or curve.
public(package) fun set_default_pricing(
    self: &mut PricingAndFeeManager,
    default_pricing: PricingInfo,
) {
    self.default = default_pricing;
}

/// Sets the pricing vote for a validator.
///
/// This function is used to set the pricing vote for a validator.
/// Cannot be called during the votes calculation.
///
/// ### Parameters
/// - **`validator_id`**: The ID of the validator.
/// - **`pricing_vote`**: The pricing vote for the validator.
///
/// ### Errors
/// - **`ECannotSetDuringVotesCalculation`**: If the pricing vote is set during the votes calculation.
public(package) fun set_pricing_vote(
    self: &mut PricingAndFeeManager,
    pricing_vote: PricingInfo,
    cap: &VerifiedValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    assert!(self.pricing_calculation_votes.is_none(), ECannotSetDuringVotesCalculation);
    if (self.validator_votes.contains(validator_id)) {
        let vote = self.validator_votes.borrow_mut(validator_id);
        *vote = pricing_vote;
    } else {
        self.validator_votes.add(validator_id, pricing_vote);
    }
}

/// Returns the current pricing.
///
/// ### Parameters
/// - **`self`**: Mutable reference to the PricingAndFeeManager
///
/// ### Returns
/// The current pricing
public(package) fun current_pricing(self: &PricingAndFeeManager): PricingInfo {
    self.current
}
