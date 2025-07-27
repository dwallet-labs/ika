// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// A utility module which implements an `ExchangeRate` struct and its methods.
/// It stores a fixed point exchange rate between the IKA token and validator shares.
module ika_system::token_exchange_rate;

// === Errors ===

/// The exchange rate between the shares and the IKA token is invalid.
const EInvalidRate: u64 = 0;

// === Structs ===

/// Represents the exchange rate for the staking validator.
public enum TokenExchangeRate has copy, drop, store {
    Flat, // one to one exchange rate
    Variable {
        /// Amount of staked IKA tokens + rewards.
        ika_amount: u128,
        /// Amount of total shares in the validator (<= ika_amount, as long as slashing is not
        /// implemented).
        share_amount: u128,
    },
}

// === Package Functions ===

/// Create an empty exchange rate.
public(package) fun flat(): TokenExchangeRate {
    TokenExchangeRate::Flat
}

/// Create a new exchange rate with the given amounts.
public(package) fun new(ika_amount: u64, share_amount: u64): TokenExchangeRate {
    // validator_token_amount <= ika_amount as long as slashing is not implemented.
    assert!(share_amount <= ika_amount, EInvalidRate);
    if (ika_amount == 0 || share_amount == 0) {
        TokenExchangeRate::Flat
    } else {
        TokenExchangeRate::Variable {
            ika_amount: (ika_amount as u128),
            share_amount: (share_amount as u128),
        }
    }
}

/// Assumptions:
/// - amount is at most the amount of shares in the validator
public(package) fun convert_to_ika_amount(exchange_rate: &TokenExchangeRate, amount: u64): u64 {
    match (exchange_rate) {
        TokenExchangeRate::Flat => amount,
        TokenExchangeRate::Variable { ika_amount, share_amount } => {
            let amount = (amount as u128);
            let res = (amount * *ika_amount) / *share_amount;
            res as u64
        },
    }
}

/// Assumptions:
/// - amount is at most the amount of IKA in the validator
public(package) fun convert_to_share_amount(exchange_rate: &TokenExchangeRate, amount: u64): u64 {
    match (exchange_rate) {
        TokenExchangeRate::Flat => amount,
        TokenExchangeRate::Variable { ika_amount, share_amount } => {
            let amount = (amount as u128);
            let res = (amount * *share_amount) / *ika_amount;
            res as u64
        },
    }
}
