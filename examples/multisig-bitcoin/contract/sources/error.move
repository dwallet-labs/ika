// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::error;

// === Error Constants ===

/// Error code for invalid approval threshold (must be > 0)
public(package) macro fun invalid_approval_threshold(): u64 {
  1
}

/// Error code for invalid rejection threshold (must be > 0)
public(package) macro fun invalid_rejection_threshold(): u64 {
  2
}

/// Error code for approval threshold exceeding member count
public(package) macro fun approval_threshold_too_high(): u64 {
  3
}

/// Error code for rejection threshold exceeding member count
public(package) macro fun rejection_threshold_too_high(): u64 {
  4
}

/// Error code for empty member list during wallet creation
public(package) macro fun empty_member_list(): u64 {
  5
}

/// Error code for request not found
public(package) macro fun request_not_found(): u64 {
  6
}

/// Error code for request not in pending status
public(package) macro fun request_not_pending(): u64 {
  7
}

/// Error code for caller not being a member
public(package) macro fun caller_not_member(): u64 {
  8
}

/// Error code for member already voted on request
public(package) macro fun already_voted(): u64 {
  9
}

/// Error code for insufficient votes to execute request
public(package) macro fun insufficient_votes(): u64 {
  10
}

/// Error code for member already exists when trying to add
public(package) macro fun member_already_exists(): u64 {
  11
}

/// Error code for member not found when trying to remove
public(package) macro fun member_not_found(): u64 {
  12
}

/// Error code for invalid threshold value
public(package) macro fun invalid_threshold(): u64 {
  13
}

/// Error code for invalid rejection threshold in specific context
public(package) macro fun invalid_rejection_threshold_specific(): u64 {
  14
}

/// Error code for invalid expiration duration (must be > 0)
public(package) macro fun invalid_expiration_duration(): u64 {
  15
}

/// Error code for request already passed threshold
public(package) macro fun request_already_passed_threshold(): u64 {
  16
}
