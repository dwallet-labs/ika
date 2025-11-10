// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::multisig_events;

use ika_btc_multisig::{event_wrapper::emit_event, multisig_request::{RequestType, RequestStatus}};

// === Event Structs ===

/// Event emitted when a new multisig wallet is successfully created.
/// This event marks the beginning of the multisig wallet lifecycle and includes
/// all the initial configuration parameters that define the wallet's behavior.
public struct MultisigCreated has copy, drop, store {
  /// Unique identifier of the newly created multisig wallet
  multisig_id: ID,
  /// Initial list of member addresses who can vote on requests
  members: vector<address>,
  /// Number of approvals required to execute requests
  approval_threshold: u64,
  /// Number of rejections required to definitively reject requests
  rejection_threshold: u64,
  /// Duration in milliseconds after which requests automatically expire
  expiration_duration: u64,
  /// Address of the user who created the multisig wallet
  created_by: address,
}

/// Event emitted when the second round of distributed key generation begins.
/// This event signals that the multisig wallet has progressed past the initial setup
/// and is now in the cryptographic key generation phase.
public struct MultisigDKGSecondRoundStarted has copy, drop, store {
  /// Unique identifier of the multisig wallet entering DKG second round
  multisig_id: ID,
}

/// Event emitted when the multisig wallet has successfully completed the DKG process
/// and is ready for use. This marks the transition from setup phase to operational phase.
public struct MultisigAcceptedAndShared has copy, drop, store {
  /// Unique identifier of the fully initialized multisig wallet
  multisig_id: ID,
}

/// Event emitted when a new request is created in the multisig wallet.
/// This event tracks all governance and operational actions that require multisig approval.
public struct RequestCreated has copy, drop, store {
  /// Unique identifier of the multisig wallet
  multisig_id: ID,
  /// Unique identifier assigned to the newly created request
  request_id: u64,
  /// The type and details of the request (transaction, governance change, etc.)
  request_type: RequestType,
  /// Address of the member who created the request
  created_by: address,
}

/// Event emitted when a request is resolved (either approved and executed or rejected).
/// This event marks the completion of the multisig voting and execution process.
public struct RequestResolved has copy, drop, store {
  /// Unique identifier of the multisig wallet
  multisig_id: ID,
  /// Unique identifier of the resolved request
  request_id: u64,
  /// Final status of the request (Approved with result or Rejected)
  request_status: RequestStatus,
}

/// Event emitted when a member casts a vote on a multisig request.
/// This event tracks all voting activity and is crucial for monitoring request progress.
public struct VoteRequest has copy, drop, store {
  /// Unique identifier of the multisig wallet
  multisig_id: ID,
  /// Unique identifier of the request being voted on
  request_id: u64,
  /// Address of the member who cast the vote
  voter: address,
  /// The vote decision (true for approval, false for rejection)
  vote: bool,
  /// Current approval count after this vote
  approvers_count: u64,
  /// Current rejection count after this vote
  rejecters_count: u64,
}

/// Event emitted when IKA or SUI tokens are added to the multisig wallet's balance.
/// This event tracks balance changes that affect the wallet's ability to pay protocol fees.
public struct BalanceAdded has copy, drop, store {
  /// Unique identifier of the multisig wallet
  multisig_id: ID,
  /// Address that added the tokens
  added_by: address,
  /// Amount of IKA tokens added (0 if SUI was added)
  ika_amount: u64,
  /// Amount of SUI tokens added (0 if IKA was added)
  sui_amount: u64,
}

/// Event emitted when a presign capability is added to the multisig wallet.
/// This event tracks the addition of signing capabilities required for Bitcoin transactions.
public struct PresignAdded has copy, drop, store {
  /// Unique identifier of the multisig wallet
  multisig_id: ID,
  /// Address that added the presign
  added_by: address,
  /// Total number of presigns after addition
  presigns_count: u64,
}

// === Public(Package) Functions ===

/// Emits a MultisigCreated event when a new multisig wallet is initialized.
/// This function should be called immediately after successful wallet creation
/// to notify listeners about the new multisig wallet and its configuration.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the created multisig wallet
/// * `members` - Initial list of member addresses
/// * `approval_threshold` - Number of approvals required for request execution
/// * `rejection_threshold` - Number of rejections required for request rejection
/// * `expiration_duration` - Request expiration time in milliseconds
/// * `created_by` - Address of the user who created the wallet
public(package) fun multisig_created(
  multisig_id: ID,
  members: vector<address>,
  approval_threshold: u64,
  rejection_threshold: u64,
  expiration_duration: u64,
  created_by: address,
) {
  emit_event(MultisigCreated {
    multisig_id,
    members,
    approval_threshold,
    rejection_threshold,
    expiration_duration,
    created_by,
  });
}

/// Emits a MultisigDKGSecondRoundStarted event when DKG second round begins.
/// This function marks the transition from initial setup to cryptographic key generation.
/// Call this function when the multisig_dkg_second_round function is invoked.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet starting DKG second round
public(package) fun multisig_dkg_second_round_started(multisig_id: ID) {
  emit_event(MultisigDKGSecondRoundStarted {
    multisig_id,
  });
}

/// Emits a MultisigAcceptedAndShared event when DKG is completed and wallet is ready.
/// This function signals that the multisig wallet has successfully completed its
/// cryptographic setup and is now operational for creating and voting on requests.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the fully initialized multisig wallet
public(package) fun multisig_accepted_and_shared(multisig_id: ID) {
  emit_event(MultisigAcceptedAndShared {
    multisig_id,
  });
}

/// Emits a RequestCreated event when a new request is submitted to the multisig wallet.
/// This function should be called whenever a new request is created through any of the
/// request creation functions (transaction_request, add_member_request, etc.).
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet
/// * `request_id` - Unique identifier assigned to the new request
/// * `request_type` - Type and details of the request being created
/// * `created_by` - Address of the member who created the request
public(package) fun request_created(
  multisig_id: ID,
  request_id: u64,
  request_type: RequestType,
  created_by: address,
) {
  emit_event(RequestCreated {
    multisig_id,
    request_id,
    request_type,
    created_by,
  });
}

/// Emits a RequestResolved event when a request reaches final resolution.
/// This function should be called when a request is either approved and executed
/// or definitively rejected, marking the end of the request's lifecycle.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet
/// * `request_id` - Unique identifier of the resolved request
/// * `request_status` - Final status (Approved with result or Rejected)
public(package) fun request_resolved(
  multisig_id: ID,
  request_id: u64,
  request_status: RequestStatus,
) {
  emit_event(RequestResolved {
    multisig_id,
    request_id,
    request_status,
  });
}

/// Emits a VoteRequest event when a member votes on a multisig request.
/// This function should be called after successfully recording a vote.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet
/// * `request_id` - Unique identifier of the request being voted on
/// * `voter` - Address of the member who cast the vote
/// * `vote` - The vote decision (true for approval, false for rejection)
/// * `approvers_count` - Current approval count after this vote
/// * `rejecters_count` - Current rejection count after this vote
public(package) fun vote_request(
  multisig_id: ID,
  request_id: u64,
  voter: address,
  vote: bool,
  approvers_count: u64,
  rejecters_count: u64,
) {
  emit_event(VoteRequest {
    multisig_id,
    request_id,
    voter,
    vote,
    approvers_count,
    rejecters_count,
  });
}

/// Emits a BalanceAdded event when tokens are added to the multisig wallet.
/// This function should be called after successfully adding IKA or SUI tokens.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet
/// * `added_by` - Address that added the tokens
/// * `ika_amount` - Amount of IKA tokens added (0 if SUI was added)
/// * `sui_amount` - Amount of SUI tokens added (0 if IKA was added)
public(package) fun balance_added(
  multisig_id: ID,
  added_by: address,
  ika_amount: u64,
  sui_amount: u64,
) {
  emit_event(BalanceAdded {
    multisig_id,
    added_by,
    ika_amount,
    sui_amount,
  });
}

/// Emits a PresignAdded event when a presign capability is added.
/// This function should be called after successfully adding a presign.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet
/// * `added_by` - Address that added the presign
/// * `presigns_count` - Total number of presigns after addition
public(package) fun presign_added(multisig_id: ID, added_by: address, presigns_count: u64) {
  emit_event(PresignAdded {
    multisig_id,
    added_by,
    presigns_count,
  });
}
