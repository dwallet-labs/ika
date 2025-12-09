// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::multisig_request;

use ika_dwallet_2pc_mpc::coordinator_inner::UnverifiedPartialUserSignatureCap;
use sui::{clock::Clock, table::{Self, Table}};

/// Represents a Bitcoin transaction request that needs multisig approval.
/// Each request contains the transaction details and tracks voting progress.
/// Once created, requests have a finite lifetime and expire automatically.
public struct Request has store {
  /// The request type.
  request_type: RequestType,
  /// Current status of this request (Pending, Approved, or Rejected).
  /// The status transitions based on accumulated votes and becomes final once thresholds are met.
  status: RequestStatus,
  /// Unix timestamp (in seconds) when this request was created.
  /// Used to calculate expiration: request is expired if created_at + expiration_duration < current_time
  created_at: u64,
  /// Running count of members who have voted in favor of this request.
  /// When this reaches approval_threshold, the request status becomes Approved.
  approvers_count: u64,
  /// Running count of members who have voted against this request.
  /// When this reaches rejection_threshold, the request status becomes Rejected.
  rejecters_count: u64,
  /// Immutable record of each member's vote on this request.
  /// Key: member address, Value: true for approval, false for rejection.
  ///
  /// CRITICAL SECURITY PROPERTY: Votes are irrevocable!
  /// Once a member votes (approval or rejection), they cannot change their decision.
  /// This prevents vote manipulation and ensures decision finality.
  votes: Table<address, bool>,
  /// Unverified partial user signature capability for Bitcoin transactions.
  /// This field is only populated for Transaction requests and contains the capability
  /// needed to sign the Bitcoin transaction with the user's public share.
  /// The capability must be verified before it can be used for signing operations.
  tx_unverified_partial_user_signature_cap: Option<UnverifiedPartialUserSignatureCap>,
}

/// Tracks the complete lifecycle of a multisig request from creation to final resolution.
/// The status follows a strict state machine: Pending → (Approved | Rejected).
/// Status transitions are irreversible once voting thresholds are reached, ensuring
/// decision finality and preventing manipulation or double-execution.
///
/// This enum serves as both a state indicator and a result container for completed requests.
public enum RequestStatus has copy, drop, store {
  /// Initial state: Request is actively collecting votes from multisig members.
  /// The request remains in this state until it reaches either approval or rejection threshold.
  /// Members can still vote, and the request can expire if the deadline passes.
  Pending,
  /// Terminal state: Request has reached approval threshold and been successfully executed.
  /// Contains the RequestResult which captures the specific outcome of the approved action.
  /// The request is now immutable and ready for implementation or further processing.
  Approved(RequestResult),
  /// Terminal state: Request has reached rejection threshold and will not be executed.
  /// No further action is possible on this request. The rejection is final and binding.
  /// This prevents the request from being resubmitted or reconsidered.
  Rejected,
}

/// Defines the various types of requests that can be submitted to the multisig wallet.
/// Each variant represents a different governance or operational action that requires collective approval.
/// All request types follow the same voting and approval process but have different execution logic.
///
/// The enum variants contain all necessary data for executing the specific request type.
/// Each variant corresponds to a specific function that creates requests of that type.
public enum RequestType has copy, drop, store {
  /// Bitcoin transaction request containing all necessary data for signing and broadcasting.
  /// - Parameter 1 (vector<u8>): UTXO input to spend(preimage to be signed)
  /// - Parameter 2 (vector<u8>): Centralized signature component for the transaction
  /// - Parameter 3 (vector<u8>): Whole serialized Bitcoin transaction in hexadecimal format
  ///
  /// This request type requires approval_threshold votes to execute and will trigger
  /// Bitcoin transaction signing through the IKA dWallet protocol when approved.
  Transaction(vector<u8>, vector<u8>, vector<u8>),
  /// Governance request to add a new member to the multisig wallet.
  /// - Parameter (address): Sui address of the new member to add to the members vector
  ///
  /// Adding members increases the total voting power and may affect threshold calculations.
  /// The new member gains full voting rights immediately upon approval and execution.
  AddMember(address),
  /// Governance request to remove an existing member from the multisig wallet.
  /// - Parameter (address): Sui address of the member to remove from the members vector
  ///
  /// Removing members decreases the total voting power and may affect existing requests
  /// if the removed member had already voted. Existing votes from removed members remain valid.
  RemoveMember(address),
  /// Governance request to modify the approval threshold for transaction requests.
  /// - Parameter (u64): New approval threshold value (> 0 and <= current member count)
  ///
  /// Increasing the threshold makes transactions harder to approve (more secure).
  /// Decreasing the threshold makes transactions easier to approve (less secure).
  ChangeApprovalThreshold(u64),
  /// Governance request to modify the rejection threshold for requests.
  /// - Parameter (u64): New rejection threshold value (> 0 and <= current member count)
  ///
  /// Increasing the threshold makes rejection harder (more secure for approvals).
  /// Decreasing the threshold makes rejection easier (less secure for approvals).
  ChangeRejectionThreshold(u64),
  /// Governance request to modify the expiration duration for new requests.
  /// - Parameter (u64): New expiration duration in milliseconds (> 0)
  ///
  /// Longer durations provide more time for voting but increase the window for potential issues.
  /// Shorter durations ensure timely processing but may cause requests to expire before completion.
  ChangeExpirationDuration(u64),
}

/// Represents the successful execution result of an approved request.
/// This enum captures the outcome of governance and operational actions that have been
/// approved through the multisig voting process. Each variant corresponds to a RequestType
/// but contains the actual result data after successful execution.
///
/// Results are stored to provide an immutable audit trail of all executed actions.
public enum RequestResult has copy, drop, store {
  /// Bitcoin transaction successfully signed and ready for broadcast.
  /// Contains the signature request ID that can be used to retrieve the final signature
  /// from the IKA dWallet coordinator. The transaction is now ready for Bitcoin network submission.
  Transaction(ID),
  /// New member successfully added to the multisig wallet.
  /// Contains the address of the member that was added to the members vector.
  /// This member can now participate in future voting processes.
  AddMember(address),
  /// Member successfully removed from the multisig wallet.
  /// Contains the address of the member that was removed from the members vector.
  /// This member can no longer participate in voting and their existing votes remain valid.
  RemoveMember(address),
  /// Approval threshold successfully updated for the multisig wallet.
  /// Contains the new approval threshold value that is now in effect.
  /// All future transaction requests will use this new threshold.
  ChangeApprovalThreshold(u64),
  /// Rejection threshold successfully updated for the multisig wallet.
  /// Contains the new rejection threshold value that is now in effect.
  /// All future requests will use this new threshold for rejection.
  ChangeRejectionThreshold(u64),
  /// Expiration duration successfully updated for the multisig wallet.
  /// Contains the new expiration duration (in seconds) that is now in effect.
  /// All future requests will use this new duration for automatic expiration.
  ChangeExpirationDuration(u64),
}

// === Public(Package) Functions ===

public(package) fun create_request(
  request_type: RequestType,
  unverified_partial_user_signature_cap: Option<UnverifiedPartialUserSignatureCap>,
  clock: &Clock,
  ctx: &mut TxContext,
): Request {
  Request {
    request_type: request_type,
    status: RequestStatus::Pending,
    created_at: clock.timestamp_ms(),
    approvers_count: 0,
    rejecters_count: 0,
    votes: table::new(ctx),
    tx_unverified_partial_user_signature_cap: unverified_partial_user_signature_cap,
  }
}

// === Request Type Functions ===

public(package) fun request_transaction(
  preimage: vector<u8>,
  message_centralized_signature: vector<u8>,
  psbt: vector<u8>,
): RequestType {
  RequestType::Transaction(preimage, message_centralized_signature, psbt)
}

public(package) fun request_add_member(member_address: address): RequestType {
  RequestType::AddMember(member_address)
}

public(package) fun request_remove_member(member_address: address): RequestType {
  RequestType::RemoveMember(member_address)
}

public(package) fun request_change_approval_threshold(new_approval_threshold: u64): RequestType {
  RequestType::ChangeApprovalThreshold(new_approval_threshold)
}

public(package) fun request_change_rejection_threshold(new_rejection_threshold: u64): RequestType {
  RequestType::ChangeRejectionThreshold(new_rejection_threshold)
}

public(package) fun request_change_expiration_duration(new_expiration_duration: u64): RequestType {
  RequestType::ChangeExpirationDuration(new_expiration_duration)
}

public(package) fun status(request: &mut Request): &mut RequestStatus {
  &mut request.status
}

public(package) fun request_type(request: &mut Request): &mut RequestType {
  &mut request.request_type
}

public(package) fun request_created_at(request: &mut Request): &mut u64 {
  &mut request.created_at
}

public(package) fun approvers_count(request: &mut Request): &mut u64 {
  &mut request.approvers_count
}

public(package) fun rejecters_count(request: &mut Request): &mut u64 {
  &mut request.rejecters_count
}

public(package) fun votes(request: &mut Request): &mut Table<address, bool> {
  &mut request.votes
}

public(package) fun tx_unverified_partial_user_signature_cap(
  request: &mut Request,
): &mut Option<UnverifiedPartialUserSignatureCap> {
  &mut request.tx_unverified_partial_user_signature_cap
}

public(package) fun created_at(request: &mut Request): &mut u64 {
  &mut request.created_at
}

// === Request Result Functions ===

public(package) fun resolve_transaction_request(signature_id: ID): RequestResult {
  RequestResult::Transaction(signature_id)
}

public(package) fun resolve_add_member_request(member_address: address): RequestResult {
  RequestResult::AddMember(member_address)
}

public(package) fun resolve_remove_member_request(member_address: address): RequestResult {
  RequestResult::RemoveMember(member_address)
}

public(package) fun resolve_change_approval_threshold_request(
  new_approval_threshold: u64,
): RequestResult {
  RequestResult::ChangeApprovalThreshold(new_approval_threshold)
}

public(package) fun resolve_change_rejection_threshold_request(
  new_rejection_threshold: u64,
): RequestResult {
  RequestResult::ChangeRejectionThreshold(new_rejection_threshold)
}

public(package) fun resolve_change_expiration_duration_request(
  new_expiration_duration: u64,
): RequestResult {
  RequestResult::ChangeExpirationDuration(new_expiration_duration)
}

// === Request Status Functions ===

public(package) fun pending(): RequestStatus {
  RequestStatus::Pending
}

public(package) fun approved(result: RequestResult): RequestStatus {
  RequestStatus::Approved(result)
}

public(package) fun rejected(): RequestStatus {
  RequestStatus::Rejected
}

// === Request Type Checking and Data Extraction Methods ===

/// Checks if the request type is a Bitcoin transaction request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is a Transaction type, `false` otherwise
public(package) fun is_transaction(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::Transaction(_, _, _) => true,
    _ => false,
  }
}

/// Extracts the transaction data from a Transaction request type.
/// Must only be called on Transaction request types.
///
/// # Arguments
/// * `request_type` - Reference to a Transaction request type
///
/// # Returns
/// A tuple containing (preimage, centralized_signature, psbt)
///
/// # Safety
/// Aborts if called on non-Transaction request types. Always check with `is_transaction()` first.
public(package) fun get_transaction_data(
  request_type: &RequestType,
): (vector<u8>, vector<u8>, vector<u8>) {
  match (request_type) {
    RequestType::Transaction(preimage, message_centralized_signature, psbt) => (
      *preimage,
      *message_centralized_signature,
      *psbt,
    ),
    _ => abort 0,
  }
}

/// Checks if the request type is an add member request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is an AddMember type, `false` otherwise
public(package) fun is_add_member(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::AddMember(_) => true,
    _ => false,
  }
}

/// Extracts the member address from an AddMember request type.
///
/// # Arguments
/// * `request_type` - Reference to an AddMember request type
///
/// # Returns
/// The address of the member to be added
///
/// # Safety
/// Aborts if called on non-AddMember request types. Always check with `is_add_member()` first.
public(package) fun get_add_member_address(request_type: &RequestType): address {
  match (request_type) {
    RequestType::AddMember(addr) => *addr,
    _ => abort 0,
  }
}

/// Checks if the request type is a remove member request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is a RemoveMember type, `false` otherwise
public(package) fun is_remove_member(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::RemoveMember(_) => true,
    _ => false,
  }
}

/// Extracts the member address from a RemoveMember request type.
///
/// # Arguments
/// * `request_type` - Reference to a RemoveMember request type
///
/// # Returns
/// The address of the member to be removed
///
/// # Safety
/// Aborts if called on non-RemoveMember request types. Always check with `is_remove_member()` first.
public(package) fun get_remove_member_address(request_type: &RequestType): address {
  match (request_type) {
    RequestType::RemoveMember(addr) => *addr,
    _ => abort 0,
  }
}

/// Checks if the request type is a change approval threshold request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is a ChangeApprovalThreshold type, `false` otherwise
public(package) fun is_change_approval_threshold(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::ChangeApprovalThreshold(_) => true,
    _ => false,
  }
}

/// Extracts the new approval threshold value from a ChangeApprovalThreshold request type.
///
/// # Arguments
/// * `request_type` - Reference to a ChangeApprovalThreshold request type
///
/// # Returns
/// The new approval threshold value
///
/// # Safety
/// Aborts if called on non-ChangeApprovalThreshold request types. Always check with `is_change_approval_threshold()` first.
public(package) fun get_change_approval_threshold_value(request_type: &RequestType): u64 {
  match (request_type) {
    RequestType::ChangeApprovalThreshold(threshold) => *threshold,
    _ => abort 0,
  }
}

/// Checks if the request type is a change rejection threshold request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is a ChangeRejectionThreshold type, `false` otherwise
public(package) fun is_change_rejection_threshold(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::ChangeRejectionThreshold(_) => true,
    _ => false,
  }
}

/// Extracts the new rejection threshold value from a ChangeRejectionThreshold request type.
///
/// # Arguments
/// * `request_type` - Reference to a ChangeRejectionThreshold request type
///
/// # Returns
/// The new rejection threshold value
///
/// # Safety
/// Aborts if called on non-ChangeRejectionThreshold request types. Always check with `is_change_rejection_threshold()` first.
public(package) fun get_change_rejection_threshold_value(request_type: &RequestType): u64 {
  match (request_type) {
    RequestType::ChangeRejectionThreshold(threshold) => *threshold,
    _ => abort 0,
  }
}

/// Checks if the request type is a change expiration duration request.
///
/// # Arguments
/// * `request_type` - Reference to the request type to check
///
/// # Returns
/// `true` if the request is a ChangeExpirationDuration type, `false` otherwise
public(package) fun is_change_expiration_duration(request_type: &RequestType): bool {
  match (request_type) {
    RequestType::ChangeExpirationDuration(_) => true,
    _ => false,
  }
}

/// Extracts the new expiration duration value from a ChangeExpirationDuration request type.
///
/// # Arguments
/// * `request_type` - Reference to a ChangeExpirationDuration request type
///
/// # Returns
/// The new expiration duration value in milliseconds
///
/// # Safety
/// Aborts if called on non-ChangeExpirationDuration request types. Always check with `is_change_expiration_duration()` first.
public(package) fun get_change_expiration_duration_value(request_type: &RequestType): u64 {
  match (request_type) {
    RequestType::ChangeExpirationDuration(duration) => *duration,
    _ => abort 0,
  }
}
