// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Bitcoin Multisig Wallet Module with IKA dWallet 2PC-MPC protocol
///
/// This module implements a distributed multi-signature wallet system for Bitcoin transactions
/// using the IKA dWallet 2PC-MPC protocol. It allows multiple members to collectively approve
/// or reject Bitcoin transactions before execution, providing enhanced security through
/// distributed key management and threshold-based decision making.
///
/// # Key Features
/// - **Configurable Thresholds**: Flexible approval and rejection thresholds for different security requirements
/// - **Time-based Expiration**: Automatic request expiration to prevent stale transactions
/// - **Irrevocable Voting**: Once cast, votes cannot be changed to prevent manipulation
/// - **Governance Operations**: Support for adding/removing members and modifying wallet parameters
/// - **Distributed Key Generation**: Integration with IKA's 2PC-MPC protocol for enhanced security
/// - **Balance Management**: Built-in support for funding protocol fees with IKA and SUI tokens
///
/// # Security Considerations
/// - All voting decisions are final and cannot be changed once cast
/// - Requests automatically expire after a configured duration to prevent indefinite pending states
/// - Threshold validation ensures no single point of failure in the approval process
/// - Cryptographic operations are handled by the secure IKA dWallet protocol
/// - All state changes are atomic and consistent across the distributed system
///
/// # Usage Workflow
/// 1. **Initialization**: Create wallet with `new_multisig()` and complete DKG rounds
/// 2. **Funding**: Add IKA/SUI balances using `add_ika_balance()` and `add_sui_balance()`
/// 3. **Request Creation**: Members create requests using specific request functions
/// 4. **Voting**: Members cast irrevocable votes using `vote_request()`
/// 5. **Execution**: Approved requests are executed using `execute_request()`
module ika_btc_multisig::multisig;

use ika::ika::IKA;
use ika_btc_multisig::{
  constants,
  error,
  multisig_events,
  multisig_request::{Self, Request, RequestType}
};
use ika_dwallet_2pc_mpc::{
  coordinator::DWalletCoordinator,
  coordinator_inner::{DWalletCap, UnverifiedPresignCap, UnverifiedPartialUserSignatureCap},
  sessions_manager::SessionIdentifier
};
use sui::{balance::Balance, clock::Clock, coin::Coin, sui::SUI, table::{Self, Table}, vec_set};

// === Structs ===

/// The main multisig wallet object that manages Bitcoin transaction approvals.
/// This shared object coordinates between multiple members to approve or reject Bitcoin transactions.
/// All state changes are atomic and consistent across the distributed system.
public struct Multisig has key, store {
  /// Unique identifier for this multisig wallet instance
  id: UID,
  /// Distributed wallet capability for creating Bitcoin signatures.
  /// This integrates with IKA's 2PC-MPC protocol for enhanced security.
  dwallet_cap: DWalletCap,
  /// List of member addresses who can vote on requests.
  /// Members are identified by their Sui addresses and must be unique.
  members: vector<address>,
  /// Number of approval votes required to execute a Bitcoin transaction.
  /// Must be greater than 0 and less than or equal to the number of members.
  approval_threshold: u64,
  /// Number of rejection votes required to definitively reject a request.
  /// Must be greater than 0 and less than or equal to the number of members.
  rejection_threshold: u64,
  /// Table storing all active requests indexed by request ID.
  /// Request IDs are auto-incrementing counters for uniqueness.
  requests: Table<u64, Request>,
  /// Duration in milliseconds after which a request automatically expires.
  /// Expired requests cannot be voted on or executed.
  /// A request is considered expired if: created_at + expiration_duration < current_time
  expiration_duration: u64,
  /// Auto-incrementing counter for generating unique request IDs.
  /// Each new request increments this counter to ensure globally unique identifiers
  /// across the multisig wallet's lifetime.
  request_id_counter: u64,
  /// Collection of unverified presign capabilities that require validation before use.
  /// These capabilities represent requested presign sessions that must be verified
  /// as completed before they can be converted to VerifiedPresignCap for signing operations.
  presigns: vector<UnverifiedPresignCap>,
  /// IKA balance of the multisig wallet. Used for paying protocol fees.
  ika_balance: Balance<IKA>,
  /// SUI balance of the multisig wallet. Used for paying protocol fees.
  sui_balance: Balance<SUI>,
  /// ID of the network encryption key
  dwallet_network_encryption_key_id: ID,
}

public struct MultisigOwnership has key {
  /// Unique identifier for this multisig ownership object.
  id: UID,
  /// ID of the multisig wallet that this ownership object belongs to.
  multisig_id: ID,
}

// === Public Functions ===

/// Creates a new multisig wallet with the specified configuration.
/// This function initializes the distributed key generation process and sets up the wallet.
///
/// # Arguments
/// * `coordinator` - The IKA dWallet coordinator for managing the distributed key generation
/// * `initial_ika_coin_for_balance` - Initial IKA tokens to fund the wallet's balance for protocol fees
/// * `initial_sui_coin_for_balance` - Initial SUI tokens to fund the wallet's balance for protocol fees
/// * `dwallet_network_encryption_key_id` - ID of the network encryption key for secure communication
/// * `centralized_public_key_share_and_proof` - Centralized public key share and proof
/// * `user_public_output` - User's public output
/// * `public_user_secret_key_share` - Public user secret key share
/// * `members` - List of member addresses who can vote on transactions
/// * `approval_threshold` - Number of approvals required to execute transactions
/// * `rejection_threshold` - Number of rejections required to reject transactions
/// * `expiration_duration` - How long requests remain valid (in milliseconds)
/// * `ctx` - Transaction context for creating the shared object
///
/// # Returns
/// Shares the Multisig object publicly so all members can interact with it.
///
/// # Security Requirements
/// * `approval_threshold` must be > 0 and <= number of members
/// * `rejection_threshold` must be > 0 and <= number of members
/// * `members` vector must not be empty and contain unique addresses
/// * Caller must have sufficient IKA and SUI tokens for DKG fees
public fun new_multisig(
  coordinator: &mut DWalletCoordinator,
  mut initial_ika_coin_for_balance: Coin<IKA>,
  mut initial_sui_coin_for_balance: Coin<SUI>,
  dwallet_network_encryption_key_id: ID,
  centralized_public_key_share_and_proof: vector<u8>,
  user_public_output: vector<u8>,
  public_user_secret_key_share: vector<u8>,
  session_identifier: vector<u8>,
  members: vector<address>,
  approval_threshold: u64,
  rejection_threshold: u64,
  expiration_duration: u64,
  ctx: &mut TxContext,
) {
  assert!(approval_threshold > 0, error::invalid_approval_threshold!());
  assert!(rejection_threshold > 0, error::invalid_rejection_threshold!());
  assert!(approval_threshold <= members.length(), error::approval_threshold_too_high!());
  assert!(rejection_threshold <= members.length(), error::rejection_threshold_too_high!());
  assert!(members.length() > 0, error::empty_member_list!());

  // A way to make sure the members in the vector is not duplicated.
  let members_non_duplicated = vec_set::from_keys(members).into_keys();

  let registered_session_identifier = coordinator.register_session_identifier(
    session_identifier,
    ctx,
  );

  let (dwallet_cap, _) = coordinator.request_dwallet_dkg_with_public_user_secret_key_share(
    dwallet_network_encryption_key_id,
    constants::curve!(),
    centralized_public_key_share_and_proof,
    user_public_output,
    public_user_secret_key_share,
    option::none(),
    registered_session_identifier,
    &mut initial_ika_coin_for_balance,
    &mut initial_sui_coin_for_balance,
    ctx,
  );

  let mut multisig = Multisig {
    id: object::new(ctx),
    dwallet_cap: dwallet_cap,
    members: members_non_duplicated,
    approval_threshold: approval_threshold,
    rejection_threshold: rejection_threshold,
    requests: table::new(ctx),
    expiration_duration: expiration_duration,
    request_id_counter: 0,
    presigns: vector::empty(),
    ika_balance: initial_ika_coin_for_balance.into_balance(),
    sui_balance: initial_sui_coin_for_balance.into_balance(),
    dwallet_network_encryption_key_id: dwallet_network_encryption_key_id,
  };

  let session_identifier = random_session_identifier(coordinator, ctx);

  let (mut payment_ika, mut payment_sui) = multisig.withdraw_payment_coins(ctx);

  multisig
    .presigns
    .push_back(coordinator.request_global_presign(
      dwallet_network_encryption_key_id,
      constants::curve!(),
      constants::signature_algorithm!(),
      session_identifier,
      &mut payment_ika,
      &mut payment_sui,
      ctx,
    ));

  multisig.return_payment_coins(payment_ika, payment_sui);

  multisig_events::multisig_created(
    object::id(&multisig),
    members_non_duplicated,
    approval_threshold,
    rejection_threshold,
    expiration_duration,
    ctx.sender(),
  );

  members_non_duplicated.do!(|member| {
    let ownership = MultisigOwnership {
      id: object::new(ctx),
      multisig_id: object::id(&multisig),
    };

    transfer::transfer(ownership, member);
  });

  transfer::public_share_object(multisig);
}

/// Adds IKA tokens to the multisig wallet's balance for paying protocol fees.
/// This function allows topping up the wallet's IKA token reserves that are used
/// to pay for distributed key generation, presign, and signing operations.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `ika_coin` - IKA coin to add to the wallet's balance
/// * `ctx` - Transaction context for the operation
///
/// # Usage
/// Use this function to fund the wallet with IKA tokens before performing
/// operations that require protocol fees. The tokens are stored in the
/// wallet's balance and automatically used when needed.
public fun add_ika_balance(self: &mut Multisig, ika_coin: Coin<IKA>, ctx: &TxContext) {
  let amount = ika_coin.value();
  self.ika_balance.join(ika_coin.into_balance());

  multisig_events::balance_added(
    object::id(self),
    ctx.sender(),
    amount,
    0,
  );
}

/// Adds SUI tokens to the multisig wallet's balance for paying protocol fees.
/// This function allows topping up the wallet's SUI token reserves that are used
/// to pay for distributed key generation, presign, and signing operations.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `sui_coin` - SUI coin to add to the wallet's balance
/// * `ctx` - Transaction context for the operation
///
/// # Usage
/// Use this function to fund the wallet with SUI tokens before performing
/// operations that require protocol fees. The tokens are stored in the
/// wallet's balance and automatically used when needed.
public fun add_sui_balance(self: &mut Multisig, sui_coin: Coin<SUI>, ctx: &TxContext) {
  let amount = sui_coin.value();
  self.sui_balance.join(sui_coin.into_balance());

  multisig_events::balance_added(
    object::id(self),
    ctx.sender(),
    0,
    amount,
  );
}

/// Adds a presign capability to the multisig wallet.
/// This function allows adding a presign capability to the wallet's presigns vector.
/// Presign capabilities are used for Bitcoin transaction signing and must be available
/// before executing a Transaction request.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator for presign operations
/// * `ctx` - Transaction context for the operation
public fun add_presign(
  self: &mut Multisig,
  coordinator: &mut DWalletCoordinator,
  ctx: &mut TxContext,
) {
  assert!(self.members.contains(&ctx.sender()), error::caller_not_member!());

  let (mut payment_ika, mut payment_sui) = self.withdraw_payment_coins(ctx);

  let session_identifier = random_session_identifier(coordinator, ctx);

  self
    .presigns
    .push_back(coordinator.request_global_presign(
      self.dwallet_network_encryption_key_id,
      constants::curve!(),
      constants::signature_algorithm!(),
      session_identifier,
      &mut payment_ika,
      &mut payment_sui,
      ctx,
    ));

  multisig_events::presign_added(
    object::id(self),
    ctx.sender(),
    self.presigns.length(),
  );

  self.return_payment_coins(payment_ika, payment_sui);
}

/// Casts a vote on an existing multisig request.
/// Members can vote exactly once per request (approval or rejection).
/// Votes are irrevocable and contribute toward reaching approval or rejection thresholds.
///
/// When voting thresholds are reached, the request status is updated but execution
/// must be triggered separately via execute_request. This allows for batched processing
/// and gives more control over when requests are actually executed.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `request_id` - The unique ID of the request to vote on
/// * `vote` - The vote decision: true for approval, false for rejection
/// * `clock` - Clock for checking request expiration
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// Updates the request's vote counts. Call execute_request separately to process
/// the request once voting thresholds are reached.
///
/// # Security Requirements
/// * Request must exist and be in Pending status
/// * Caller must be an active member of the multisig wallet
/// * Member cannot vote twice on the same request (irrevocable voting)
/// * Vote immediately contributes to threshold calculations
/// * Execution is separate from voting for better control
public fun vote_request(
  self: &mut Multisig,
  request_id: u64,
  vote: bool,
  clock: &Clock,
  ctx: &mut TxContext,
) {
  assert!(self.requests.contains(request_id), error::request_not_found!());
  let multisig_id = object::id(self);

  let request = self.requests.borrow_mut(request_id);

  assert!(request.status() == multisig_request::pending(), error::request_not_pending!());
  assert!(self.members.contains(&ctx.sender()), error::caller_not_member!());
  assert!(!request.votes().contains(ctx.sender()), error::already_voted!());

  if (clock.timestamp_ms() > *request.created_at() + self.expiration_duration) {
    self.reject_request(request_id);
    return
  };

  request.votes().add(ctx.sender(), vote);

  if (vote) {
    *request.approvers_count() = *request.approvers_count() + 1;
  } else {
    *request.rejecters_count() = *request.rejecters_count() + 1;
  };

  if (*request.rejecters_count() >= self.rejection_threshold) {
    self.reject_request(request_id);
    return
  };

  multisig_events::vote_request(
    multisig_id,
    request_id,
    ctx.sender(),
    vote,
    *request.approvers_count(),
    *request.rejecters_count(),
  );
}

/// Executes an approved request or marks it as rejected.
/// This is the final step in the multisig request lifecycle.
/// It checks if voting thresholds are met and either executes the approved action
/// or permanently rejects the request. Can be called by anyone after thresholds are reached.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator for Bitcoin transaction signing
/// * `request_id` - The unique ID of the request to execute
/// * `clock` - Clock for checking request expiration before execution
/// * `ctx` - Transaction context for the operation
///
/// # Execution Flow
/// 1. **Expiration Check**: Verifies request hasn't expired before processing
/// 2. **Threshold Validation**: Checks that voting thresholds are actually met
/// 3. **Rejection Case**: If rejection threshold reached or expired, mark request as rejected
/// 4. **Approval Case**: If approval threshold reached, match on request type and execute:
///    - SendBTC: Signs Bitcoin transaction using presign capabilities and returns signature ID
///    - AddMember: Adds member to the members vector
///    - RemoveMember: Removes member from the members vector
///    - ChangeApprovalThreshold: Updates the approval threshold
///    - ChangeRejectionThreshold: Updates the rejection threshold
///    - ChangeExpirationDuration: Updates the expiration duration
///
/// # State Changes
/// - Request status becomes Approved(result) or Rejected
/// - Wallet configuration may be modified (members, thresholds, duration)
/// - All changes are atomic within the transaction
///
/// # Security Notes
/// - Validates thresholds before execution (prevents premature execution)
/// - All state changes are permanent and cannot be reversed
/// - Governance actions take effect immediately
/// - Can be called by any party after thresholds are reached
public fun execute_request(
  self: &mut Multisig,
  coordinator: &mut DWalletCoordinator,
  request_id: u64,
  clock: &Clock,
  ctx: &mut TxContext,
) {
  let multisig_id = object::id(self);
  let (mut payment_ika, mut payment_sui) = self.withdraw_payment_coins(ctx);

  let request = self.requests.borrow_mut(request_id);

  if (clock.timestamp_ms() > *request.created_at() + self.expiration_duration) {
    self.reject_request(request_id);
    self.return_payment_coins(payment_ika, payment_sui);
    return
  };

  assert!(
    *request.approvers_count() >= self.approval_threshold || *request.rejecters_count() >= self.rejection_threshold,
    error::insufficient_votes!(),
  );

  if (*request.rejecters_count() >= self.rejection_threshold) {
    self.reject_request(request_id);
    self.return_payment_coins(payment_ika, payment_sui);
    return
  };

  let request_type = request.request_type();

  let result = if (request_type.is_transaction()) {
    let (preimage, _, _) = request_type.get_transaction_data();

    let unverified_partial_user_signature_cap = request
      .tx_unverified_partial_user_signature_cap()
      .extract();

    let verified_partial_user_signature_cap = coordinator.verify_partial_user_signature_cap(
      unverified_partial_user_signature_cap,
      ctx,
    );

    let message_approval = coordinator.approve_message(
      &self.dwallet_cap,
      constants::signature_algorithm!(),
      constants::hash_scheme!(),
      preimage,
    );

    let session_identifier = random_session_identifier(coordinator, ctx);

    let sign_id = coordinator.request_sign_with_partial_user_signature_and_return_id(
      verified_partial_user_signature_cap,
      message_approval,
      session_identifier,
      &mut payment_ika,
      &mut payment_sui,
      ctx,
    );

    multisig_request::resolve_transaction_request(sign_id)
  } else if (request_type.is_add_member()) {
    let member_address = request_type.get_add_member_address();

    if (self.members.contains(&member_address)) {
      self.reject_request(request_id);
      self.return_payment_coins(payment_ika, payment_sui);
      return
    };

    self.members.push_back(member_address);

    let ownership = MultisigOwnership {
      id: object::new(ctx),
      multisig_id,
    };

    transfer::transfer(ownership, member_address);

    multisig_request::resolve_add_member_request(member_address)
  } else if (request_type.is_remove_member()) {
    let member_address = request_type.get_remove_member_address();
    let mut index = self.members.find_index!(|member| member_address == *member);

    if (index.is_none()) {
      self.reject_request(request_id);
      self.return_payment_coins(payment_ika, payment_sui);
      return
    };

    self.members.swap_remove(index.extract());
    multisig_request::resolve_remove_member_request(member_address)
  } else if (request_type.is_change_approval_threshold()) {
    let new_threshold = request_type.get_change_approval_threshold_value();

    if (new_threshold > self.members.length()) {
      self.reject_request(request_id);
      self.return_payment_coins(payment_ika, payment_sui);
      return
    };

    self.approval_threshold = new_threshold;
    multisig_request::resolve_change_approval_threshold_request(new_threshold)
  } else if (request_type.is_change_rejection_threshold()) {
    let new_threshold = request_type.get_change_rejection_threshold_value();

    if (new_threshold > self.members.length()) {
      self.reject_request(request_id);
      self.return_payment_coins(payment_ika, payment_sui);
      return
    };

    self.rejection_threshold = new_threshold;
    multisig_request::resolve_change_rejection_threshold_request(new_threshold)
  } else if (request_type.is_change_expiration_duration()) {
    let new_duration = request_type.get_change_expiration_duration_value();
    self.expiration_duration = new_duration;
    multisig_request::resolve_change_expiration_duration_request(new_duration)
  } else {
    abort 0 // This should never happen if all cases are covered
  };

  *request.status() = multisig_request::approved(result);

  multisig_events::request_resolved(multisig_id, request_id, *request.status());

  self.return_payment_coins(payment_ika, payment_sui);
}

// === Request Creation Functions ===

/// Creates a Bitcoin transaction request with all necessary signing components.
/// This function constructs a complete Transaction request by creating the necessary
/// partial user signature capability and preparing all components for multisig signing.
///
/// The function handles the complex setup required for Bitcoin transaction signing,
/// including presign verification and partial signature capability creation.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator for signature operations
/// * `preimage` - BIP 341 preimage for the transaction
/// * `message_centralized_signature` - Centralized signature component for the transaction
/// * `psbt` - Complete serialized Bitcoin transaction in hexadecimal format
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// The unique request ID that was assigned to the Bitcoin transaction request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * A presign capability must be available in the wallet
/// * All cryptographic components are properly initialized
/// * Request creation automatically replenishes presign capabilities if needed
///
/// # Usage
/// This request type requires approval_threshold votes to execute and will
/// trigger Bitcoin transaction signing through the IKA dWallet protocol.
public fun transaction_request(
  self: &mut Multisig,
  coordinator: &mut DWalletCoordinator,
  preimage: vector<u8>,
  message_centralized_signature: vector<u8>,
  psbt: vector<u8>,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  let (mut payment_ika, mut payment_sui) = self.withdraw_payment_coins(ctx);

  let session_identifier = random_session_identifier(coordinator, ctx);
  let unverified_presign_cap = self.presigns.swap_remove(0);
  let verified_presign_cap = coordinator.verify_presign_cap(unverified_presign_cap, ctx);

  let unverified_partial_user_signature_cap_from_request_sign = coordinator.request_future_sign(
    self.dwallet_cap.dwallet_id(),
    verified_presign_cap,
    preimage,
    constants::hash_scheme!(),
    message_centralized_signature,
    session_identifier,
    &mut payment_ika,
    &mut payment_sui,
    ctx,
  );

  if (self.presigns.length() == 0) {
    let session_identifier = random_session_identifier(coordinator, ctx);

    self
      .presigns
      .push_back(coordinator.request_global_presign(
        self.dwallet_network_encryption_key_id,
        constants::curve!(),
        constants::signature_algorithm!(),
        session_identifier,
        &mut payment_ika,
        &mut payment_sui,
        ctx,
      ));
  };

  self.return_payment_coins(payment_ika, payment_sui);

  self.new_request(
    multisig_request::request_transaction(preimage, message_centralized_signature, psbt),
    option::some(unverified_partial_user_signature_cap_from_request_sign),
    clock,
    ctx,
  )
}

/// Creates a governance request to add a new member to the multisig wallet.
/// This function validates that the address is not already a member and that the
/// caller is an existing member before creating the request. Adding members affects
/// voting thresholds and requires collective approval.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `member_address` - The Sui address of the new member to add
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the add member request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * Address must not already be a member (prevents duplicates)
/// * Requires approval_threshold votes to execute
/// * New member gains full voting rights immediately upon approval
public fun add_member_request(
  self: &mut Multisig,
  member_address: address,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(!self.members.contains(&member_address), error::member_already_exists!());

  self.new_request(
    multisig_request::request_add_member(member_address),
    option::none(),
    clock,
    ctx,
  )
}

/// Creates a governance request to remove an existing member from the multisig wallet.
/// This function validates that the address is currently a member and that the
/// caller is an existing member before creating the request. Removing members affects
/// existing votes and requires careful consideration.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `member_address` - The Sui address of the member to remove
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the remove member request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * Address must be an existing member
/// * Requires approval_threshold votes to execute
/// * Removed member loses all voting rights and cannot create new requests
public fun remove_member_request(
  self: &mut Multisig,
  member_address: address,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(self.members.contains(&member_address), error::member_not_found!());

  self.new_request(
    multisig_request::request_remove_member(member_address),
    option::none(),
    clock,
    ctx,
  )
}

/// Creates a governance request to modify the approval threshold.
/// This function validates that the new threshold is greater than zero and that the
/// caller is an existing member. Increasing the threshold makes transactions harder
/// to approve; decreasing makes them easier.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_threshold` - The new approval threshold value (> 0)
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change approval threshold request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New threshold must be greater than zero
/// * New threshold must be less than or equal to the number of members
/// * Requires approval_threshold votes to execute (based on current threshold)
/// * Affects all future transaction requests immediately upon approval
public fun change_approval_threshold_request(
  self: &mut Multisig,
  new_threshold: u64,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(new_threshold > 0, error::invalid_threshold!());
  assert!(new_threshold <= self.members.length(), error::invalid_threshold!());

  self.new_request(
    multisig_request::request_change_approval_threshold(new_threshold),
    option::none(),
    clock,
    ctx,
  )
}

/// Creates a governance request to modify the rejection threshold.
/// This function validates that the new threshold is greater than zero and that the
/// caller is an existing member. Increasing the threshold makes rejection harder;
/// decreasing makes it easier.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_threshold` - The new rejection threshold value (> 0)
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change rejection threshold request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New threshold must be greater than zero
/// * New threshold must be less than or equal to the number of members
/// * Requires approval_threshold votes to execute
/// * Affects all future requests immediately upon approval
public fun change_rejection_threshold_request(
  self: &mut Multisig,
  new_threshold: u64,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(new_threshold > 0, error::invalid_rejection_threshold_specific!());
  assert!(new_threshold <= self.members.length(), error::invalid_rejection_threshold_specific!());

  self.new_request(
    multisig_request::request_change_rejection_threshold(new_threshold),
    option::none(),
    clock,
    ctx,
  )
}

/// Creates a governance request to modify the request expiration duration.
/// This function validates that the new duration is greater than zero and that the
/// caller is an existing member. Setting the duration too low may cause requests
/// to expire before voting completes.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_duration` - The new expiration duration in milliseconds (> 0)
/// * `clock` - Clock for getting the current timestamp for request expiration tracking
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change expiration duration request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New duration must be greater than zero
/// * Requires approval_threshold votes to execute
/// * Affects all future requests created after approval
public fun change_expiration_duration_request(
  self: &mut Multisig,
  new_duration: u64,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(new_duration > 0, error::invalid_expiration_duration!());

  self.new_request(
    multisig_request::request_change_expiration_duration(new_duration),
    option::none(),
    clock,
    ctx,
  )
}

// === Private Helper Functions ===

/// Generates a random session identifier for DKG operations.
/// Uses the transaction context's fresh object address to create a unique identifier.
///
/// # Arguments
/// * `coordinator` - The dWallet coordinator that will register the session
/// * `ctx` - Transaction context containing the fresh address generator
///
/// # Returns
/// A new SessionIdentifier registered with the coordinator
///
fun random_session_identifier(
  coordinator: &mut DWalletCoordinator,
  ctx: &mut TxContext,
): SessionIdentifier {
  coordinator.register_session_identifier(
    ctx.fresh_object_address().to_bytes(),
    ctx,
  )
}

/// Creates a new request to be voted on by the multisig members.
/// This function initializes a new request with the specified type and parameters,
/// assigning it a unique ID and setting up the initial voting state.
///
/// The request starts in Pending status and must be approved by the required threshold
/// of members before it can be executed. Only multisig members can create requests.
///
/// For SendBTC requests, the unverified partial user signature capability is validated
/// and stored for later use during execution. The capability is created by the calling
/// function and passed in as an Option parameter.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `request_type` - The type of request to create (SendBTC, AddMember, etc.)
/// * `unverified_partial_user_signature_cap` - Optional capability for SendBTC requests
/// * `clock` - Clock for getting the current timestamp for expiration tracking
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// The unique request ID that was assigned to the newly created request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * SendBTC requests must include a valid unverified partial user signature capability
/// * Request ID is guaranteed to be unique within this wallet
/// * Request starts with zero votes and Pending status
/// * Signature capability is validated against the request type
fun new_request(
  self: &mut Multisig,
  request_type: RequestType,
  unverified_partial_user_signature_cap: Option<UnverifiedPartialUserSignatureCap>,
  clock: &Clock,
  ctx: &mut TxContext,
): u64 {
  assert!(self.members.contains(&ctx.sender()), error::caller_not_member!());

  let request = multisig_request::create_request(
    request_type,
    unverified_partial_user_signature_cap,
    clock,
    ctx,
  );

  self.request_id_counter = self.request_id_counter + 1;

  multisig_events::request_created(
    object::id(self),
    self.request_id_counter,
    request_type,
    ctx.sender(),
  );

  self.requests.add(self.request_id_counter, request);

  self.request_id_counter
}

/// Withdraws all IKA and SUI tokens from the multisig wallet's balance for payment.
/// This helper function extracts all available tokens from the wallet's balances
/// to use for paying protocol fees in IKA dWallet operations.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `ctx` - Transaction context for creating the coin objects
///
/// # Returns
/// A tuple containing the withdrawn IKA and SUI coins
///
/// # Security Notes
/// This function withdraws all available tokens. Ensure that return_payment_coins
/// is called to restore any unused funds to maintain the wallet's balance.
fun withdraw_payment_coins(self: &mut Multisig, ctx: &mut TxContext): (Coin<IKA>, Coin<SUI>) {
  let payment_ika = self.ika_balance.withdraw_all().into_coin(ctx);
  let payment_sui = self.sui_balance.withdraw_all().into_coin(ctx);
  (payment_ika, payment_sui)
}

/// Returns unused payment coins back to the multisig wallet's balance.
/// This helper function restores any remaining IKA and SUI tokens to the wallet's
/// balances after completing protocol operations that required payment.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `payment_ika` - Remaining IKA coin to return to balance
/// * `payment_sui` - Remaining SUI coin to return to balance
///
/// # Usage
/// Always call this function after protocol operations to ensure unused
/// payment funds are returned to the wallet's balance for future use.
fun return_payment_coins(self: &mut Multisig, payment_ika: Coin<IKA>, payment_sui: Coin<SUI>) {
  self.ika_balance.join(payment_ika.into_balance());
  self.sui_balance.join(payment_sui.into_balance());
}

fun reject_request(self: &mut Multisig, request_id: u64) {
  let multisig_id = object::id(self);
  let request = self.requests.borrow_mut(request_id);
  *request.status() = multisig_request::rejected();

  multisig_events::request_resolved(multisig_id, request_id, *request.status());
}
