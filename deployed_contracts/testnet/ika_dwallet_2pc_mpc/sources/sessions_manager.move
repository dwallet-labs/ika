// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_dwallet_2pc_mpc::sessions_manager;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::pricing::PricingInfoValue;
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::coin::Coin;
use sui::event;
use sui::object_table::{Self, ObjectTable};
use sui::sui::SUI;
use sui::table::{Self, Table};

// === Constants ===

/// Session identifier length
const SESSION_IDENTIFIER_LENGTH: u64 = 32;

// === Errors ===

/// Insufficient IKA payment
const EInsufficientIKAPayment: u64 = 1;
/// Insufficient SUI payment
const EInsufficientSUIPayment: u64 = 2;
/// Session identifier already registered
const ESessionIdentifierAlreadyRegistered: u64 = 3;
/// Session identifier does not exist
const ESessionIdentifierNotExist: u64 = 4;
/// Session identifier is invalid
const ESessionIdentifierInvalidLength: u64 = 5;
/// Not all current epoch sessions are completed
const ENotAllCurrentEpochSessionsCompleted: u64 = 6;

// === Structs ===

public struct SessionsKeeper has store {
    /// Active sessions indexed by sequence number
    sessions: ObjectTable<u64, DWalletSession>,
    /// Events for sessions, keyed by session ID
    session_events: Bag,
    /// Count of started sessions
    started_sessions_count: u64,
    /// Count of completed sessions
    completed_sessions_count: u64,
    /// The sequence number to assign to the next session.
    /// Initialized to `1` and incremented at every new session creation.
    next_session_sequence_number: u64,
}

/// Session management data for the dWallet coordinator.
public struct SessionsManager has store {
    /// Registered user session identifiers, keyed by the session identifier bytes -> to session object ID
    registered_user_session_identifiers: Table<vector<u8>, ID>,
    /// Holds the data for user-initiated sessions
    user_sessions_keeper: SessionsKeeper,
    /// Holds the data for system-initiated sessions
    system_sessions_keeper: SessionsKeeper,
    /// The last MPC session to process in the current epoch.
    /// The validators of the Ika network must always begin sessions,
    /// when they become available to them, so long their sequence number is lesser or equal to this value.
    /// Initialized to `0`, as when the system is initialized no user-requested session exists so none should be started
    /// and we shouldn't wait for any to complete before advancing epoch (until the first session is created),
    /// and updated at every new session creation or completion, and when advancing epochs,
    /// to the latest session whilst assuring a maximum of `max_active_sessions_buffer` sessions to be completed in the current epoch.
    /// Validators should complete every session they start before switching epochs.
    last_user_initiated_session_to_complete_in_current_epoch: u64,
    /// Denotes whether the `last_user_initiated_session_to_complete_in_current_epoch` field is locked or not.
    /// This field gets locked before performing the epoch switch.
    locked_last_user_initiated_session_to_complete_in_current_epoch: bool,
    /// The maximum number of active MPC sessions Ika nodes may run during an epoch.
    /// Validators should complete every session they start before switching epochs.
    max_active_sessions_buffer: u64,
}

/// Represents an active MPC session in the Ika network.
///
/// Each session tracks fees and is associated with a network encryption key.
/// Sessions are sequentially numbered for epoch management.
public struct DWalletSession has key, store {
    id: UID,
    /// Session identifier
    session_identifier: SessionIdentifier,
    /// Sequential number for session ordering
    session_sequence_number: u64,
    /// Associated network encryption key
    dwallet_network_encryption_key_id: ID,
    /// IKA fees for the session
    fee_charged_ika: Balance<IKA>,
    /// SUI balance for gas reimbursement
    gas_fee_reimbursement_sui: Balance<SUI>,
}

/// Type of dWallet MPC session for scheduling and epoch management.
///
/// User-initiated sessions have sequence numbers for multi-epoch completion scheduling.
/// System sessions are guaranteed to complete within their creation epoch.
public enum SessionType has copy, drop, store {
    /// User-initiated session (across epochs scheduling)
    User,
    /// System-initiated session (always completes in current epoch)
    System,
}

/// The preimage is used to create the session identifier.
public struct SessionIdentifier has key, store {
    id: UID,
    identifier_preimage: vector<u8>,
}

// === Events ===

/// Event emitted when a user session identifier is registered.
///
/// This event signals that a new user session identifier has been registered and is
/// ready for use in the dWallet system.
public struct UserSessionIdentifierRegisteredEvent has copy, drop, store {
    /// ID of the session object
    session_object_id: ID,
    /// Unique session identifier
    session_identifier_preimage: vector<u8>,
}

/// Generic wrapper for dWallet-related events with session context.
///
/// Provides standardized metadata for all dWallet operations including
/// epoch information, session type, and session ID for tracking and debugging.
public struct DWalletSessionEvent<E: copy + drop + store> has copy, drop, store {
    /// Epoch when the event occurred
    epoch: u64,
    /// ID of the session object
    session_object_id: ID,
    /// Type of session (User or System)
    session_type: SessionType,
    /// Sequential number for session ordering
    session_sequence_number: u64,
    /// Unique session identifier
    session_identifier_preimage: vector<u8>,
    /// Event-specific data
    event_data: E,
}

/// The status of a dWallet session result event.
///
/// This enum represents the possible outcomes of a dWallet session event.
/// It can either be successful or rejected, with event-specific data for each case.
public enum DWalletSessionStatusEvent<
    Success: copy + drop + store,
    Rejected: copy + drop + store,
> has copy, drop, store {
    /// The event was successful
    Success(Success),
    /// The event was rejected
    Rejected(Rejected),
}

/// Event emitted when a dWallet session result is completed.
///
/// This event signals that a dWallet session has been completed and provides
/// the status of the session (success or rejection) along with the event-specific
/// data for each case.
public struct DWalletSessionResultEvent<
    E: copy + drop + store,
    Success: copy + drop + store,
    Rejected: copy + drop + store,
> has copy, drop, store {
    /// Epoch when the event occurred
    epoch: u64,
    /// Epoch when the event was initiated
    event_initiated_at_epoch: u64,
    /// ID of the session object
    session_object_id: ID,
    /// Type of session (User or System)
    session_type: SessionType,
    /// Sequential number for session ordering
    session_sequence_number: u64,
    /// The identifier of the session
    session_identifier_preimage: vector<u8>,
    /// Event-specific data of the session initiator
    session_initiator_event_data: E,
    /// The status of the event
    status: DWalletSessionStatusEvent<Success, Rejected>,
}

// === Package Functions ===

/// Creates a new SessionsManager instance.
///
/// Initializes all internal data structures with default values.
///
/// ### Parameters
/// - `ctx`: Transaction context for object creation
///
public(package) fun create(ctx: &mut TxContext): SessionsManager {
    SessionsManager {
        registered_user_session_identifiers: table::new(ctx),
        user_sessions_keeper: SessionsKeeper {
            sessions: object_table::new(ctx),
            session_events: bag::new(ctx),
            started_sessions_count: 0,
            completed_sessions_count: 0,
            next_session_sequence_number: 1,
        },
        system_sessions_keeper: SessionsKeeper {
            sessions: object_table::new(ctx),
            session_events: bag::new(ctx),
            started_sessions_count: 0,
            completed_sessions_count: 0,
            next_session_sequence_number: 1,
        },
        last_user_initiated_session_to_complete_in_current_epoch: 0,
        locked_last_user_initiated_session_to_complete_in_current_epoch: true,
        max_active_sessions_buffer: 100,
    }
}

/// Locks the last active user-initiated session sequence number to prevent further updates.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
///
/// ### Effects
/// - Prevents further updates to `last_user_initiated_session_to_complete_in_current_epoch`
/// - Ensures session completion targets remain stable during epoch transitions
public(package) fun lock_last_user_initiated_session_to_complete_in_current_epoch(
    self: &mut SessionsManager,
) {
    self.locked_last_user_initiated_session_to_complete_in_current_epoch = true;
}

/// Registers a new session identifier.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager.
/// - `identifier_preimage`: The preimage bytes for creating the session identifier.
/// - `ctx`: Transaction context for object creation.
public(package) fun register_session_identifier(
    self: &mut SessionsManager,
    identifier_preimage: vector<u8>,
    ctx: &mut TxContext,
): SessionIdentifier {
    assert!(
        identifier_preimage.length() == SESSION_IDENTIFIER_LENGTH,
        ESessionIdentifierInvalidLength,
    );
    assert!(
        !self.registered_user_session_identifiers.contains(identifier_preimage),
        ESessionIdentifierAlreadyRegistered,
    );
    let id = object::new(ctx);
    self.registered_user_session_identifiers.add(identifier_preimage, id.to_inner());
    event::emit(UserSessionIdentifierRegisteredEvent {
        session_object_id: id.to_inner(),
        session_identifier_preimage: identifier_preimage,
    });
    SessionIdentifier {
        id,
        identifier_preimage,
    }
}

/// Advances the epoch by ensuring all current epoch sessions are completed.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
///
/// ### Effects
/// - Asserts that all current epoch sessions are completed
/// - Unlocks the last active user-initiated session sequence number
/// - Updates the last active user-initiated session sequence number to the latest session sequence number
public(package) fun advance_epoch(self: &mut SessionsManager) {
    assert!(self.all_current_epoch_sessions_completed(), ENotAllCurrentEpochSessionsCompleted);
    self.locked_last_user_initiated_session_to_complete_in_current_epoch = false;
    self.update_last_user_initiated_session_to_complete_in_current_epoch();
}

/// Creates a success status event for a dWallet session.
public(package) fun create_success_status_event<
    Success: copy + drop + store,
    Rejected: copy + drop + store,
>(
    event_data: Success,
): DWalletSessionStatusEvent<Success, Rejected> {
    DWalletSessionStatusEvent::Success(event_data)
}

/// Creates a rejected status event for a dWallet session.
public(package) fun create_rejected_status_event<
    Success: copy + drop + store,
    Rejected: copy + drop + store,
>(
    event_data: Rejected,
): DWalletSessionStatusEvent<Success, Rejected> {
    DWalletSessionStatusEvent::Rejected(event_data)
}

/// Initiates a user-initiated session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
/// - `epoch`: The epoch number
/// - `session_identifier`: The session identifier
/// - `dwallet_network_encryption_key_id`: The ID of the dWallet network encryption key
/// - `pricing_value`: The pricing value for the session
/// - `payment_ika`: The payment for the session in IKA
/// - `payment_sui`: The payment for the session in SUI
/// - `event_data`: The event data for the session
/// - `ctx`: The transaction context
///
/// ### Returns
/// The amount of SUI paid for gas reimbursement for system calls
public(package) fun initiate_user_session<E: copy + drop + store>(
    self: &mut SessionsManager,
    epoch: u64,
    session_identifier: SessionIdentifier,
    dwallet_network_encryption_key_id: ID,
    pricing_value: PricingInfoValue,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    event_data: E,
    ctx: &mut TxContext,
): Balance<SUI> {
    assert!(payment_ika.value() >= pricing_value.fee_ika(), EInsufficientIKAPayment);
    assert!(
        payment_sui.value() >= pricing_value.gas_fee_reimbursement_sui() + pricing_value.gas_fee_reimbursement_sui_for_system_calls(),
        EInsufficientSUIPayment,
    );

    let fee_charged_ika = payment_ika.split(pricing_value.fee_ika(), ctx).into_balance();
    let gas_fee_reimbursement_sui = payment_sui
        .split(pricing_value.gas_fee_reimbursement_sui(), ctx)
        .into_balance();
    let gas_fee_reimbursement_sui_for_system_calls = payment_sui
        .split(pricing_value.gas_fee_reimbursement_sui_for_system_calls(), ctx)
        .into_balance();

    let identifier_preimage = session_identifier.identifier_preimage;
    assert!(
        self.registered_user_session_identifiers.contains(identifier_preimage),
        ESessionIdentifierNotExist,
    );
    assert!(
        self.registered_user_session_identifiers.borrow(identifier_preimage) == session_identifier.id.to_inner(),
        ESessionIdentifierNotExist,
    );

    self
        .user_sessions_keeper
        .initiate_session(
            epoch,
            session_identifier,
            dwallet_network_encryption_key_id,
            SessionType::User,
            event_data,
            fee_charged_ika,
            gas_fee_reimbursement_sui,
            ctx,
        );

    self.update_last_user_initiated_session_to_complete_in_current_epoch();

    gas_fee_reimbursement_sui_for_system_calls
}

/// Completes a user-initiated session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
/// - `session_sequence_number`: The sequence number of the session
/// - `status`: The status of the session
///
/// ### Returns
/// A tuple containing the amount of IKA fees paid and SUI for gas reimbursement for the session
public(package) fun complete_user_session<
    E: copy + drop + store,
    Success: copy + drop + store,
    Rejected: copy + drop + store,
>(
    self: &mut SessionsManager,
    epoch: u64,
    session_sequence_number: u64,
    status: DWalletSessionStatusEvent<Success, Rejected>,
): (Balance<IKA>, Balance<SUI>) {
    let (fee_charged_ika, gas_fee_reimbursement_sui) = self
        .user_sessions_keeper
        .complete_session<E, Success, Rejected>(epoch, session_sequence_number, status);
    self.update_last_user_initiated_session_to_complete_in_current_epoch();
    (fee_charged_ika, gas_fee_reimbursement_sui)
}

/// Initiates a system-initiated session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
/// - `epoch`: The epoch number
/// - `dwallet_network_encryption_key_id`: The ID of the dWallet network encryption key
/// - `event_data`: The event data for the session
/// - `ctx`: The transaction context
///
/// ### Effects
/// - Creates a new system-initiated session
/// - Emits a session event
public(package) fun initiate_system_session<E: copy + drop + store>(
    self: &mut SessionsManager,
    epoch: u64,
    dwallet_network_encryption_key_id: ID,
    event_data: E,
    ctx: &mut TxContext,
) {
    // Notice that `session_identifier_preimage` is only the pre-image.
    // For user-initiated events, we guarantee uniqueness by guaranteeing it never repeats (which guarantees the hash is unique).
    // For system events, we guarantee uniqueness by creating an object address, which can never repeat in Move (system-wide).
    // To avoid user-initiated events colliding with system events,
    // we pad the `session_identifier_preimage` differently for user and system events before hashing it.
    let session_identifier_preimage = tx_context::fresh_object_address(ctx).to_bytes();

    self
        .system_sessions_keeper
        .initiate_session(
            epoch,
            SessionIdentifier {
                id: object::new(ctx),
                identifier_preimage: session_identifier_preimage,
            },
            dwallet_network_encryption_key_id,
            SessionType::System,
            event_data,
            balance::zero(),
            balance::zero(),
            ctx,
        );
}

/// Completes a system-initiated session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
/// - `session_sequence_number`: The sequence number of the session
/// - `status`: The status of the session
///
/// ### Returns
/// A tuple containing the amount of IKA fees paid and SUI for gas reimbursement for the session
public(package) fun complete_system_session<
    E: copy + drop + store,
    Success: copy + drop + store,
    Rejected: copy + drop + store,
>(
    self: &mut SessionsManager,
    epoch: u64,
    session_sequence_number: u64,
    status: DWalletSessionStatusEvent<Success, Rejected>,
) {
    let (fee_charged_ika, gas_fee_reimbursement_sui) = self
        .system_sessions_keeper
        .complete_session<E, Success, Rejected>(epoch, session_sequence_number, status);
    fee_charged_ika.destroy_zero();
    gas_fee_reimbursement_sui.destroy_zero();
}

/// Sets the maximum number of active sessions buffer.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
/// - `max_active_sessions_buffer`: The new maximum number of active sessions buffer
///
public(package) fun set_max_active_sessions_buffer(
    self: &mut SessionsManager,
    max_active_sessions_buffer: u64,
) {
    self.max_active_sessions_buffer = max_active_sessions_buffer;
}

// === Private Functions ===

/// Initiates a session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session keeper
/// - `epoch`: The epoch number
/// - `session_identifier`: The session identifier
/// - `dwallet_network_encryption_key_id`: The ID of the dWallet network encryption key
/// - `session_type`: The type of session
/// - `event_data`: The event data for the session
/// - `fee_charged_ika`: The amount of IKA fees paid
/// - `gas_fee_reimbursement_sui`: The amount of SUI for gas reimbursement
/// - `ctx`: The transaction context
///
/// ### Effects
/// - Creates a new session
/// - Emits a session event
fun initiate_session<E: copy + drop + store>(
    self: &mut SessionsKeeper,
    epoch: u64,
    session_identifier: SessionIdentifier,
    dwallet_network_encryption_key_id: ID,
    session_type: SessionType,
    event_data: E,
    fee_charged_ika: Balance<IKA>,
    gas_fee_reimbursement_sui: Balance<SUI>,
    ctx: &mut TxContext,
) {
    let session_sequence_number = self.next_session_sequence_number;
    let identifier_preimage = session_identifier.identifier_preimage;

    let session = DWalletSession {
        id: object::new(ctx),
        session_identifier,
        session_sequence_number,
        dwallet_network_encryption_key_id,
        fee_charged_ika,
        gas_fee_reimbursement_sui,
    };

    let event = DWalletSessionEvent {
        epoch,
        session_object_id: session.id.to_inner(),
        session_type,
        session_sequence_number,
        session_identifier_preimage: identifier_preimage,
        event_data,
    };

    self.session_events.add(session.id.to_inner(), event);
    self.sessions.add(session_sequence_number, session);
    self.next_session_sequence_number = session_sequence_number + 1;
    self.started_sessions_count = self.started_sessions_count + 1;

    event::emit(event);
}

/// Completes a session.
///
/// ### Parameters
/// - `self`: Mutable reference to the session keeper
/// - `session_sequence_number`: The sequence number of the session
/// - `status`: The status of the session
///
/// ### Returns
/// A tuple containing the amount of IKA fees paid and SUI for gas reimbursement for the session
fun complete_session<
    E: copy + drop + store,
    Success: copy + drop + store,
    Rejected: copy + drop + store,
>(
    self: &mut SessionsKeeper,
    epoch: u64,
    session_sequence_number: u64,
    status: DWalletSessionStatusEvent<Success, Rejected>,
): (Balance<IKA>, Balance<SUI>) {
    self.completed_sessions_count = self.completed_sessions_count + 1;

    let session = self.sessions.remove(session_sequence_number);

    // Unpack and delete the `DWalletSession` object.
    let DWalletSession {
        session_identifier,
        gas_fee_reimbursement_sui,
        fee_charged_ika,
        id,
        ..,
    } = session;

    // Remove the corresponding event.
    let DWalletSessionEvent<E> {
        epoch: event_initiated_at_epoch,
        session_object_id,
        session_type,
        session_sequence_number,
        session_identifier_preimage,
        event_data,
    } = self.session_events.remove(id.to_inner());

    id.delete();

    // Unpack and delete the corresponding session identifier object.
    // This assures it cannot be reused for another session.
    let SessionIdentifier {
        id,
        ..,
    } = session_identifier;

    id.delete();

    event::emit(DWalletSessionResultEvent {
        epoch,
        event_initiated_at_epoch,
        session_object_id,
        session_type,
        session_sequence_number,
        session_identifier_preimage,
        session_initiator_event_data: event_data,
        status,
    });

    (fee_charged_ika, gas_fee_reimbursement_sui)
}

/// Checks if all current epoch sessions are completed.
///
/// ### Parameters
/// - `self`: Reference to the session manager
///
/// ### Returns
/// `true` if all current epoch sessions are completed, `false` otherwise
fun all_current_epoch_sessions_completed(self: &SessionsManager): bool {
    let user_sessions_completed =
        self.user_sessions_keeper.completed_sessions_count == self.last_user_initiated_session_to_complete_in_current_epoch;
    let system_sessions_completed =
        self.system_sessions_keeper.completed_sessions_count == self.system_sessions_keeper.started_sessions_count;
    self.locked_last_user_initiated_session_to_complete_in_current_epoch && user_sessions_completed && system_sessions_completed
}

/// Updates the last user-initiated session to complete in the current epoch.
///
/// ### Parameters
/// - `self`: Mutable reference to the session manager
///
/// ### Effects
/// - Updates the last user-initiated session to complete in the current epoch
fun update_last_user_initiated_session_to_complete_in_current_epoch(self: &mut SessionsManager) {
    // Don't update during epoch transitions when session management is locked
    if (!self.locked_last_user_initiated_session_to_complete_in_current_epoch) {
        // Calculate new target: completed + buffer, but don't exceed latest session
        let new_last_user_initiated_session_to_complete_in_current_epoch = (
            self.user_sessions_keeper.completed_sessions_count + self.max_active_sessions_buffer,
        ).min(
            self.user_sessions_keeper.next_session_sequence_number - 1,
        );

        // Sanity check: Only update if the new target is higher (prevent regression)
        if (
            self.last_user_initiated_session_to_complete_in_current_epoch < new_last_user_initiated_session_to_complete_in_current_epoch
        ) {
            self.last_user_initiated_session_to_complete_in_current_epoch =
                new_last_user_initiated_session_to_complete_in_current_epoch;
        };
    };
}

// === Test Functions ===

#[test_only]
public(package) fun next_user_session_sequence_number(self: &SessionsManager): u64 {
    self.user_sessions_keeper.next_session_sequence_number
}

#[test_only]
public(package) fun next_system_session_sequence_number(self: &SessionsManager): u64 {
    self.system_sessions_keeper.next_session_sequence_number
}
