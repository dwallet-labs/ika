/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, MoveEnum } from '../utils/index.js';
import { bcs, type BcsType } from '@mysten/sui/bcs';
import * as object_table from './deps/sui/object_table.js';
import * as bag from './deps/sui/bag.js';
import * as table from './deps/sui/table.js';
import * as object from './deps/sui/object.js';
import * as balance from './deps/sui/balance.js';
const $moduleName = '@local-pkg/2pc-mpc::sessions_manager';
export const SessionsKeeper = new MoveStruct({ name: `${$moduleName}::SessionsKeeper`, fields: {
        /** Active sessions indexed by sequence number */
        sessions: object_table.ObjectTable,
        /** Events for sessions, keyed by session ID */
        session_events: bag.Bag,
        /** Count of started sessions */
        started_sessions_count: bcs.u64(),
        /** Count of completed sessions */
        completed_sessions_count: bcs.u64(),
        /**
         * The sequence number to assign to the next session. Initialized to `1` and
         * incremented at every new session creation.
         */
        next_session_sequence_number: bcs.u64()
    } });
export const SessionsManager = new MoveStruct({ name: `${$moduleName}::SessionsManager`, fields: {
        /**
           * Registered user session identifiers, keyed by the session identifier bytes -> to
           * session object ID
           */
        registered_user_session_identifiers: table.Table,
        /** Holds the data for user-initiated sessions */
        user_sessions_keeper: SessionsKeeper,
        /** Holds the data for system-initiated sessions */
        system_sessions_keeper: SessionsKeeper,
        /**
         * The last MPC session to process in the current epoch. The validators of the Ika
         * network must always begin sessions, when they become available to them, so long
         * their sequence number is lesser or equal to this value. Initialized to `0`, as
         * when the system is initialized no user-requested session exists so none should
         * be started and we shouldn't wait for any to complete before advancing epoch
         * (until the first session is created), and updated at every new session creation
         * or completion, and when advancing epochs, to the latest session whilst assuring
         * a maximum of `max_active_sessions_buffer` sessions to be completed in the
         * current epoch. Validators should complete every session they start before
         * switching epochs.
         */
        last_user_initiated_session_to_complete_in_current_epoch: bcs.u64(),
        /**
         * Denotes whether the `last_user_initiated_session_to_complete_in_current_epoch`
         * field is locked or not. This field gets locked before performing the epoch
         * switch.
         */
        locked_last_user_initiated_session_to_complete_in_current_epoch: bcs.bool(),
        /**
         * The maximum number of active MPC sessions Ika nodes may run during an epoch.
         * Validators should complete every session they start before switching epochs.
         */
        max_active_sessions_buffer: bcs.u64()
    } });
export const SessionIdentifier = new MoveStruct({ name: `${$moduleName}::SessionIdentifier`, fields: {
        id: object.UID,
        identifier_preimage: bcs.vector(bcs.u8())
    } });
export const DWalletSession = new MoveStruct({ name: `${$moduleName}::DWalletSession`, fields: {
        id: object.UID,
        /** Session identifier */
        session_identifier: SessionIdentifier,
        /** Sequential number for session ordering */
        session_sequence_number: bcs.u64(),
        /** Associated network encryption key */
        dwallet_network_encryption_key_id: bcs.Address,
        /** IKA fees for the session */
        fee_charged_ika: balance.Balance,
        /** SUI balance for gas reimbursement */
        gas_fee_reimbursement_sui: balance.Balance
    } });
export const UserSessionIdentifierRegisteredEvent = new MoveStruct({ name: `${$moduleName}::UserSessionIdentifierRegisteredEvent`, fields: {
        /** ID of the session object */
        session_object_id: bcs.Address,
        /** Unique session identifier */
        session_identifier_preimage: bcs.vector(bcs.u8())
    } });
/**
 * Type of dWallet MPC session for scheduling and epoch management.
 *
 * User-initiated sessions have sequence numbers for multi-epoch completion
 * scheduling. System sessions are guaranteed to complete within their creation
 * epoch.
 */
export const SessionType = new MoveEnum({ name: `${$moduleName}::SessionType`, fields: {
        /** User-initiated session (across epochs scheduling) */
        User: null,
        /** System-initiated session (always completes in current epoch) */
        System: null
    } });
/**
 * Generic wrapper for dWallet-related events with session context.
 *
 * Provides standardized metadata for all dWallet operations including epoch
 * information, session type, and session ID for tracking and debugging.
 */
export function DWalletSessionEvent<E extends BcsType<any>>(...typeParameters: [
    E
]) {
    return new MoveStruct({ name: `${$moduleName}::DWalletSessionEvent<${typeParameters[0].name as E['name']}>`, fields: {
            /** Epoch when the event occurred */
            epoch: bcs.u64(),
            /** ID of the session object */
            session_object_id: bcs.Address,
            /** Type of session (User or System) */
            session_type: SessionType,
            /** Sequential number for session ordering */
            session_sequence_number: bcs.u64(),
            /** Unique session identifier */
            session_identifier_preimage: bcs.vector(bcs.u8()),
            /** Event-specific data */
            event_data: typeParameters[0]
        } });
}
/**
 * The status of a dWallet session result event.
 *
 * This enum represents the possible outcomes of a dWallet session event. It can
 * either be successful or rejected, with event-specific data for each case.
 */
export function DWalletSessionStatusEvent<Success extends BcsType<any>, Rejected extends BcsType<any>>(...typeParameters: [
    Success,
    Rejected
]) {
    return new MoveEnum({ name: `${$moduleName}::DWalletSessionStatusEvent<${typeParameters[0].name as Success['name']}, ${typeParameters[1].name as Rejected['name']}>`, fields: {
            /** The event was successful */
            Success: typeParameters[0],
            /** The event was rejected */
            Rejected: typeParameters[1]
        } });
}
/**
 * Event emitted when a dWallet session result is completed.
 *
 * This event signals that a dWallet session has been completed and provides the
 * status of the session (success or rejection) along with the event-specific data
 * for each case.
 */
export function DWalletSessionResultEvent<E extends BcsType<any>, Success extends BcsType<any>, Rejected extends BcsType<any>>(...typeParameters: [
    E,
    Success,
    Rejected
]) {
    return new MoveStruct({ name: `${$moduleName}::DWalletSessionResultEvent<${typeParameters[0].name as E['name']}, ${typeParameters[1].name as Success['name']}, ${typeParameters[2].name as Rejected['name']}>`, fields: {
            /** Epoch when the event occurred */
            epoch: bcs.u64(),
            /** Epoch when the event was initiated */
            event_initiated_at_epoch: bcs.u64(),
            /** ID of the session object */
            session_object_id: bcs.Address,
            /** Type of session (User or System) */
            session_type: SessionType,
            /** Sequential number for session ordering */
            session_sequence_number: bcs.u64(),
            /** The identifier of the session */
            session_identifier_preimage: bcs.vector(bcs.u8()),
            /** Event-specific data of the session initiator */
            session_initiator_event_data: typeParameters[0],
            /** The status of the event */
            status: DWalletSessionStatusEvent(typeParameters[1], typeParameters[2])
        } });
}