/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * # Ika System Module
 * 
 * The `ika_system::system` module provides the core system state management for
 * the Ika network. It acts as the central coordinator for validators, staking,
 * epochs, and network governance.
 * 
 * ## Overview
 * 
 * The module implements a versioned wrapper pattern around the core system state:
 * 
 * - `System`: A shared object that serves as the public interface and version
 *   manager
 * - `SystemInner`: The actual system state implementation containing all business
 *   logic
 * - `ProtocolCap`: Capability object for privileged system operations
 * 
 * ## Architecture
 * 
 * The system uses a two-layer architecture:
 * 
 * ### System Wrapper Layer
 * 
 * The `System` struct is a thin wrapper that:
 * 
 * - Maintains version information for upgrades
 * - Stores the package ID for authorization
 * - Holds the inner system state as a dynamic field
 * - Provides a stable public interface across versions
 * 
 * ### SystemInner Layer
 * 
 * The `SystemInner` struct contains all the core functionality:
 * 
 * - Validator set management and operations
 * - Epoch progression and timing
 * - Staking and delegation logic
 * - Protocol treasury and rewards distribution
 * - dWallet network coordination
 * - System parameter management
 * 
 * ## Key Responsibilities
 * 
 * ### Validator Management
 * 
 * - Adding/removing validator candidates
 * - Managing validator metadata and configuration
 * - Handling validator state transitions (PreActive → Active → Withdrawing)
 * - Processing validator reports and governance actions
 * 
 * ### Staking Operations
 * 
 * - Processing stake additions and withdrawals
 * - Managing staked IKA tokens and rewards
 * - Calculating token exchange rates across epochs
 * - Handling delegation to validators
 * 
 * ### Epoch Management
 * 
 * - Coordinating epoch transitions
 * - Processing mid-epoch reconfigurations
 * - Managing epoch timing and duration
 * - Distributing stake subsidies and rewards
 * 
 * ### dWallet Integration
 * 
 * - Coordinating with dWallet 2PC MPC system
 * - Managing encryption keys and DKG processes
 * - Handling pricing and curve configurations
 * - Processing dWallet network operations
 * 
 * ### System Governance
 * 
 * - Managing protocol upgrades via UpgradeCap
 * - Processing system parameter changes
 * - Handling protocol version transitions
 * - Coordinating checkpoint message processing
 * 
 * ## State Management
 * 
 * The system maintains state across multiple components:
 * 
 * - **ValidatorSet**: Current and pending validator configurations
 * - **ProtocolTreasury**: Rewards, subsidies, and fee management
 * - **BLS Committee**: Cryptographic committee for consensus
 * - **Token Exchange Rates**: Historical staking reward calculations
 * - **Pending Values**: Future epoch configuration changes
 * 
 * ## Ika System Upgrade Guide
 * 
 * `System` is a versioned wrapper around `SystemInner` that provides upgrade
 * capabilities. The `SystemInner` object is stored as a dynamic field with the
 * version as the key. There are multiple approaches to upgrade the system state:
 * 
 * The simplest approach is to add dynamic fields to the `extra_fields` field of
 * `SystemInner` or any of its subtypes. This is useful for rapid changes, small
 * modifications, or experimental features.
 * 
 * To perform a proper type upgrade of `SystemInner`, follow these steps:
 * 
 * 1.  Define a new `SystemInnerV2` type in system_inner.move.
 * 2.  Create a data migration function that transforms `SystemInner` to
 *     `SystemInnerV2`.
 * 3.  Update the `VERSION` constant to 2 and replace all references to
 *     `SystemInner` with `SystemInnerV2` in both system.move and
 *     system_inner.move.
 * 4.  Modify the `migrate` function to handle the version upgrade by:
 *     - Removing the old inner object from the dynamic field
 *     - Applying the data migration transformation
 *     - Adding the new inner object with the updated version
 * 5.  Update the `inner()` and `inner_mut()` functions to work with the new
 *     version.
 * 
 * Along with the Move changes, update the Rust code:
 * 
 * 1.  Define a new `SystemInnerV2` struct that matches the Move type.
 * 2.  Update the `System` enum to include the new version variant.
 * 3.  Update relevant system state getter functions to handle the new version.
 * 
 * To upgrade Validator types:
 * 
 * 1.  Define a new Validator version (e.g. ValidatorV2) in validator.move.
 * 2.  Create migration functions to convert between validator versions.
 * 3.  Update validator creation and access functions to use the new version.
 * 4.  Update the validator set and related components to handle the new validator
 *     type.
 * 
 * In Rust, add new cases to handle the upgraded validator types in the appropriate
 * getter functions. Validator upgrades can be done independently of SystemInner
 * upgrades, but ensure version consistency across related components.
 */

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
const $moduleName = '@local-pkg/system::system';
export const System = new MoveStruct({ name: `${$moduleName}::System`, fields: {
        id: object.UID,
        version: bcs.u64(),
        package_id: bcs.Address,
        new_package_id: bcs.option(bcs.Address),
        migration_epoch: bcs.option(bcs.u64())
    } });
export interface InitializeArguments {
    self: RawTransactionArgument<string>;
    maxValidatorChangeCount: RawTransactionArgument<number | bigint>;
    cap: RawTransactionArgument<string>;
}
export interface InitializeOptions {
    package?: string;
    arguments: InitializeArguments | [
        self: RawTransactionArgument<string>,
        maxValidatorChangeCount: RawTransactionArgument<number | bigint>,
        cap: RawTransactionArgument<string>
    ];
}
export function initialize(options: InitializeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'u64',
        `${packageAddress}::protocol_cap::ProtocolCap`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::clock::Clock'
    ] satisfies string[];
    const parameterNames = ["self", "maxValidatorChangeCount", "cap", "clock"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'initialize',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestAddValidatorCandidateArguments {
    self: RawTransactionArgument<string>;
    name: RawTransactionArgument<string>;
    protocolPubkeyBytes: RawTransactionArgument<number[]>;
    networkPubkeyBytes: RawTransactionArgument<number[]>;
    consensusPubkeyBytes: RawTransactionArgument<number[]>;
    mpcDataBytes: RawTransactionArgument<string>;
    proofOfPossessionBytes: RawTransactionArgument<number[]>;
    networkAddress: RawTransactionArgument<string>;
    p2pAddress: RawTransactionArgument<string>;
    consensusAddress: RawTransactionArgument<string>;
    commissionRate: RawTransactionArgument<number>;
    metadata: RawTransactionArgument<string>;
}
export interface RequestAddValidatorCandidateOptions {
    package?: string;
    arguments: RequestAddValidatorCandidateArguments | [
        self: RawTransactionArgument<string>,
        name: RawTransactionArgument<string>,
        protocolPubkeyBytes: RawTransactionArgument<number[]>,
        networkPubkeyBytes: RawTransactionArgument<number[]>,
        consensusPubkeyBytes: RawTransactionArgument<number[]>,
        mpcDataBytes: RawTransactionArgument<string>,
        proofOfPossessionBytes: RawTransactionArgument<number[]>,
        networkAddress: RawTransactionArgument<string>,
        p2pAddress: RawTransactionArgument<string>,
        consensusAddress: RawTransactionArgument<string>,
        commissionRate: RawTransactionArgument<number>,
        metadata: RawTransactionArgument<string>
    ];
}
/**
 * Can be called by anyone who wishes to become a validator candidate and starts
 * accruing delegated stakes in their staking pool. Once they have at least
 * `MIN_VALIDATOR_JOINING_STAKE` amount of stake they can call
 * `request_add_validator` to officially become an active validator at the next
 * epoch. Aborts if the caller is already a pending or active validator, or a
 * validator candidate. Note: `proof_of_possession_bytes` MUST be a valid signature
 * using sui_address and protocol_pubkey_bytes. To produce a valid PoP, run [fn
 * test_proof_of_possession_bytes].
 */
export function requestAddValidatorCandidate(options: RequestAddValidatorCandidateOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        'vector<u8>',
        'vector<u8>',
        'vector<u8>',
        '0x0000000000000000000000000000000000000000000000000000000000000002::table_vec::TableVec<vector<u8>>',
        'vector<u8>',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        'u16',
        `${packageAddress}::validator_metadata::ValidatorMetadata`
    ] satisfies string[];
    const parameterNames = ["self", "name", "protocolPubkeyBytes", "networkPubkeyBytes", "consensusPubkeyBytes", "mpcDataBytes", "proofOfPossessionBytes", "networkAddress", "p2pAddress", "consensusAddress", "commissionRate", "metadata"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_add_validator_candidate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestRemoveValidatorCandidateArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface RequestRemoveValidatorCandidateOptions {
    package?: string;
    arguments: RequestRemoveValidatorCandidateArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Called by a validator candidate to remove themselves from the candidacy. After
 * this call their staking pool becomes deactivate.
 */
export function requestRemoveValidatorCandidate(options: RequestRemoveValidatorCandidateOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_remove_validator_candidate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestAddValidatorArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface RequestAddValidatorOptions {
    package?: string;
    arguments: RequestAddValidatorArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Called by a validator candidate to add themselves to the active validator set
 * beginning next epoch. Aborts if the validator is a duplicate with one of the
 * pending or active validators, or if the amount of stake the validator has
 * doesn't meet the min threshold, or if the number of new validators for the next
 * epoch has already reached the maximum.
 */
export function requestAddValidator(options: RequestAddValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_add_validator',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestRemoveValidatorArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface RequestRemoveValidatorOptions {
    package?: string;
    arguments: RequestRemoveValidatorArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * A validator can call this function to request a removal in the next epoch. We
 * use the sender of `ctx` to look up the validator (i.e. sender must match the
 * sui_address in the validator). At the end of the epoch, the `validator` object
 * will be returned to the sui_address of the validator.
 */
export function requestRemoveValidator(options: RequestRemoveValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_remove_validator',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextCommissionArguments {
    self: RawTransactionArgument<string>;
    newCommissionRate: RawTransactionArgument<number>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextCommissionOptions {
    package?: string;
    arguments: SetNextCommissionArguments | [
        self: RawTransactionArgument<string>,
        newCommissionRate: RawTransactionArgument<number>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * A validator can call this function to set a new commission rate, updated at the
 * end of the epoch.
 */
export function setNextCommission(options: SetNextCommissionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'u16',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "newCommissionRate", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_commission',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestAddStakeArguments {
    self: RawTransactionArgument<string>;
    stake: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface RequestAddStakeOptions {
    package?: string;
    arguments: RequestAddStakeArguments | [
        self: RawTransactionArgument<string>,
        stake: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/** Add stake to a validator's staking pool. */
export function requestAddStake(options: RequestAddStakeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "stake", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_add_stake',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestWithdrawStakeArguments {
    self: RawTransactionArgument<string>;
    stakedIka: RawTransactionArgument<string>;
}
export interface RequestWithdrawStakeOptions {
    package?: string;
    arguments: RequestWithdrawStakeArguments | [
        self: RawTransactionArgument<string>,
        stakedIka: RawTransactionArgument<string>
    ];
}
/**
 * Marks the amount as a withdrawal to be processed and removes it from the stake
 * weight of the node. Allows the user to call withdraw_stake after the epoch
 * change to the next epoch and shard transfer is done.
 */
export function requestWithdrawStake(options: RequestWithdrawStakeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["self", "stakedIka"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'request_withdraw_stake',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface WithdrawStakeArguments {
    self: RawTransactionArgument<string>;
    stakedIka: RawTransactionArgument<string>;
}
export interface WithdrawStakeOptions {
    package?: string;
    arguments: WithdrawStakeArguments | [
        self: RawTransactionArgument<string>,
        stakedIka: RawTransactionArgument<string>
    ];
}
/** Withdraws the staked amount from the staking pool. */
export function withdrawStake(options: WithdrawStakeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["self", "stakedIka"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'withdraw_stake',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ReportValidatorArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
    reporteeId: RawTransactionArgument<string>;
}
export interface ReportValidatorOptions {
    package?: string;
    arguments: ReportValidatorArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>,
        reporteeId: RawTransactionArgument<string>
    ];
}
/**
 * Report a validator as a bad or non-performant actor in the system. Succeeds if
 * all the following are satisfied:
 *
 * 1.  both the reporter in `cap` and the input `reportee_id` are active
 *     validators.
 * 2.  reporter and reportee not the same address.
 * 3.  the cap object is still valid. This function is idempotent.
 */
export function reportValidator(options: ReportValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorOperationCap`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "cap", "reporteeId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'report_validator',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface UndoReportValidatorArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
    reporteeId: RawTransactionArgument<string>;
}
export interface UndoReportValidatorOptions {
    package?: string;
    arguments: UndoReportValidatorArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>,
        reporteeId: RawTransactionArgument<string>
    ];
}
/**
 * Undo a `report_validator` action. Aborts if
 *
 * 1.  the reportee is not a currently active validator or
 * 2.  the sender has not previously reported the `reportee_id`, or
 * 3.  the cap is not valid
 */
export function undoReportValidator(options: UndoReportValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorOperationCap`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "cap", "reporteeId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'undo_report_validator',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RotateOperationCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface RotateOperationCapOptions {
    package?: string;
    arguments: RotateOperationCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Create a new `ValidatorOperationCap` and registers it. The original object is
 * thus revoked.
 */
export function rotateOperationCap(options: RotateOperationCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'rotate_operation_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RotateCommissionCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface RotateCommissionCapOptions {
    package?: string;
    arguments: RotateCommissionCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Create a new `ValidatorCommissionCap` and registers it. The original object is
 * thus revoked.
 */
export function rotateCommissionCap(options: RotateCommissionCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'rotate_commission_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CollectCommissionArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
    amount: RawTransactionArgument<number | bigint | null>;
}
export interface CollectCommissionOptions {
    package?: string;
    arguments: CollectCommissionArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>,
        amount: RawTransactionArgument<number | bigint | null>
    ];
}
/**
 * Withdraws the commission from the validator. Amount is optional, if not
 * provided, the full commission is withdrawn.
 */
export function collectCommission(options: CollectCommissionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCommissionCap`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::option::Option<u64>'
    ] satisfies string[];
    const parameterNames = ["self", "cap", "amount"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'collect_commission',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetValidatorNameArguments {
    self: RawTransactionArgument<string>;
    name: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetValidatorNameOptions {
    package?: string;
    arguments: SetValidatorNameArguments | [
        self: RawTransactionArgument<string>,
        name: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/** Set a validator's name. */
export function setValidatorName(options: SetValidatorNameOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "name", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_validator_name',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorMetadataArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface ValidatorMetadataOptions {
    package?: string;
    arguments: ValidatorMetadataArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/** Get a validator's metadata. */
export function validatorMetadata(options: ValidatorMetadataOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'validator_metadata',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetValidatorMetadataArguments {
    self: RawTransactionArgument<string>;
    metadata: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetValidatorMetadataOptions {
    package?: string;
    arguments: SetValidatorMetadataArguments | [
        self: RawTransactionArgument<string>,
        metadata: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function setValidatorMetadata(options: SetValidatorMetadataOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_metadata::ValidatorMetadata`,
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "metadata", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_validator_metadata',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochNetworkAddressArguments {
    self: RawTransactionArgument<string>;
    networkAddress: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochNetworkAddressOptions {
    package?: string;
    arguments: SetNextEpochNetworkAddressArguments | [
        self: RawTransactionArgument<string>,
        networkAddress: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's network address. The change will only take effects starting
 * from the next epoch.
 */
export function setNextEpochNetworkAddress(options: SetNextEpochNetworkAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "networkAddress", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_network_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochP2pAddressArguments {
    self: RawTransactionArgument<string>;
    p2pAddress: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochP2pAddressOptions {
    package?: string;
    arguments: SetNextEpochP2pAddressArguments | [
        self: RawTransactionArgument<string>,
        p2pAddress: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's p2p address. The change will only take effects starting from
 * the next epoch.
 */
export function setNextEpochP2pAddress(options: SetNextEpochP2pAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "p2pAddress", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_p2p_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochConsensusAddressArguments {
    self: RawTransactionArgument<string>;
    consensusAddress: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochConsensusAddressOptions {
    package?: string;
    arguments: SetNextEpochConsensusAddressArguments | [
        self: RawTransactionArgument<string>,
        consensusAddress: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's consensus address. The change will only take effects starting
 * from the next epoch.
 */
export function setNextEpochConsensusAddress(options: SetNextEpochConsensusAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "consensusAddress", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_consensus_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochProtocolPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
    protocolPubkey: RawTransactionArgument<number[]>;
    proofOfPossessionBytes: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochProtocolPubkeyBytesOptions {
    package?: string;
    arguments: SetNextEpochProtocolPubkeyBytesArguments | [
        self: RawTransactionArgument<string>,
        protocolPubkey: RawTransactionArgument<number[]>,
        proofOfPossessionBytes: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's public key of protocol key and proof of possession. The
 * change will only take effects starting from the next epoch.
 */
export function setNextEpochProtocolPubkeyBytes(options: SetNextEpochProtocolPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'vector<u8>',
        'vector<u8>',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "protocolPubkey", "proofOfPossessionBytes", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_protocol_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochNetworkPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
    networkPubkey: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochNetworkPubkeyBytesOptions {
    package?: string;
    arguments: SetNextEpochNetworkPubkeyBytesArguments | [
        self: RawTransactionArgument<string>,
        networkPubkey: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's public key of network key. The change will only take effects
 * starting from the next epoch.
 */
export function setNextEpochNetworkPubkeyBytes(options: SetNextEpochNetworkPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'vector<u8>',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "networkPubkey", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_network_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochConsensusPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
    consensusPubkeyBytes: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochConsensusPubkeyBytesOptions {
    package?: string;
    arguments: SetNextEpochConsensusPubkeyBytesArguments | [
        self: RawTransactionArgument<string>,
        consensusPubkeyBytes: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's public key of worker key. The change will only take effects
 * starting from the next epoch.
 */
export function setNextEpochConsensusPubkeyBytes(options: SetNextEpochConsensusPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'vector<u8>',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "consensusPubkeyBytes", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_consensus_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetNextEpochMpcDataBytesArguments {
    self: RawTransactionArgument<string>;
    mpcData: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetNextEpochMpcDataBytesOptions {
    package?: string;
    arguments: SetNextEpochMpcDataBytesArguments | [
        self: RawTransactionArgument<string>,
        mpcData: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Sets a validator's MPC public data. The change will only take effects starting
 * from the next epoch.
 */
export function setNextEpochMpcDataBytes(options: SetNextEpochMpcDataBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::table_vec::TableVec<vector<u8>>',
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "mpcData", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_next_epoch_mpc_data_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface TokenExchangeRatesArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface TokenExchangeRatesOptions {
    package?: string;
    arguments: TokenExchangeRatesArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/**
 * Get the pool token exchange rate of a validator. Works for both active and
 * inactive pools.
 */
export function tokenExchangeRates(options: TokenExchangeRatesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'token_exchange_rates',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ActiveCommitteeArguments {
    self: RawTransactionArgument<string>;
}
export interface ActiveCommitteeOptions {
    package?: string;
    arguments: ActiveCommitteeArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Get the active committee of the current epoch. */
export function activeCommittee(options: ActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'active_committee',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochActiveCommitteeArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochActiveCommitteeOptions {
    package?: string;
    arguments: NextEpochActiveCommitteeArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Get the active committee of the next epoch. */
export function nextEpochActiveCommittee(options: NextEpochActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'next_epoch_active_committee',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface InitiateMidEpochReconfigurationArguments {
    self: RawTransactionArgument<string>;
}
export interface InitiateMidEpochReconfigurationOptions {
    package?: string;
    arguments: InitiateMidEpochReconfigurationArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Locks the committee of the next epoch to allow starting the reconfiguration
 * process.
 */
export function initiateMidEpochReconfiguration(options: InitiateMidEpochReconfigurationOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::clock::Clock'
    ] satisfies string[];
    const parameterNames = ["self", "clock"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'initiate_mid_epoch_reconfiguration',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CreateSystemCurrentStatusInfoArguments {
    self: RawTransactionArgument<string>;
}
export interface CreateSystemCurrentStatusInfoOptions {
    package?: string;
    arguments: CreateSystemCurrentStatusInfoArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Create the system current status info. */
export function createSystemCurrentStatusInfo(options: CreateSystemCurrentStatusInfoOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::clock::Clock'
    ] satisfies string[];
    const parameterNames = ["self", "clock"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'create_system_current_status_info',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface InitiateAdvanceEpochArguments {
    self: RawTransactionArgument<string>;
}
export interface InitiateAdvanceEpochOptions {
    package?: string;
    arguments: InitiateAdvanceEpochArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Initiates the advance epoch process. */
export function initiateAdvanceEpoch(options: InitiateAdvanceEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::clock::Clock'
    ] satisfies string[];
    const parameterNames = ["self", "clock"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'initiate_advance_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AdvanceEpochArguments {
    self: RawTransactionArgument<string>;
    advanceEpochApprover: RawTransactionArgument<string>;
}
export interface AdvanceEpochOptions {
    package?: string;
    arguments: AdvanceEpochArguments | [
        self: RawTransactionArgument<string>,
        advanceEpochApprover: RawTransactionArgument<string>
    ];
}
/**
 * Advances the epoch to the next epoch. Can only be called after all the witnesses
 * have approved the advance epoch.
 */
export function advanceEpoch(options: AdvanceEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::clock::Clock'
    ] satisfies string[];
    const parameterNames = ["self", "advanceEpochApprover", "clock"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'advance_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyValidatorCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyValidatorCapOptions {
    package?: string;
    arguments: VerifyValidatorCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyValidatorCap(options: VerifyValidatorCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'verify_validator_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyOperationCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyOperationCapOptions {
    package?: string;
    arguments: VerifyOperationCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyOperationCap(options: VerifyOperationCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'verify_operation_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyCommissionCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyCommissionCapOptions {
    package?: string;
    arguments: VerifyCommissionCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyCommissionCap(options: VerifyCommissionCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::validator_cap::ValidatorCommissionCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'verify_commission_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AuthorizeUpgradeArguments {
    self: RawTransactionArgument<string>;
    packageId: RawTransactionArgument<string>;
}
export interface AuthorizeUpgradeOptions {
    package?: string;
    arguments: AuthorizeUpgradeArguments | [
        self: RawTransactionArgument<string>,
        packageId: RawTransactionArgument<string>
    ];
}
export function authorizeUpgrade(options: AuthorizeUpgradeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "packageId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'authorize_upgrade',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CommitUpgradeArguments {
    self: RawTransactionArgument<string>;
    receipt: RawTransactionArgument<string>;
    upgradePackageApprover: RawTransactionArgument<string>;
}
export interface CommitUpgradeOptions {
    package?: string;
    arguments: CommitUpgradeArguments | [
        self: RawTransactionArgument<string>,
        receipt: RawTransactionArgument<string>,
        upgradePackageApprover: RawTransactionArgument<string>
    ];
}
export function commitUpgrade(options: CommitUpgradeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeReceipt',
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self", "receipt", "upgradePackageApprover"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'commit_upgrade',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface FinalizeUpgradeArguments {
    self: RawTransactionArgument<string>;
    upgradePackageApprover: RawTransactionArgument<string>;
}
export interface FinalizeUpgradeOptions {
    package?: string;
    arguments: FinalizeUpgradeArguments | [
        self: RawTransactionArgument<string>,
        upgradePackageApprover: RawTransactionArgument<string>
    ];
}
export function finalizeUpgrade(options: FinalizeUpgradeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self", "upgradePackageApprover"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'finalize_upgrade',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProcessCheckpointMessageByQuorumArguments {
    self: RawTransactionArgument<string>;
    signature: RawTransactionArgument<number[]>;
    signersBitmap: RawTransactionArgument<number[]>;
    message: RawTransactionArgument<number[]>;
}
export interface ProcessCheckpointMessageByQuorumOptions {
    package?: string;
    arguments: ProcessCheckpointMessageByQuorumArguments | [
        self: RawTransactionArgument<string>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
        message: RawTransactionArgument<number[]>
    ];
}
export function processCheckpointMessageByQuorum(options: ProcessCheckpointMessageByQuorumOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'vector<u8>',
        'vector<u8>',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "signature", "signersBitmap", "message"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'process_checkpoint_message_by_quorum',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AddUpgradeCapByCapArguments {
    self: RawTransactionArgument<string>;
    upgradeCap: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface AddUpgradeCapByCapOptions {
    package?: string;
    arguments: AddUpgradeCapByCapArguments | [
        self: RawTransactionArgument<string>,
        upgradeCap: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function addUpgradeCapByCap(options: AddUpgradeCapByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeCap',
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "upgradeCap", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'add_upgrade_cap_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyProtocolCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyProtocolCapOptions {
    package?: string;
    arguments: VerifyProtocolCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyProtocolCap(options: VerifyProtocolCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'verify_protocol_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProcessCheckpointMessageByCapArguments {
    self: RawTransactionArgument<string>;
    message: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface ProcessCheckpointMessageByCapOptions {
    package?: string;
    arguments: ProcessCheckpointMessageByCapArguments | [
        self: RawTransactionArgument<string>,
        message: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
export function processCheckpointMessageByCap(options: ProcessCheckpointMessageByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        'vector<u8>',
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "message", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'process_checkpoint_message_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetApprovedUpgradeByCapArguments {
    self: RawTransactionArgument<string>;
    packageId: RawTransactionArgument<string>;
    digest: RawTransactionArgument<number[] | null>;
    cap: RawTransactionArgument<string>;
}
export interface SetApprovedUpgradeByCapOptions {
    package?: string;
    arguments: SetApprovedUpgradeByCapArguments | [
        self: RawTransactionArgument<string>,
        packageId: RawTransactionArgument<string>,
        digest: RawTransactionArgument<number[] | null>,
        cap: RawTransactionArgument<string>
    ];
}
export function setApprovedUpgradeByCap(options: SetApprovedUpgradeByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        '0x0000000000000000000000000000000000000000000000000000000000000001::option::Option<vector<u8>>',
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "packageId", "digest", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_approved_upgrade_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetOrRemoveWitnessApprovingAdvanceEpochByCapArguments {
    self: RawTransactionArgument<string>;
    witnessType: RawTransactionArgument<string>;
    remove: RawTransactionArgument<boolean>;
    cap: RawTransactionArgument<string>;
}
export interface SetOrRemoveWitnessApprovingAdvanceEpochByCapOptions {
    package?: string;
    arguments: SetOrRemoveWitnessApprovingAdvanceEpochByCapArguments | [
        self: RawTransactionArgument<string>,
        witnessType: RawTransactionArgument<string>,
        remove: RawTransactionArgument<boolean>,
        cap: RawTransactionArgument<string>
    ];
}
export function setOrRemoveWitnessApprovingAdvanceEpochByCap(options: SetOrRemoveWitnessApprovingAdvanceEpochByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        'bool',
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "witnessType", "remove", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'set_or_remove_witness_approving_advance_epoch_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface TryMigrateByCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface TryMigrateByCapOptions {
    package?: string;
    arguments: TryMigrateByCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
/**
 * Try to migrate the system object to the new package id using a cap.
 *
 * This function sets the new package id and version and can be modified in future
 * versions to migrate changes in the `system_inner` object if needed. This
 * function can be called immediately after the upgrade is committed.
 */
export function tryMigrateByCap(options: TryMigrateByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::protocol_cap::ProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'try_migrate_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface TryMigrateArguments {
    self: RawTransactionArgument<string>;
}
export interface TryMigrateOptions {
    package?: string;
    arguments: TryMigrateArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Try to migrate the system object to the new package id.
 *
 * This function sets the new package id and version and can be modified in future
 * versions to migrate changes in the `system_inner` object if needed. Call this
 * function after the migration epoch is reached.
 */
export function tryMigrate(options: TryMigrateOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'try_migrate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VersionArguments {
    self: RawTransactionArgument<string>;
}
export interface VersionOptions {
    package?: string;
    arguments: VersionArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function version(options: VersionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'version',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CalculateRewardsArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
    stakedPrincipal: RawTransactionArgument<number | bigint>;
    activationEpoch: RawTransactionArgument<number | bigint>;
    withdrawEpoch: RawTransactionArgument<number | bigint>;
}
export interface CalculateRewardsOptions {
    package?: string;
    arguments: CalculateRewardsArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>,
        stakedPrincipal: RawTransactionArgument<number | bigint>,
        activationEpoch: RawTransactionArgument<number | bigint>,
        withdrawEpoch: RawTransactionArgument<number | bigint>
    ];
}
/**
 * Calculates the rewards for an amount with value `staked_principal`, staked in
 * the validator with the given `validator_id` between `activation_epoch` and
 * `withdraw_epoch`.
 *
 * This function can be used with `dev_inspect` to calculate the expected rewards
 * for a `StakedIka` object or, more generally, the returns provided by a given
 * validator over a given period.
 */
export function calculateRewards(options: CalculateRewardsOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u64',
        'u64',
        'u64'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId", "stakedPrincipal", "activationEpoch", "withdrawEpoch"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'calculate_rewards',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CanWithdrawStakedIkaEarlyArguments {
    self: RawTransactionArgument<string>;
    stakedIka: RawTransactionArgument<string>;
}
export interface CanWithdrawStakedIkaEarlyOptions {
    package?: string;
    arguments: CanWithdrawStakedIkaEarlyArguments | [
        self: RawTransactionArgument<string>,
        stakedIka: RawTransactionArgument<string>
    ];
}
/**
 * Call `staked_ika::can_withdraw_early` to allow calling this method in
 * applications.
 */
export function canWithdrawStakedIkaEarly(options: CanWithdrawStakedIkaEarlyOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["self", "stakedIka"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'can_withdraw_staked_ika_early',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface EpochArguments {
    self: RawTransactionArgument<string>;
}
export interface EpochOptions {
    package?: string;
    arguments: EpochArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Return the current epoch number. Useful for applications that need a
 * coarse-grained concept of time, since epochs are ever-increasing and epoch
 * changes are intended to happen every 24 hours.
 */
export function epoch(options: EpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorStakeAmountArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface ValidatorStakeAmountOptions {
    package?: string;
    arguments: ValidatorStakeAmountArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/**
 * Returns the total amount staked with `validator_id`. Aborts if `validator_id` is
 * not an active validator.
 */
export function validatorStakeAmount(options: ValidatorStakeAmountOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::system::System`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system',
        function: 'validator_stake_amount',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}