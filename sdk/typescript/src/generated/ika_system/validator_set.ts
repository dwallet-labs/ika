/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object_table from './deps/sui/object_table.js';
import * as bls_committee from './deps/ika_common/bls_committee.js';
import * as extended_field from './deps/ika_common/extended_field.js';
import * as vec_map from './deps/sui/vec_map.js';
import * as vec_set from './deps/sui/vec_set.js';
import * as bag from './deps/sui/bag.js';
import * as token_exchange_rate from './token_exchange_rate.js';
const $moduleName = '@local-pkg/system::validator_set';
export const ValidatorSet = new MoveStruct({ name: `${$moduleName}::ValidatorSet`, fields: {
        /** Total amount of stake from all active validators at the beginning of the epoch. */
        total_stake: bcs.u64(),
        /** How many reward are slashed to punish a validator, in bps. */
        reward_slashing_rate: bcs.u16(),
        /** A table that contains all validators */
        validators: object_table.ObjectTable,
        /** The current list of active committee of validators. */
        active_committee: bls_committee.BlsCommittee,
        /**
         * The next list of active committee of validators. It will become the
         * active_committee at the end of the epoch.
         */
        next_epoch_active_committee: bcs.option(bls_committee.BlsCommittee),
        /** The current list of previous committee of validators. */
        previous_committee: bls_committee.BlsCommittee,
        /**
         * The next list of pending active set of validators to be
         * next_epoch_active_committee. It will start from the last
         * next_epoch_active_committee and will be process between middle of the epochs and
         * will be finalize at the middle of the epoch.
         */
        pending_active_set: extended_field.ExtendedField,
        /**
         * A map storing the records of validator reporting each other. There is an entry
         * in the map for each validator that has been reported at least once. The entry
         * VecSet contains all the validators that reported them. If a validator has never
         * been reported they don't have an entry in this map. This map persists across
         * epoch: a peer continues being in a reported state until the reporter doesn't
         * explicitly remove their report. Note that in case we want to support validator
         * address change in future, the reports should be based on validator ids
         */
        validator_report_records: vec_map.VecMap(bcs.Address, vec_set.VecSet(bcs.Address)),
        /** Any extra fields that's not defined statically. */
        extra_fields: bag.Bag
    } });
export const ValidatorEpochInfoEventV1 = new MoveStruct({ name: `${$moduleName}::ValidatorEpochInfoEventV1`, fields: {
        epoch: bcs.u64(),
        validator_id: bcs.Address,
        stake: bcs.u64(),
        commission_rate: bcs.u16(),
        staking_rewards: bcs.u64(),
        token_exchange_rate: token_exchange_rate.TokenExchangeRate,
        tallying_rule_reporters: bcs.vector(bcs.Address),
        tallying_rule_global_score: bcs.u64()
    } });
export const ValidatorJoinEvent = new MoveStruct({ name: `${$moduleName}::ValidatorJoinEvent`, fields: {
        epoch: bcs.u64(),
        validator_id: bcs.Address
    } });
export const ValidatorLeaveEvent = new MoveStruct({ name: `${$moduleName}::ValidatorLeaveEvent`, fields: {
        withdrawing_epoch: bcs.u64(),
        validator_id: bcs.Address,
        is_voluntary: bcs.bool()
    } });
export interface TotalStakeArguments {
    self: RawTransactionArgument<string>;
}
export interface TotalStakeOptions {
    package?: string;
    arguments: TotalStakeArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function totalStake(options: TotalStakeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'total_stake',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorTotalStakeAmountArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface ValidatorTotalStakeAmountOptions {
    package?: string;
    arguments: ValidatorTotalStakeAmountArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
export function validatorTotalStakeAmount(options: ValidatorTotalStakeAmountOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'validator_total_stake_amount',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GetValidatorArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface GetValidatorOptions {
    package?: string;
    arguments: GetValidatorArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/** Get reference to a validator by id. */
export function getValidator(options: GetValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'get_validator',
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
/** Return the active validators in `self` */
export function activeCommittee(options: ActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
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
/** Return the next epoch active committee in `self` */
export function nextEpochActiveCommittee(options: NextEpochActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'next_epoch_active_committee',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface PendingActiveSetArguments {
    self: RawTransactionArgument<string>;
}
export interface PendingActiveSetOptions {
    package?: string;
    arguments: PendingActiveSetArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Return the pending active set in `self` */
export function pendingActiveSet(options: PendingActiveSetOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'pending_active_set',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsValidatorCandidateArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface IsValidatorCandidateOptions {
    package?: string;
    arguments: IsValidatorCandidateArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/** Returns true if the `validator_id` is a validator candidate. */
export function isValidatorCandidate(options: IsValidatorCandidateOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'is_validator_candidate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsInactiveValidatorArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface IsInactiveValidatorOptions {
    package?: string;
    arguments: IsInactiveValidatorArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/**
 * Returns true if the validator identified by `validator_id` is of an inactive
 * validator.
 */
export function isInactiveValidator(options: IsInactiveValidatorOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_set::ValidatorSet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_set',
        function: 'is_inactive_validator',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}