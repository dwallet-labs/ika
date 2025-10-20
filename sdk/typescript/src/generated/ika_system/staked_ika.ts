/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * Implements the `StakedIka` functionality - a staked IKA is an object that
 * represents a staked amount of IKAs in a staking pool. It is created in the
 * `staking_pool` on staking and can be split, joined, and burned. The burning is
 * performed via the `withdraw_stake` method in the `staking_pool`.
 */

import { MoveEnum, MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
import * as balance from './deps/sui/balance.js';
const $moduleName = '@local-pkg/system::staked_ika';
/**
 * The state of the staked IKA. It can be either `Staked` or `Withdrawing`. The
 * `Withdrawing` state contains the epoch when the staked IKA can be withdrawn.
 */
export const StakedIkaState = new MoveEnum({ name: `${$moduleName}::StakedIkaState`, fields: {
        Staked: null,
        Withdrawing: new MoveStruct({ name: `StakedIkaState.Withdrawing`, fields: {
                withdraw_epoch: bcs.u64()
            } })
    } });
export const StakedIka = new MoveStruct({ name: `${$moduleName}::StakedIka`, fields: {
        id: object.UID,
        /** Whether the staked IKA is active or withdrawing. */
        state: StakedIkaState,
        /** ID of the staking pool. */
        validator_id: bcs.Address,
        /** The staked amount. */
        principal: balance.Balance,
        /** The Ikarus epoch when the staked IKA was activated. */
        activation_epoch: bcs.u64()
    } });
export interface ValidatorIdArguments {
    sw: RawTransactionArgument<string>;
}
export interface ValidatorIdOptions {
    package?: string;
    arguments: ValidatorIdArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/** Returns the `validator_id` of the staked IKA. */
export function validatorId(options: ValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValueArguments {
    sw: RawTransactionArgument<string>;
}
export interface ValueOptions {
    package?: string;
    arguments: ValueArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/**
 * Returns the `principal` of the staked IKA. Called `value` to be consistent with
 * `Coin`.
 */
export function value(options: ValueOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'value',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ActivationEpochArguments {
    sw: RawTransactionArgument<string>;
}
export interface ActivationEpochOptions {
    package?: string;
    arguments: ActivationEpochArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/** Returns the `activation_epoch` of the staked IKA. */
export function activationEpoch(options: ActivationEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'activation_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsStakedArguments {
    sw: RawTransactionArgument<string>;
}
export interface IsStakedOptions {
    package?: string;
    arguments: IsStakedArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/** Returns true if the staked IKA is in the `Staked` state. */
export function isStaked(options: IsStakedOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'is_staked',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsWithdrawingArguments {
    sw: RawTransactionArgument<string>;
}
export interface IsWithdrawingOptions {
    package?: string;
    arguments: IsWithdrawingArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/** Checks whether the staked IKA is in the `Withdrawing` state. */
export function isWithdrawing(options: IsWithdrawingOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'is_withdrawing',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface WithdrawEpochArguments {
    sw: RawTransactionArgument<string>;
}
export interface WithdrawEpochOptions {
    package?: string;
    arguments: WithdrawEpochArguments | [
        sw: RawTransactionArgument<string>
    ];
}
/**
 * Returns the `withdraw_epoch` of the staked IKA if it is in the `Withdrawing`.
 * Aborts otherwise.
 */
export function withdrawEpoch(options: WithdrawEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'withdraw_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface JoinArguments {
    sw: RawTransactionArgument<string>;
    other: RawTransactionArgument<string>;
}
export interface JoinOptions {
    package?: string;
    arguments: JoinArguments | [
        sw: RawTransactionArgument<string>,
        other: RawTransactionArgument<string>
    ];
}
/**
 * Joins the staked IKA with another staked IKA, adding the `principal` of the
 * `other` staked IKA to the current staked IKA.
 *
 * Aborts if the `validator_id` or `activation_epoch` of the staked IKAs do not
 * match.
 */
export function join(options: JoinOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`,
        `${packageAddress}::staked_ika::StakedIka`
    ] satisfies string[];
    const parameterNames = ["sw", "other"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'join',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SplitArguments {
    sw: RawTransactionArgument<string>;
    amount: RawTransactionArgument<number | bigint>;
}
export interface SplitOptions {
    package?: string;
    arguments: SplitArguments | [
        sw: RawTransactionArgument<string>,
        amount: RawTransactionArgument<number | bigint>
    ];
}
/**
 * Splits the staked IKA into two parts, one with the `amount` and the other with
 * the remaining `principal`. The `validator_id`, `activation_epoch` are the same
 * for both the staked IKAs.
 *
 * Aborts if the `amount` is greater than the `principal` of the staked IKA. Aborts
 * if the `amount` is zero.
 */
export function split(options: SplitOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::staked_ika::StakedIka`,
        'u64'
    ] satisfies string[];
    const parameterNames = ["sw", "amount"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'staked_ika',
        function: 'split',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}