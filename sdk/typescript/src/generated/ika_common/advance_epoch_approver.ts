/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs, type BcsType } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as balance from './deps/sui/balance.js';
const $moduleName = '@local-pkg/common::advance_epoch_approver';
export const AdvanceEpochApprover = new MoveStruct({ name: `${$moduleName}::AdvanceEpochApprover`, fields: {
        new_epoch: bcs.u64(),
        remaining_witnesses_to_approve: bcs.vector(bcs.string()),
        balance_ika: balance.Balance
    } });
export interface CreateArguments {
    newEpoch: RawTransactionArgument<number | bigint>;
    remainingWitnessesToApprove: RawTransactionArgument<string[]>;
    balanceIka: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface CreateOptions {
    package?: string;
    arguments: CreateArguments | [
        newEpoch: RawTransactionArgument<number | bigint>,
        remainingWitnessesToApprove: RawTransactionArgument<string[]>,
        balanceIka: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function create(options: CreateOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        'u64',
        'vector<0x0000000000000000000000000000000000000000000000000000000000000001::string::String>',
        `0x0000000000000000000000000000000000000000000000000000000000000002::balance::Balance<${packageAddress}::ika::IKA>`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["newEpoch", "remainingWitnessesToApprove", "balanceIka", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'advance_epoch_approver',
        function: 'create',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewEpochArguments {
    self: RawTransactionArgument<string>;
}
export interface NewEpochOptions {
    package?: string;
    arguments: NewEpochArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function newEpoch(options: NewEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'advance_epoch_approver',
        function: 'new_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AssertAllWitnessesApprovedArguments {
    self: RawTransactionArgument<string>;
}
export interface AssertAllWitnessesApprovedOptions {
    package?: string;
    arguments: AssertAllWitnessesApprovedArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function assertAllWitnessesApproved(options: AssertAllWitnessesApprovedOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'advance_epoch_approver',
        function: 'assert_all_witnesses_approved',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface DestroyArguments {
    self: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface DestroyOptions {
    package?: string;
    arguments: DestroyArguments | [
        self: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function destroy(options: DestroyOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["self", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'advance_epoch_approver',
        function: 'destroy',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ApproveAdvanceEpochByWitnessArguments<Witness extends BcsType<any>> {
    advanceEpochApprover: RawTransactionArgument<string>;
    _: RawTransactionArgument<Witness>;
    balanceIka: RawTransactionArgument<string>;
}
export interface ApproveAdvanceEpochByWitnessOptions<Witness extends BcsType<any>> {
    package?: string;
    arguments: ApproveAdvanceEpochByWitnessArguments<Witness> | [
        advanceEpochApprover: RawTransactionArgument<string>,
        _: RawTransactionArgument<Witness>,
        balanceIka: RawTransactionArgument<string>
    ];
    typeArguments: [
        string
    ];
}
export function approveAdvanceEpochByWitness<Witness extends BcsType<any>>(options: ApproveAdvanceEpochByWitnessOptions<Witness>) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`,
        `${options.typeArguments[0]}`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::balance::Balance<${packageAddress}::ika::IKA>`
    ] satisfies string[];
    const parameterNames = ["advanceEpochApprover", "_", "balanceIka"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'advance_epoch_approver',
        function: 'approve_advance_epoch_by_witness',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
        typeArguments: options.typeArguments
    });
}