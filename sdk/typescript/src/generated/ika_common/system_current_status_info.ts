/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as bls_committee from './bls_committee.js';
const $moduleName = '@local-pkg/common::system_current_status_info';
export const SystemCurrentStatusInfo = new MoveStruct({ name: `${$moduleName}::SystemCurrentStatusInfo`, fields: {
        current_epoch: bcs.u64(),
        is_mid_epoch_time: bcs.bool(),
        is_end_epoch_time: bcs.bool(),
        current_epoch_active_committee: bls_committee.BlsCommittee,
        next_epoch_active_committee: bcs.option(bls_committee.BlsCommittee)
    } });
export interface CreateArguments {
    currentEpoch: RawTransactionArgument<number | bigint>;
    isMidEpochTime: RawTransactionArgument<boolean>;
    isEndEpochTime: RawTransactionArgument<boolean>;
    currentEpochActiveCommittee: RawTransactionArgument<string>;
    nextEpochActiveCommittee: RawTransactionArgument<string | null>;
    _: RawTransactionArgument<string>;
}
export interface CreateOptions {
    package?: string;
    arguments: CreateArguments | [
        currentEpoch: RawTransactionArgument<number | bigint>,
        isMidEpochTime: RawTransactionArgument<boolean>,
        isEndEpochTime: RawTransactionArgument<boolean>,
        currentEpochActiveCommittee: RawTransactionArgument<string>,
        nextEpochActiveCommittee: RawTransactionArgument<string | null>,
        _: RawTransactionArgument<string>
    ];
}
export function create(options: CreateOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        'u64',
        'bool',
        'bool',
        `${packageAddress}::bls_committee::BlsCommittee`,
        `0x0000000000000000000000000000000000000000000000000000000000000001::option::Option<${packageAddress}::bls_committee::BlsCommittee>`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["currentEpoch", "isMidEpochTime", "isEndEpochTime", "currentEpochActiveCommittee", "nextEpochActiveCommittee", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'create',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CurrentEpochArguments {
    self: RawTransactionArgument<string>;
}
export interface CurrentEpochOptions {
    package?: string;
    arguments: CurrentEpochArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function currentEpoch(options: CurrentEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'current_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsMidEpochTimeArguments {
    self: RawTransactionArgument<string>;
}
export interface IsMidEpochTimeOptions {
    package?: string;
    arguments: IsMidEpochTimeArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function isMidEpochTime(options: IsMidEpochTimeOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'is_mid_epoch_time',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsEndEpochTimeArguments {
    self: RawTransactionArgument<string>;
}
export interface IsEndEpochTimeOptions {
    package?: string;
    arguments: IsEndEpochTimeArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function isEndEpochTime(options: IsEndEpochTimeOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'is_end_epoch_time',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CurrentEpochActiveCommitteeArguments {
    self: RawTransactionArgument<string>;
}
export interface CurrentEpochActiveCommitteeOptions {
    package?: string;
    arguments: CurrentEpochActiveCommitteeArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function currentEpochActiveCommittee(options: CurrentEpochActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'current_epoch_active_committee',
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
export function nextEpochActiveCommittee(options: NextEpochActiveCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'system_current_status_info',
        function: 'next_epoch_active_committee',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}