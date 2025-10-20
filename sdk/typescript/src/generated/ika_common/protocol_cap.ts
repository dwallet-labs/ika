/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
const $moduleName = '@local-pkg/common::protocol_cap';
export const ProtocolCap = new MoveStruct({ name: `${$moduleName}::ProtocolCap`, fields: {
        id: object.UID
    } });
export const VerifiedProtocolCap = new MoveStruct({ name: `${$moduleName}::VerifiedProtocolCap`, fields: {
        dummy_field: bcs.bool()
    } });
export interface CreateArguments {
    _: RawTransactionArgument<string>;
}
export interface CreateOptions {
    package?: string;
    arguments: CreateArguments | [
        _: RawTransactionArgument<string>
    ];
}
export function create(options: CreateOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'protocol_cap',
        function: 'create',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CreateVerifiedArguments {
    _: RawTransactionArgument<string>;
}
export interface CreateVerifiedOptions {
    package?: string;
    arguments: CreateVerifiedArguments | [
        _: RawTransactionArgument<string>
    ];
}
export function createVerified(options: CreateVerifiedOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'protocol_cap',
        function: 'create_verified',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}