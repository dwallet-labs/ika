/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type Transaction } from '@mysten/sui/transactions';
import { normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
export interface Ed25519AddressArguments {
    publicKey: RawTransactionArgument<number[]>;
}
export interface Ed25519AddressOptions {
    package?: string;
    arguments: Ed25519AddressArguments | [
        publicKey: RawTransactionArgument<number[]>
    ];
}
export function ed25519Address(options: Ed25519AddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["publicKey"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'address',
        function: 'ed25519_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}