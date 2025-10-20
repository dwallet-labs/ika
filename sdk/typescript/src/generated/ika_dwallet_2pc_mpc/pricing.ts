/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * This module provides structures and functions for managing pricing information
 * for a dWallet. Each operation (e.g., DKG, re-encrypt user share, ECDSA presign,
 * etc.) has its own pricing data, represented by a `PricingPerOperation`. Each
 * `PricingPerOperation` holds three values:
 * 
 * - **fee_ika**: The IKA fee for the operation.
 * - **gas_fee_reimbursement_sui**: The SUI reimbursement.
 * - **gas_fee_reimbursement_sui_for_system_calls**: The SUI reimbursement for
 *   system calls.
 * 
 * The main struct, `PricingInfo`, now holds one `PricingPerOperation` per
 * operation. The DKG operation is split into two separate rounds:
 * 
 * - `dkg_first_round`
 * - `dkg_second_round`
 */

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as vec_map from './deps/sui/vec_map.js';
import * as bls_committee from './deps/ika_common/bls_committee.js';
const $moduleName = '@local-pkg/2pc-mpc::pricing';
export const PricingInfoKey = new MoveStruct({ name: `${$moduleName}::PricingInfoKey`, fields: {
        curve: bcs.u32(),
        signature_algorithm: bcs.option(bcs.u32()),
        protocol: bcs.u32()
    } });
export const PricingInfoValue = new MoveStruct({ name: `${$moduleName}::PricingInfoValue`, fields: {
        fee_ika: bcs.u64(),
        gas_fee_reimbursement_sui: bcs.u64(),
        gas_fee_reimbursement_sui_for_system_calls: bcs.u64()
    } });
export const PricingInfo = new MoveStruct({ name: `${$moduleName}::PricingInfo`, fields: {
        /**
           * The pricing for each curve and signature algorithm and protocol. The first key
           * is the curve, the second is the signature algorithm, the third is the protocol.
           */
        pricing_map: vec_map.VecMap(PricingInfoKey, PricingInfoValue)
    } });
export const PricingInfoCalculationVotes = new MoveStruct({ name: `${$moduleName}::PricingInfoCalculationVotes`, fields: {
        bls_committee: bls_committee.BlsCommittee,
        default_pricing: PricingInfo,
        working_pricing: PricingInfo
    } });
export interface EmptyOptions {
    package?: string;
    arguments?: [
    ];
}
/**
 * Creates a new [`PricingInfo`] object.
 *
 * Initializes the table with the given pricing values for each operation.
 *
 * # Parameters
 *
 * - `ctx`: The transaction context.
 *
 * # Returns
 *
 * A newly created instance of `PricingInfo`.
 */
export function empty(options: EmptyOptions = {}) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'pricing',
        function: 'empty',
    });
}
export interface InsertOrUpdatePricingArguments {
    self: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    signatureAlgorithm: RawTransactionArgument<number | null>;
    protocol: RawTransactionArgument<number>;
    feeIka: RawTransactionArgument<number | bigint>;
    gasFeeReimbursementSui: RawTransactionArgument<number | bigint>;
    gasFeeReimbursementSuiForSystemCalls: RawTransactionArgument<number | bigint>;
}
export interface InsertOrUpdatePricingOptions {
    package?: string;
    arguments: InsertOrUpdatePricingArguments | [
        self: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        signatureAlgorithm: RawTransactionArgument<number | null>,
        protocol: RawTransactionArgument<number>,
        feeIka: RawTransactionArgument<number | bigint>,
        gasFeeReimbursementSui: RawTransactionArgument<number | bigint>,
        gasFeeReimbursementSuiForSystemCalls: RawTransactionArgument<number | bigint>
    ];
}
/**
 * Inserts pricing information for a specific operation into the [`PricingInfo`]
 * table.
 *
 * # Parameters
 *
 * - `self`: The [`PricingInfo`] object.
 * - `key`: The key for the operation.
 * - `value`: The pricing information for the operation.
 *
 * # Returns
 *
 * The [`PricingInfo`] object.
 */
export function insertOrUpdatePricing(options: InsertOrUpdatePricingOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::pricing::PricingInfo`,
        'u32',
        '0x0000000000000000000000000000000000000000000000000000000000000001::option::Option<u32>',
        'u32',
        'u64',
        'u64',
        'u64'
    ] satisfies string[];
    const parameterNames = ["self", "curve", "signatureAlgorithm", "protocol", "feeIka", "gasFeeReimbursementSui", "gasFeeReimbursementSuiForSystemCalls"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'pricing',
        function: 'insert_or_update_pricing',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface FeeIkaArguments {
    self: RawTransactionArgument<string>;
}
export interface FeeIkaOptions {
    package?: string;
    arguments: FeeIkaArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Getter for the fee_ika field of a PricingInfoValue. */
export function feeIka(options: FeeIkaOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::pricing::PricingInfoValue`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'pricing',
        function: 'fee_ika',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GasFeeReimbursementSuiArguments {
    self: RawTransactionArgument<string>;
}
export interface GasFeeReimbursementSuiOptions {
    package?: string;
    arguments: GasFeeReimbursementSuiArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Getter for the gas_fee_reimbursement_sui field of a PricingInfoValue. */
export function gasFeeReimbursementSui(options: GasFeeReimbursementSuiOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::pricing::PricingInfoValue`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'pricing',
        function: 'gas_fee_reimbursement_sui',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GasFeeReimbursementSuiForSystemCallsArguments {
    self: RawTransactionArgument<string>;
}
export interface GasFeeReimbursementSuiForSystemCallsOptions {
    package?: string;
    arguments: GasFeeReimbursementSuiForSystemCallsArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Getter for the gas_fee_reimbursement_sui_for_system_calls field of a
 * PricingInfoValue.
 */
export function gasFeeReimbursementSuiForSystemCalls(options: GasFeeReimbursementSuiForSystemCallsOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::pricing::PricingInfoValue`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'pricing',
        function: 'gas_fee_reimbursement_sui_for_system_calls',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}