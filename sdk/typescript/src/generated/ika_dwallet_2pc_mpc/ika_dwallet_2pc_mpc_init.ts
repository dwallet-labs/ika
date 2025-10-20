/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
import * as _package from './deps/sui/package.js';
const $moduleName = '@local-pkg/2pc-mpc::ika_dwallet_2pc_mpc_init';
export const IKA_DWALLET_2PC_MPC_INIT = new MoveStruct({ name: `${$moduleName}::IKA_DWALLET_2PC_MPC_INIT`, fields: {
        dummy_field: bcs.bool()
    } });
export const InitCap = new MoveStruct({ name: `${$moduleName}::InitCap`, fields: {
        id: object.UID,
        publisher: _package.Publisher
    } });
export interface InitializeArguments {
    initCap: RawTransactionArgument<string>;
    advanceEpochApprover: RawTransactionArgument<string>;
    systemCurrentStatusInfo: RawTransactionArgument<string>;
    pricing: RawTransactionArgument<string>;
    supportedCurvesToSignatureAlgorithmsToHashSchemes: RawTransactionArgument<string>;
    dwalletCapImageUrl: RawTransactionArgument<string>;
    importedKeyDwalletCapImageUrl: RawTransactionArgument<string>;
    unverifiedPresignCapImageUrl: RawTransactionArgument<string>;
    verifiedPresignCapImageUrl: RawTransactionArgument<string>;
    unverifiedPartialUserSignatureCapImageUrl: RawTransactionArgument<string>;
    verifiedPartialUserSignatureCapImageUrl: RawTransactionArgument<string>;
}
export interface InitializeOptions {
    package?: string;
    arguments: InitializeArguments | [
        initCap: RawTransactionArgument<string>,
        advanceEpochApprover: RawTransactionArgument<string>,
        systemCurrentStatusInfo: RawTransactionArgument<string>,
        pricing: RawTransactionArgument<string>,
        supportedCurvesToSignatureAlgorithmsToHashSchemes: RawTransactionArgument<string>,
        dwalletCapImageUrl: RawTransactionArgument<string>,
        importedKeyDwalletCapImageUrl: RawTransactionArgument<string>,
        unverifiedPresignCapImageUrl: RawTransactionArgument<string>,
        verifiedPresignCapImageUrl: RawTransactionArgument<string>,
        unverifiedPartialUserSignatureCapImageUrl: RawTransactionArgument<string>,
        verifiedPartialUserSignatureCapImageUrl: RawTransactionArgument<string>
    ];
}
/**
 * Function to initialize ika and share the system object. This can only be called
 * once, after which the `InitCap` is destroyed.
 */
export function initialize(options: InitializeOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::ika_dwallet_2pc_mpc_init::InitCap`,
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`,
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`,
        `${packageAddress}::pricing::PricingInfo`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::vec_map::VecMap<u32, 0x0000000000000000000000000000000000000000000000000000000000000002::vec_map::VecMap<u32, vector<u32>>>',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["initCap", "advanceEpochApprover", "systemCurrentStatusInfo", "pricing", "supportedCurvesToSignatureAlgorithmsToHashSchemes", "dwalletCapImageUrl", "importedKeyDwalletCapImageUrl", "unverifiedPresignCapImageUrl", "verifiedPresignCapImageUrl", "unverifiedPartialUserSignatureCapImageUrl", "verifiedPartialUserSignatureCapImageUrl"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'ika_dwallet_2pc_mpc_init',
        function: 'initialize',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}