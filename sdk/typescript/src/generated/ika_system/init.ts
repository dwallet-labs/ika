/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
import * as _package from './deps/sui/package.js';
const $moduleName = '@local-pkg/system::init';
export const INIT = new MoveStruct({ name: `${$moduleName}::INIT`, fields: {
        dummy_field: bcs.bool()
    } });
export const InitCap = new MoveStruct({ name: `${$moduleName}::InitCap`, fields: {
        id: object.UID,
        publisher: _package.Publisher
    } });
export interface InitializeArguments {
    initCap: RawTransactionArgument<string>;
    systemObjectCap: RawTransactionArgument<string>;
    ikaUpgradeCap: RawTransactionArgument<string>;
    ikaSystemUpgradeCap: RawTransactionArgument<string>;
    protocolTreasuryCap: RawTransactionArgument<string>;
    protocolVersion: RawTransactionArgument<number | bigint>;
    chainStartTimestampMs: RawTransactionArgument<number | bigint>;
    epochDurationMs: RawTransactionArgument<number | bigint>;
    stakeSubsidyStartEpoch: RawTransactionArgument<number | bigint>;
    stakeSubsidyRate: RawTransactionArgument<number>;
    stakeSubsidyPeriodLength: RawTransactionArgument<number | bigint>;
    minValidatorCount: RawTransactionArgument<number | bigint>;
    maxValidatorCount: RawTransactionArgument<number | bigint>;
    minValidatorJoiningStake: RawTransactionArgument<number | bigint>;
    rewardSlashingRate: RawTransactionArgument<number>;
    stakedIkaImageUrl: RawTransactionArgument<string>;
}
export interface InitializeOptions {
    package?: string;
    arguments: InitializeArguments | [
        initCap: RawTransactionArgument<string>,
        systemObjectCap: RawTransactionArgument<string>,
        ikaUpgradeCap: RawTransactionArgument<string>,
        ikaSystemUpgradeCap: RawTransactionArgument<string>,
        protocolTreasuryCap: RawTransactionArgument<string>,
        protocolVersion: RawTransactionArgument<number | bigint>,
        chainStartTimestampMs: RawTransactionArgument<number | bigint>,
        epochDurationMs: RawTransactionArgument<number | bigint>,
        stakeSubsidyStartEpoch: RawTransactionArgument<number | bigint>,
        stakeSubsidyRate: RawTransactionArgument<number>,
        stakeSubsidyPeriodLength: RawTransactionArgument<number | bigint>,
        minValidatorCount: RawTransactionArgument<number | bigint>,
        maxValidatorCount: RawTransactionArgument<number | bigint>,
        minValidatorJoiningStake: RawTransactionArgument<number | bigint>,
        rewardSlashingRate: RawTransactionArgument<number>,
        stakedIkaImageUrl: RawTransactionArgument<string>
    ];
}
/**
 * Function to initialize ika and share the system object. This can only be called
 * once, after which the `InitCap` is destroyed.
 */
export function initialize(options: InitializeOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::init::InitCap`,
        `${packageAddress}::system_object_cap::SystemObjectCap`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeCap',
        '0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeCap',
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::TreasuryCap<${packageAddress}::ika::IKA>`,
        'u64',
        'u64',
        'u64',
        'u64',
        'u16',
        'u64',
        'u64',
        'u64',
        'u64',
        'u16',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["initCap", "systemObjectCap", "ikaUpgradeCap", "ikaSystemUpgradeCap", "protocolTreasuryCap", "protocolVersion", "chainStartTimestampMs", "epochDurationMs", "stakeSubsidyStartEpoch", "stakeSubsidyRate", "stakeSubsidyPeriodLength", "minValidatorCount", "maxValidatorCount", "minValidatorJoiningStake", "rewardSlashingRate", "stakedIkaImageUrl"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'init',
        function: 'initialize',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}