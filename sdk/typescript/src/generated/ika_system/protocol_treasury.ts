/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as coin from './deps/sui/coin.js';
import * as bag from './deps/sui/bag.js';
const $moduleName = '@local-pkg/system::protocol_treasury';
export const ProtocolTreasury = new MoveStruct({ name: `${$moduleName}::ProtocolTreasury`, fields: {
        /** TreasuryCap of IKA tokens. */
        treasury_cap: coin.TreasuryCap,
        /** Count of the number of times stake subsidies have been distributed. */
        stake_subsidy_distribution_counter: bcs.u64(),
        /**
         * The rate at which the amount per distribution is calculated based on period nad
         * total supply. Expressed in basis points.
         */
        stake_subsidy_rate: bcs.u16(),
        /**
         * The amount of stake subsidy to be destructured per distribution. This amount
         * changes based on `stake_subsidy_rate`.
         */
        stake_subsidy_amount_per_distribution: bcs.u64(),
        /**
         * Number of distributions to occur before the amount per distribution will be
         * recalculated.
         */
        stake_subsidy_period_length: bcs.u64(),
        /** The total supply of IKA tokens at the start of the current period. */
        total_supply_at_period_start: bcs.u64(),
        /** Any extra fields that's not defined statically. */
        extra_fields: bag.Bag
    } });
export interface StakeSubsidyAmountPerDistributionArguments {
    self: RawTransactionArgument<string>;
}
export interface StakeSubsidyAmountPerDistributionOptions {
    package?: string;
    arguments: StakeSubsidyAmountPerDistributionArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the stake subsidy amount per distribution. */
export function stakeSubsidyAmountPerDistribution(options: StakeSubsidyAmountPerDistributionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::protocol_treasury::ProtocolTreasury`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'protocol_treasury',
        function: 'stake_subsidy_amount_per_distribution',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}