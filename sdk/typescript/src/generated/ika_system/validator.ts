/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveEnum, MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './deps/sui/object.js';
import * as validator_info from './validator_info.js';
import * as pending_values from './pending_values.js';
import * as table from './deps/sui/table.js';
import * as balance from './deps/sui/balance.js';
import * as bag from './deps/sui/bag.js';
const $moduleName = '@local-pkg/system::validator';
/** Represents the state of the validator. */
export const ValidatorState = new MoveEnum({ name: `${$moduleName}::ValidatorState`, fields: {
        /** The validator is not active yet but can accept stakes. */
        PreActive: null,
        /** The validator is active and can accept stakes. */
        Active: null,
        /**
         * The validator awaits the stake to be withdrawn. The value inside the variant is
         * the epoch in which the validator will be withdrawn.
         */
        Withdrawing: bcs.u64()
    } });
export const Validator = new MoveStruct({ name: `${$moduleName}::Validator`, fields: {
        id: object.UID,
        /** The validator info for the validator. */
        validator_info: validator_info.ValidatorInfo,
        /** The current state of the validator. */
        state: ValidatorState,
        /**
         * The epoch when the validator is / will be activated. Serves information purposes
         * only, the checks are performed in the `state` property.
         */
        activation_epoch: bcs.option(bcs.u64()),
        /** Epoch when the validator was last updated. */
        latest_epoch: bcs.u64(),
        /** Currently staked IKA in the validator + rewards validator. */
        ika_balance: bcs.u64(),
        /** The total number of shares in the current epoch. */
        num_shares: bcs.u64(),
        /**
         * The amount of the shares that will be withdrawn in E+1 or E+2. We use this
         * amount to calculate the IKA withdrawal in the `process_pending_stake`.
         */
        pending_shares_withdraw: pending_values.PendingValues,
        /**
         * The amount of the stake requested for withdrawal for a node that may part of the
         * next committee. Stores principals of not yet active stakes. In practice, those
         * tokens are staked for exactly one epoch.
         */
        pre_active_withdrawals: pending_values.PendingValues,
        /**
         * The pending commission rate for the validator. Commission rate is applied in
         * E+2, so we store the value for the matching epoch and apply it in the
         * `advance_epoch` function.
         */
        pending_commission_rate: pending_values.PendingValues,
        /** The commission rate for the validator, in basis points. */
        commission_rate: bcs.u16(),
        /**
         * Historical exchange rates for the validator. The key is the epoch when the
         * exchange rate was set, and the value is the exchange rate (the ratio of the
         * amount of IKA tokens for the validator shares).
         */
        exchange_rates: table.Table,
        /**
         * The amount of stake that will be added to the `ika_balance`. Can hold up to two
         * keys: E+1 and E+2, due to the differences in the activation epoch.
         *
         * ```
         * E+1 -> Balance
         * E+2 -> Balance
         * ```
         *
         * Single key is cleared in the `advance_epoch` function, leaving only the next
         * epoch's stake.
         */
        pending_stake: pending_values.PendingValues,
        /** The rewards that the validator has received from being in the committee. */
        rewards_pool: balance.Balance,
        /** The commission that the validator has received from the rewards. */
        commission: balance.Balance,
        /** The ID of this validator's `ValidatorCap` */
        validator_cap_id: bcs.Address,
        /** The ID of this validator's current valid `ValidatorOperationCap` */
        operation_cap_id: bcs.Address,
        /** The ID of this validator's current valid `ValidatorCommissionCap` */
        commission_cap_id: bcs.Address,
        /** Reserved for future use and migrations. */
        extra_fields: bag.Bag
    } });