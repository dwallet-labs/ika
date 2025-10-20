/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * A utility module which implements an `ExchangeRate` struct and its methods. It
 * stores a fixed point exchange rate between the IKA token and validator shares.
 */

import { MoveEnum, MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
const $moduleName = '@local-pkg/system::token_exchange_rate';
/** Represents the exchange rate for the staking validator. */
export const TokenExchangeRate = new MoveEnum({ name: `${$moduleName}::TokenExchangeRate`, fields: {
        Flat: null,
        Variable: new MoveStruct({ name: `TokenExchangeRate.Variable`, fields: {
                ika_amount: bcs.u128(),
                share_amount: bcs.u128()
            } })
    } });