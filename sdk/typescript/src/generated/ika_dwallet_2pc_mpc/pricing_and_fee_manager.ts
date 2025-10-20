/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as pricing from './pricing.js';
import * as table from './deps/sui/table.js';
import * as balance from './deps/sui/balance.js';
const $moduleName = '@local-pkg/2pc-mpc::pricing_and_fee_manager';
export const PricingAndFeeManager = new MoveStruct({ name: `${$moduleName}::PricingAndFeeManager`, fields: {
        /** Pricing for the current epoch */
        current: pricing.PricingInfo,
        /** Default pricing configuration */
        default: pricing.PricingInfo,
        /** Validator votes for pricing (validator ID -> pricing vote) */
        validator_votes: table.Table,
        /** Pricing calculation votes - if set, must complete before epoch advance */
        pricing_calculation_votes: bcs.option(pricing.PricingInfoCalculationVotes),
        /** Gas fee reimbursement value for system calls */
        gas_fee_reimbursement_sui_system_call_value: bcs.u64(),
        /** SUI balance for gas fee reimbursement to fund network tx responses */
        gas_fee_reimbursement_sui_system_call_balance: balance.Balance,
        /** IKA fees charged for consensus validation */
        fee_charged_ika: balance.Balance
    } });