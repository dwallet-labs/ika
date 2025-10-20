/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * The IKA for the Ika Protocol. Coin<IKA> is the token used to pay for gas in Ika.
 * It has 9 decimals, and the smallest unit (10^-9) is called "INKU".
 */

import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
const $moduleName = '@local-pkg/ika::ika';
export const IKA = new MoveStruct({ name: `${$moduleName}::IKA`, fields: {
        dummy_field: bcs.bool()
    } });
export interface InkuPerIkaOptions {
    package?: string;
    arguments?: [
    ];
}
/** Number of INKU per IKA. */
export function inkuPerIka(options: InkuPerIkaOptions = {}) {
    const packageAddress = options.package ?? '@local-pkg/ika';
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'ika',
        function: 'inku_per_ika',
    });
}