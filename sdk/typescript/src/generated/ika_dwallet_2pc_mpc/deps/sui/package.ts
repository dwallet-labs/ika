/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * Functions for operating on Move packages from within Move:
 * 
 * - Creating proof-of-publish objects from one-time witnesses
 * - Administering package upgrades through upgrade policies.
 */

import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './object.js';
const $moduleName = '0x2::package';
export const Publisher = new MoveStruct({ name: `${$moduleName}::Publisher`, fields: {
        id: object.UID,
        package: bcs.string(),
        module_name: bcs.string()
    } });