/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * Similar to `sui::bag`, an `ObjectBag` is a heterogeneous map-like collection.
 * But unlike `sui::bag`, the values bound to these dynamic fields _must_ be
 * objects themselves. This allows for the objects to still exist in storage, which
 * may be important for external tools. The difference is otherwise not observable
 * from within Move.
 */

import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './object.js';
const $moduleName = '0x2::object_bag';
export const ObjectBag = new MoveStruct({ name: `${$moduleName}::ObjectBag`, fields: {
        /** the ID of this bag */
        id: object.UID,
        /** the number of key-value pairs in the bag */
        size: bcs.u64()
    } });