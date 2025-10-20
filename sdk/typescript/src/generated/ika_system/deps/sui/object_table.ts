/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * Similar to `sui::table`, an `ObjectTable<K, V>` is a map-like collection. But
 * unlike `sui::table`, the values bound to these dynamic fields _must_ be objects
 * themselves. This allows for the objects to still exist within in storage, which
 * may be important for external tools. The difference is otherwise not observable
 * from within Move.
 */

import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './object.js';
const $moduleName = '0x2::object_table';
export const ObjectTable = new MoveStruct({ name: `${$moduleName}::ObjectTable`, fields: {
        /** the ID of this table */
        id: object.UID,
        /** the number of key-value pairs in the table */
        size: bcs.u64()
    } });