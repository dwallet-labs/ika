/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * A table is a map-like collection. But unlike a traditional collection, it's keys
 * and values are not stored within the `Table` value, but instead are stored using
 * Sui's object system. The `Table` struct acts only as a handle into the object
 * system to retrieve those keys and values. Note that this means that `Table`
 * values with exactly the same key-value mapping will not be equal, with `==`, at
 * runtime. For example
 * 
 * ```
 * let table1 = table::new<u64, bool>();
 * let table2 = table::new<u64, bool>();
 * table::add(&mut table1, 0, false);
 * table::add(&mut table1, 1, true);
 * table::add(&mut table2, 0, false);
 * table::add(&mut table2, 1, true);
 * // table1 does not equal table2, despite having the same entries
 * assert!(&table1 != &table2);
 * ```
 */

import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './object.js';
const $moduleName = '0x2::table';
export const Table = new MoveStruct({ name: `${$moduleName}::Table`, fields: {
        /** the ID of this table */
        id: object.UID,
        /** the number of key-value pairs in the table */
        size: bcs.u64()
    } });