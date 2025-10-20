/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * A bag is a heterogeneous map-like collection. The collection is similar to
 * `sui::table` in that its keys and values are not stored within the `Bag` value,
 * but instead are stored using Sui's object system. The `Bag` struct acts only as
 * a handle into the object system to retrieve those keys and values. Note that
 * this means that `Bag` values with exactly the same key-value mapping will not be
 * equal, with `==`, at runtime. For example
 * 
 * ```
 * let bag1 = bag::new();
 * let bag2 = bag::new();
 * bag::add(&mut bag1, 0, false);
 * bag::add(&mut bag1, 1, true);
 * bag::add(&mut bag2, 0, false);
 * bag::add(&mut bag2, 1, true);
 * // bag1 does not equal bag2, despite having the same entries
 * assert!(&bag1 != &bag2);
 * ```
 * 
 * At it's core, `sui::bag` is a wrapper around `UID` that allows for access to
 * `sui::dynamic_field` while preventing accidentally stranding field values. A
 * `UID` can be deleted, even if it has dynamic fields associated with it, but a
 * bag, on the other hand, must be empty to be destroyed.
 */

import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as object from './object.js';
const $moduleName = '0x2::bag';
export const Bag = new MoveStruct({ name: `${$moduleName}::Bag`, fields: {
        /** the ID of this bag */
        id: object.UID,
        /** the number of key-value pairs in the bag */
        size: bcs.u64()
    } });