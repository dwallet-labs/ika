/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type BcsType, bcs } from '@mysten/sui/bcs';
import { MoveStruct } from '../../../utils/index.js';
const $moduleName = '0x2::vec_map';
/** An entry in the map */
export function Entry<K extends BcsType<any>, V extends BcsType<any>>(...typeParameters: [
    K,
    V
]) {
    return new MoveStruct({ name: `${$moduleName}::Entry<${typeParameters[0].name as K['name']}, ${typeParameters[1].name as V['name']}>`, fields: {
            key: typeParameters[0],
            value: typeParameters[1]
        } });
}
/**
 * A map data structure backed by a vector. The map is guaranteed not to contain
 * duplicate keys, but entries are _not_ sorted by key--entries are included in
 * insertion order. All operations are O(N) in the size of the map--the intention
 * of this data structure is only to provide the convenience of programming against
 * a map API. Large maps should use handwritten parent/child relationships instead.
 * Maps that need sorted iteration rather than insertion order iteration should
 * also be handwritten.
 */
export function VecMap<K extends BcsType<any>, V extends BcsType<any>>(...typeParameters: [
    K,
    V
]) {
    return new MoveStruct({ name: `${$moduleName}::VecMap<${typeParameters[0].name as K['name']}, ${typeParameters[1].name as V['name']}>`, fields: {
            contents: bcs.vector(Entry(typeParameters[0], typeParameters[1]))
        } });
}