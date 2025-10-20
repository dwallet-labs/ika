/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveTuple } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as vec_map from './deps/sui/vec_map.js';
const $moduleName = '@local-pkg/system::pending_values';
export const PendingValues = new MoveTuple({ name: `${$moduleName}::PendingValues`, fields: [vec_map.VecMap(bcs.u64(), bcs.u64())] });