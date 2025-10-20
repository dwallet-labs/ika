/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * Contains an active set of validators. The active set is a smart collection that
 * only stores up to a max size of validators. The active set tracks the total
 * amount of staked IKA to make the calculation of the rewards and voting power
 * distribution easier.
 */

import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as vec_set from './deps/sui/vec_set.js';
const $moduleName = '@local-pkg/system::pending_active_set';
export const PendingActiveSetEntry = new MoveStruct({ name: `${$moduleName}::PendingActiveSetEntry`, fields: {
        /** The ID of the validator */
        validator_id: bcs.Address,
        /** The amount of IKA staked by this validator */
        staked_amount: bcs.u64()
    } });
export const PendingActiveSet = new MoveStruct({ name: `${$moduleName}::PendingActiveSet`, fields: {
        /** The minimum number of validators required in the active set */
        min_validator_count: bcs.u64(),
        /** The maximum number of validators in the active set */
        max_validator_count: bcs.u64(),
        /**
         * The minimum amount of staked IKA needed to enter the active set. This is used to
         * determine if a storage validator can be added to the active set
         */
        min_validator_joining_stake: bcs.u64(),
        /**
         * The maximum number of validators that can be added or removed to the active set
         * in an epoch
         */
        max_validator_change_count: bcs.u64(),
        /** The list of validators in the active set and their stake */
        validators: bcs.vector(PendingActiveSetEntry),
        /** The total amount of staked IKA in the active set */
        total_stake: bcs.u64(),
        /**
         * The list of validators that have been added or removed to the active set in the
         * current epoch
         */
        validator_changes: vec_set.VecSet(bcs.Address)
    } });