/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../../../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as group_ops from '../sui/group_ops.js';
const $moduleName = 'ika_common::bls_committee';
export const BlsCommitteeMember = new MoveStruct({ name: `${$moduleName}::BlsCommitteeMember`, fields: {
        validator_id: bcs.Address,
        protocol_pubkey: group_ops.Element
    } });
export const BlsCommittee = new MoveStruct({ name: `${$moduleName}::BlsCommittee`, fields: {
        members: bcs.vector(BlsCommitteeMember),
        /** The aggregation of public keys for all members of the committee */
        aggregated_protocol_pubkey: group_ops.Element,
        /** Minimum signatures required for quorum (2n/3 + 1) */
        quorum_threshold: bcs.u64(),
        /** Minimum signatures required for validity (n/3 + 1) */
        validity_threshold: bcs.u64()
    } });