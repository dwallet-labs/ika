/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as system_object_cap from './deps/ika_common/system_object_cap.js';
import * as _package from './deps/sui/package.js';
import * as vec_map from './deps/sui/vec_map.js';
import * as validator_set from './validator_set.js';
import * as protocol_treasury from './protocol_treasury.js';
import * as balance from './deps/sui/balance.js';
import * as bag from './deps/sui/bag.js';
const $moduleName = '@local-pkg/system::system_inner';
export const SystemInner = new MoveStruct({ name: `${$moduleName}::SystemInner`, fields: {
        /** The current epoch ID, starting from 0. */
        epoch: bcs.u64(),
        epoch_start_tx_digest: bcs.vector(bcs.u8()),
        /** The system object cap for common modules. */
        system_object_cap: system_object_cap.SystemObjectCap,
        /** The current protocol version, starting from 1. */
        protocol_version: bcs.u64(),
        next_protocol_version: bcs.option(bcs.u64()),
        /** Upgrade caps for this package and others like ika coin of the ika protocol. */
        upgrade_caps: bcs.vector(_package.UpgradeCap),
        /** Approved upgrade for package id to its approved digest. */
        approved_upgrades: vec_map.VecMap(bcs.Address, bcs.vector(bcs.u8())),
        /** Contains all information about the validators. */
        validator_set: validator_set.ValidatorSet,
        /** The duration of an epoch, in milliseconds. */
        epoch_duration_ms: bcs.u64(),
        /** The starting epoch in which stake subsidies start being paid out */
        stake_subsidy_start_epoch: bcs.u64(),
        /** Schedule of stake subsidies given out each epoch. */
        protocol_treasury: protocol_treasury.ProtocolTreasury,
        /** Unix timestamp of the current epoch start. */
        epoch_start_timestamp_ms: bcs.u64(),
        /** The last processed checkpoint sequence number. */
        last_processed_checkpoint_sequence_number: bcs.u64(),
        /** The last checkpoint sequence number of the previous epoch. */
        previous_epoch_last_checkpoint_sequence_number: bcs.u64(),
        /** The total messages processed. */
        total_messages_processed: bcs.u64(),
        /** The fees paid for computation. */
        remaining_rewards: balance.Balance,
        /** List of authorized protocol cap ids. */
        authorized_protocol_cap_ids: bcs.vector(bcs.Address),
        /**
         * List of witnesses approving advance epoch. as part of the epoch advancement, we
         * have to collect approval from all witnesses.
         */
        witnesses_approving_advance_epoch: bcs.vector(bcs.string()),
        /** Whether the system has received the end of publish message. */
        received_end_of_publish: bcs.bool(),
        /** Any extra fields that's not defined statically. */
        extra_fields: bag.Bag
    } });
export const SystemEpochInfoEvent = new MoveStruct({ name: `${$moduleName}::SystemEpochInfoEvent`, fields: {
        epoch: bcs.u64(),
        protocol_version: bcs.u64(),
        total_stake: bcs.u64(),
        stake_subsidy_amount: bcs.u64(),
        total_computation_fees: bcs.u64(),
        total_stake_rewards_distributed: bcs.u64()
    } });
export const SystemCheckpointInfoEvent = new MoveStruct({ name: `${$moduleName}::SystemCheckpointInfoEvent`, fields: {
        epoch: bcs.u64(),
        sequence_number: bcs.u64()
    } });
export const SetNextProtocolVersionEvent = new MoveStruct({ name: `${$moduleName}::SetNextProtocolVersionEvent`, fields: {
        epoch: bcs.u64(),
        next_protocol_version: bcs.u64()
    } });
export const SetEpochDurationMsEvent = new MoveStruct({ name: `${$moduleName}::SetEpochDurationMsEvent`, fields: {
        epoch: bcs.u64(),
        epoch_duration_ms: bcs.u64()
    } });
export const SetStakeSubsidyStartEpochEvent = new MoveStruct({ name: `${$moduleName}::SetStakeSubsidyStartEpochEvent`, fields: {
        epoch: bcs.u64(),
        stake_subsidy_start_epoch: bcs.u64()
    } });
export const SetStakeSubsidyRateEvent = new MoveStruct({ name: `${$moduleName}::SetStakeSubsidyRateEvent`, fields: {
        epoch: bcs.u64(),
        stake_subsidy_rate: bcs.u16()
    } });
export const SetStakeSubsidyPeriodLengthEvent = new MoveStruct({ name: `${$moduleName}::SetStakeSubsidyPeriodLengthEvent`, fields: {
        epoch: bcs.u64(),
        stake_subsidy_period_length: bcs.u64()
    } });
export const SetMinValidatorCountEvent = new MoveStruct({ name: `${$moduleName}::SetMinValidatorCountEvent`, fields: {
        epoch: bcs.u64(),
        min_validator_count: bcs.u64()
    } });
export const SetMaxValidatorCountEvent = new MoveStruct({ name: `${$moduleName}::SetMaxValidatorCountEvent`, fields: {
        epoch: bcs.u64(),
        max_validator_count: bcs.u64()
    } });
export const SetMinValidatorJoiningStakeEvent = new MoveStruct({ name: `${$moduleName}::SetMinValidatorJoiningStakeEvent`, fields: {
        epoch: bcs.u64(),
        min_validator_joining_stake: bcs.u64()
    } });
export const SetMaxValidatorChangeCountEvent = new MoveStruct({ name: `${$moduleName}::SetMaxValidatorChangeCountEvent`, fields: {
        epoch: bcs.u64(),
        max_validator_change_count: bcs.u64()
    } });
export const SetRewardSlashingRateEvent = new MoveStruct({ name: `${$moduleName}::SetRewardSlashingRateEvent`, fields: {
        epoch: bcs.u64(),
        reward_slashing_rate: bcs.u16()
    } });
export const SetApprovedUpgradeEvent = new MoveStruct({ name: `${$moduleName}::SetApprovedUpgradeEvent`, fields: {
        epoch: bcs.u64(),
        package_id: bcs.Address,
        digest: bcs.option(bcs.vector(bcs.u8()))
    } });
export const EndOfPublishEvent = new MoveStruct({ name: `${$moduleName}::EndOfPublishEvent`, fields: {
        epoch: bcs.u64()
    } });
export const SetOrRemoveWitnessApprovingAdvanceEpochEvent = new MoveStruct({ name: `${$moduleName}::SetOrRemoveWitnessApprovingAdvanceEpochEvent`, fields: {
        epoch: bcs.u64(),
        witness_type: bcs.string(),
        remove: bcs.bool()
    } });