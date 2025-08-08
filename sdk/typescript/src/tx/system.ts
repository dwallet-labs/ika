import { bcs } from '@mysten/bcs';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { IkaConfig } from '../client/types.js';

export function requestAddValidatorCandidate(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	name: string,
	protocolPubkeyBytes: Uint8Array,
	networkPubkeyBytes: Uint8Array,
	consensusPubkeyBytes: Uint8Array,
	mpcDataBytes: Uint8Array[],
	proofOfPossessionBytes: Uint8Array,
	networkAddress: string,
	p2pAddress: string,
	consensusAddress: string,
	commissionRate: number,
	metadata: {
		name: string;
		description: string;
		imageUrl: string;
		projectUrl: string;
	},
	tx: Transaction,
): {
	validatorCap: TransactionObjectArgument;
	validatorOperationCap: TransactionObjectArgument;
	validatorCommissionCap: TransactionObjectArgument;
} {
	const [validatorCap, validatorOperationCap, validatorCommissionCap] = tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_validator_candidate`,
		arguments: [
			systemObjectRef,
			tx.pure.string(name),
			tx.pure(bcs.vector(bcs.u8()).serialize(protocolPubkeyBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(networkPubkeyBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(consensusPubkeyBytes)),
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(mpcDataBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(proofOfPossessionBytes)),
			tx.pure.string(networkAddress),
			tx.pure.string(p2pAddress),
			tx.pure.string(consensusAddress),
			tx.pure.u16(commissionRate),
			tx.moveCall({
				target: `${ikaConfig.packages.ikaSystemPackage}::validator_metadata::new`,
				arguments: [
					tx.pure.string(metadata.imageUrl),
					tx.pure.string(metadata.projectUrl),
					tx.pure.string(metadata.description),
				],
			}),
		],
	});

	return {
		validatorCap,
		validatorOperationCap,
		validatorCommissionCap,
	};
}

export function requestRemoveValidatorCandidate(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_remove_validator_candidate`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function requestAddValidator(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_validator`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function requestRemoveValidator(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_remove_validator`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function setNextCommission(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	newCommissionRate: number,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_commission`,
		arguments: [systemObjectRef, tx.pure.u16(newCommissionRate), tx.object(validatorOperationCap)],
	});
}

export function requestAddStake(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	stakeCoin: TransactionObjectArgument,
	validatorId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_stake`,
		arguments: [systemObjectRef, stakeCoin, tx.pure.id(validatorId)],
	});
}

export function requestWithdrawStake(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	stakedIka: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_withdraw_stake`,
		arguments: [systemObjectRef, tx.object(stakedIka)],
	});
}

export function withdrawStake(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	stakedIka: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::withdraw_stake`,
		arguments: [systemObjectRef, tx.object(stakedIka)],
	});
}

export function reportValidator(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorOperationCap: string,
	reporteeId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::report_validator`,
		arguments: [systemObjectRef, tx.object(validatorOperationCap), tx.pure.id(reporteeId)],
	});
}

export function undoReportValidator(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorOperationCap: string,
	reporteeId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::undo_report_validator`,
		arguments: [systemObjectRef, tx.object(validatorOperationCap), tx.pure.id(reporteeId)],
	});
}

export function rotateOperationCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::rotate_operation_cap`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function rotateCommissionCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::rotate_commission_cap`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function collectCommission(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCommissionCap: string,
	amount: number | null,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::collect_commission`,
		arguments: [
			systemObjectRef,
			tx.object(validatorCommissionCap),
			amount !== null
				? tx.pure(bcs.option(bcs.u64()).serialize(amount))
				: tx.pure(bcs.option(bcs.u64()).serialize(null)),
		],
	});
}

export function setValidatorName(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	name: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_validator_name`,
		arguments: [systemObjectRef, tx.pure.string(name), tx.object(validatorOperationCap)],
	});
}

export function validatorMetadata(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::validator_metadata`,
		arguments: [systemObjectRef, tx.pure.id(validatorId)],
	});
}

export function setValidatorMetadata(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	metadata: {
		description: string;
		imageUrl: string;
		projectUrl: string;
	},
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_validator_metadata`,
		arguments: [
			systemObjectRef,
			tx.moveCall({
				target: `${ikaConfig.packages.ikaSystemPackage}::validator_metadata::new`,
				arguments: [
					tx.pure.string(metadata.imageUrl),
					tx.pure.string(metadata.projectUrl),
					tx.pure.string(metadata.description),
				],
			}),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochNetworkAddress(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	networkAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_network_address`,
		arguments: [systemObjectRef, tx.pure.string(networkAddress), tx.object(validatorOperationCap)],
	});
}

export function setNextEpochP2pAddress(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	p2pAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_p2p_address`,
		arguments: [systemObjectRef, tx.pure.string(p2pAddress), tx.object(validatorOperationCap)],
	});
}

export function setNextEpochConsensusAddress(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	consensusAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_consensus_address`,
		arguments: [
			systemObjectRef,
			tx.pure.string(consensusAddress),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochProtocolPubkeyBytes(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	protocolPubkey: Uint8Array,
	proofOfPossessionBytes: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_protocol_pubkey_bytes`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(protocolPubkey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(proofOfPossessionBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochNetworkPubkeyBytes(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	networkPubkey: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_network_pubkey_bytes`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(networkPubkey)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochConsensusPubkeyBytes(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	consensusPubkeyBytes: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_consensus_pubkey_bytes`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(consensusPubkeyBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochMpcDataBytes(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	mpcData: Uint8Array[],
	validatorOperationCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_mpc_data_bytes`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(mpcData)),
			tx.object(validatorOperationCap),
		],
	});
}

export function activeCommittee(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::active_committee`,
		arguments: [systemObjectRef],
	});
}

export function nextEpochActiveCommittee(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::next_epoch_active_committee`,
		arguments: [systemObjectRef],
	});
}

export function initiateMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	clock: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::initiate_mid_epoch_reconfiguration`,
		arguments: [systemObjectRef, tx.object(clock)],
	});
}

export function createSystemCurrentStatusInfo(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	clock: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::create_system_current_status_info`,
		arguments: [systemObjectRef, tx.object(clock)],
	});
}

export function initiateAdvanceEpoch(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	clock: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::initiate_advance_epoch`,
		arguments: [systemObjectRef, tx.object(clock)],
	});
}

export function advanceEpoch(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	advanceEpochApprover: string,
	clock: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::advance_epoch`,
		arguments: [systemObjectRef, tx.object(advanceEpochApprover), tx.object(clock)],
	});
}

export function verifyValidatorCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_validator_cap`,
		arguments: [systemObjectRef, tx.object(validatorCap)],
	});
}

export function verifyOperationCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorOperationCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_operation_cap`,
		arguments: [systemObjectRef, tx.object(validatorOperationCap)],
	});
}

export function verifyCommissionCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorCommissionCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_commission_cap`,
		arguments: [systemObjectRef, tx.object(validatorCommissionCap)],
	});
}

export function authorizeUpgrade(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	packageId: string,
	tx: Transaction,
): {
	upgradeTicket: TransactionObjectArgument;
	upgradePackageApprover: TransactionObjectArgument;
} {
	const [upgradeTicket, upgradePackageApprover] = tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::authorize_upgrade`,
		arguments: [systemObjectRef, tx.pure.id(packageId)],
	});

	return {
		upgradeTicket,
		upgradePackageApprover,
	};
}

export function commitUpgrade(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	upgradeReceipt: string,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::commit_upgrade`,
		arguments: [systemObjectRef, tx.object(upgradeReceipt), tx.object(upgradePackageApprover)],
	});
}

export function finalizeUpgrade(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::finalize_upgrade`,
		arguments: [systemObjectRef, tx.object(upgradePackageApprover)],
	});
}

export function processCheckpointMessageByQuorum(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	signature: Uint8Array,
	signersBitmap: Uint8Array,
	message: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::process_checkpoint_message_by_quorum`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function addUpgradeCapByCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	upgradeCap: string,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::add_upgrade_cap_by_cap`,
		arguments: [systemObjectRef, tx.object(upgradeCap), tx.object(protocolCap)],
	});
}

export function verifyProtocolCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	protocolCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [systemObjectRef, tx.object(protocolCap)],
	});
}

export function processCheckpointMessageByCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	message: Uint8Array,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::process_checkpoint_message_by_cap`,
		arguments: [
			systemObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(protocolCap),
		],
	});
}

export function setApprovedUpgradeByCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	packageId: string,
	digest: Uint8Array | null,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_approved_upgrade_by_cap`,
		arguments: [
			systemObjectRef,
			tx.pure.id(packageId),
			digest !== null
				? tx.pure(bcs.option(bcs.vector(bcs.u8())).serialize(digest))
				: tx.pure(bcs.option(bcs.vector(bcs.u8())).serialize(null)),
			tx.object(protocolCap),
		],
	});
}

export function setOrRemoveWitnessApprovingAdvanceEpochByCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	witnessType: string,
	remove: boolean,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_or_remove_witness_approving_advance_epoch_by_cap`,
		arguments: [
			systemObjectRef,
			tx.pure.string(witnessType),
			tx.pure.bool(remove),
			tx.object(protocolCap),
		],
	});
}

export function tryMigrateByCap(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::try_migrate_by_cap`,
		arguments: [systemObjectRef, tx.object(protocolCap)],
	});
}

export function tryMigrate(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::try_migrate`,
		arguments: [systemObjectRef],
	});
}

export function calculateRewards(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	validatorId: string,
	stakedPrincipal: number,
	activationEpoch: number,
	withdrawEpoch: number,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::calculate_rewards`,
		arguments: [
			systemObjectRef,
			tx.pure.id(validatorId),
			tx.pure.u64(stakedPrincipal),
			tx.pure.u64(activationEpoch),
			tx.pure.u64(withdrawEpoch),
		],
	});
}

export function canWithdrawStakedIkaEarly(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	stakedIka: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::can_withdraw_staked_ika_early`,
		arguments: [systemObjectRef, tx.object(stakedIka)],
	});
}

export function version(
	ikaConfig: IkaConfig,
	systemObjectRef: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::version`,
		arguments: [systemObjectRef],
	});
}
