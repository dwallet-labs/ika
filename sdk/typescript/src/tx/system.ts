import { bcs } from '@mysten/bcs';
import type { Transaction, TransactionArgument } from '@mysten/sui/transactions';

import { IkaConfig } from '../client/types';

export function requestAddValidatorCandidate(
	ikaConfig: IkaConfig,
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
	validatorCap: TransactionArgument;
	validatorOperationCap: TransactionArgument;
	validatorCommissionCap: TransactionArgument;
} {
	const [validatorCap, validatorOperationCap, validatorCommissionCap] = tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_validator_candidate`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
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
	validatorCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_remove_validator_candidate`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function requestAddValidator(ikaConfig: IkaConfig, validatorCap: string, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_validator`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function requestRemoveValidator(
	ikaConfig: IkaConfig,
	validatorCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_remove_validator`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function setNextCommission(
	ikaConfig: IkaConfig,
	newCommissionRate: number,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_commission`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.u16(newCommissionRate),
			tx.object(validatorOperationCap),
		],
	});
}

export function requestAddStake(
	ikaConfig: IkaConfig,
	stakeCoin: TransactionArgument,
	validatorId: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_add_stake`,
		arguments: [getSystemObjectRef(ikaConfig, tx), stakeCoin, tx.pure.id(validatorId)],
	});
}

export function requestWithdrawStake(ikaConfig: IkaConfig, stakedIka: string, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::request_withdraw_stake`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(stakedIka)],
	});
}

export function withdrawStake(
	ikaConfig: IkaConfig,
	stakedIka: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::withdraw_stake`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(stakedIka)],
	});
}

export function reportValidator(
	ikaConfig: IkaConfig,
	validatorOperationCap: string,
	reporteeId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::report_validator`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.object(validatorOperationCap),
			tx.pure.id(reporteeId),
		],
	});
}

export function undoReportValidator(
	ikaConfig: IkaConfig,
	validatorOperationCap: string,
	reporteeId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::undo_report_validator`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.object(validatorOperationCap),
			tx.pure.id(reporteeId),
		],
	});
}

export function rotateOperationCap(
	ikaConfig: IkaConfig,
	validatorCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::rotate_operation_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function rotateCommissionCap(
	ikaConfig: IkaConfig,
	validatorCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::rotate_commission_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function collectCommission(
	ikaConfig: IkaConfig,
	validatorCommissionCap: string,
	amount: number | null,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::collect_commission`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.object(validatorCommissionCap),
			amount !== null
				? tx.pure(bcs.option(bcs.u64()).serialize(amount))
				: tx.pure(bcs.option(bcs.u64()).serialize(null)),
		],
	});
}

export function setValidatorName(
	ikaConfig: IkaConfig,
	name: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_validator_name`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.string(name),
			tx.object(validatorOperationCap),
		],
	});
}

export function validatorMetadata(
	ikaConfig: IkaConfig,
	validatorId: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::validator_metadata`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.pure.id(validatorId)],
	});
}

export function setValidatorMetadata(
	ikaConfig: IkaConfig,
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
			getSystemObjectRef(ikaConfig, tx),
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
	networkAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_network_address`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.string(networkAddress),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochP2pAddress(
	ikaConfig: IkaConfig,
	p2pAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_p2p_address`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.string(p2pAddress),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochConsensusAddress(
	ikaConfig: IkaConfig,
	consensusAddress: string,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_consensus_address`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.string(consensusAddress),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochProtocolPubkeyBytes(
	ikaConfig: IkaConfig,
	protocolPubkey: Uint8Array,
	proofOfPossessionBytes: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_protocol_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(protocolPubkey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(proofOfPossessionBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochNetworkPubkeyBytes(
	ikaConfig: IkaConfig,
	networkPubkey: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_network_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(networkPubkey)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochConsensusPubkeyBytes(
	ikaConfig: IkaConfig,
	consensusPubkeyBytes: Uint8Array,
	validatorOperationCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_consensus_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(consensusPubkeyBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochMpcDataBytes(
	ikaConfig: IkaConfig,
	mpcData: Uint8Array[],
	validatorOperationCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_next_epoch_mpc_data_bytes`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(mpcData)),
			tx.object(validatorOperationCap),
		],
	});
}

export function activeCommittee(ikaConfig: IkaConfig, tx: Transaction): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::active_committee`,
		arguments: [getSystemObjectRef(ikaConfig, tx)],
	});
}

export function nextEpochActiveCommittee(
	ikaConfig: IkaConfig,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::next_epoch_active_committee`,
		arguments: [getSystemObjectRef(ikaConfig, tx)],
	});
}

export function initiateMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	clock: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::initiate_mid_epoch_reconfiguration`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(clock)],
	});
}

export function createSystemCurrentStatusInfo(
	ikaConfig: IkaConfig,
	clock: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::create_system_current_status_info`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(clock)],
	});
}

export function initiateAdvanceEpoch(
	ikaConfig: IkaConfig,
	clock: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::initiate_advance_epoch`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(clock)],
	});
}

export function advanceEpoch(
	ikaConfig: IkaConfig,
	advanceEpochApprover: string,
	clock: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::advance_epoch`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.object(advanceEpochApprover),
			tx.object(clock),
		],
	});
}

export function verifyValidatorCap(
	ikaConfig: IkaConfig,
	validatorCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_validator_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCap)],
	});
}

export function verifyOperationCap(
	ikaConfig: IkaConfig,
	validatorOperationCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_operation_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorOperationCap)],
	});
}

export function verifyCommissionCap(
	ikaConfig: IkaConfig,
	validatorCommissionCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_commission_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(validatorCommissionCap)],
	});
}

export function authorizeUpgrade(
	ikaConfig: IkaConfig,
	packageId: string,
	tx: Transaction,
): {
	upgradeTicket: TransactionArgument;
	upgradePackageApprover: TransactionArgument;
} {
	const [upgradeTicket, upgradePackageApprover] = tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::authorize_upgrade`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.pure.id(packageId)],
	});

	return {
		upgradeTicket,
		upgradePackageApprover,
	};
}

export function commitUpgrade(
	ikaConfig: IkaConfig,
	upgradeReceipt: string,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::commit_upgrade`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.object(upgradeReceipt),
			tx.object(upgradePackageApprover),
		],
	});
}

export function finalizeUpgrade(
	ikaConfig: IkaConfig,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::finalize_upgrade`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(upgradePackageApprover)],
	});
}

export function processCheckpointMessageByQuorum(
	ikaConfig: IkaConfig,
	signature: Uint8Array,
	signersBitmap: Uint8Array,
	message: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::process_checkpoint_message_by_quorum`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function addUpgradeCapByCap(
	ikaConfig: IkaConfig,
	upgradeCap: string,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::add_upgrade_cap_by_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(upgradeCap), tx.object(protocolCap)],
	});
}

export function verifyProtocolCap(
	ikaConfig: IkaConfig,
	protocolCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(protocolCap)],
	});
}

export function processCheckpointMessageByCap(
	ikaConfig: IkaConfig,
	message: Uint8Array,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::process_checkpoint_message_by_cap`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(protocolCap),
		],
	});
}

export function setApprovedUpgradeByCap(
	ikaConfig: IkaConfig,
	packageId: string,
	digest: Uint8Array | null,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_approved_upgrade_by_cap`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
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
	witnessType: string,
	remove: boolean,
	protocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::set_or_remove_witness_approving_advance_epoch_by_cap`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.string(witnessType),
			tx.pure.bool(remove),
			tx.object(protocolCap),
		],
	});
}

export function tryMigrateByCap(ikaConfig: IkaConfig, protocolCap: string, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::try_migrate_by_cap`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(protocolCap)],
	});
}

export function tryMigrate(ikaConfig: IkaConfig, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::try_migrate`,
		arguments: [getSystemObjectRef(ikaConfig, tx)],
	});
}

export function calculateRewards(
	ikaConfig: IkaConfig,
	validatorId: string,
	stakedPrincipal: number,
	activationEpoch: number,
	withdrawEpoch: number,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::calculate_rewards`,
		arguments: [
			getSystemObjectRef(ikaConfig, tx),
			tx.pure.id(validatorId),
			tx.pure.u64(stakedPrincipal),
			tx.pure.u64(activationEpoch),
			tx.pure.u64(withdrawEpoch),
		],
	});
}

export function canWithdrawStakedIkaEarly(
	ikaConfig: IkaConfig,
	stakedIka: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::can_withdraw_staked_ika_early`,
		arguments: [getSystemObjectRef(ikaConfig, tx), tx.object(stakedIka)],
	});
}

export function version(ikaConfig: IkaConfig, tx: Transaction): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaSystemPackage}::system::version`,
		arguments: [getSystemObjectRef(ikaConfig, tx)],
	});
}

function getSystemObjectRef(ikaConfig: IkaConfig, tx: Transaction) {
	return tx.sharedObjectRef({
		objectId: ikaConfig.objects.ikaSystemObject.objectID,
		initialSharedVersion: ikaConfig.objects.ikaSystemObject.initialSharedVersion,
		mutable: true,
	});
}
