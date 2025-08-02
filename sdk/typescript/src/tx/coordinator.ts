import { bcs } from '@mysten/bcs';
import type { Transaction, TransactionArgument } from '@mysten/sui/transactions';

import { IkaConfig } from '../client/types';

export function registerEncryptionKey(
	ikaConfig: IkaConfig,
	encryption: {
		encryptionKey: Uint8Array;
		encryptionKeySignature: Uint8Array;
		encryptionKeyAddress: Uint8Array;
	},
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::register_encryption_key`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.u32(0),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKeySignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryption.encryptionKeyAddress)),
		],
	});
}

export function registerSessionIdentifier(
	ikaConfig: IkaConfig,
	sessionIdentifier: Uint8Array,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::register_session_identifier`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			tx.gas,
		],
	});
}

export function getActiveEncryptionKey(
	ikaConfig: IkaConfig,
	address: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::get_active_encryption_key`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.pure.address(address)],
	});
}

export function approveMessage(
	ikaConfig: IkaConfig,
	dwalletCap: string,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_message`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(dwalletCap),
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function approveImportedKeyMessage(
	ikaConfig: IkaConfig,
	importedKeyDWalletCap: string,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_imported_key_message`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(importedKeyDWalletCap),
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function requestDWalletDKGFirstRound(
	ikaConfig: IkaConfig,
	dwalletNetworkEncryptionKeyID: string,
	curve: number,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg_first_round`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletNetworkEncryptionKeyID),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestDWalletDKGSecondRound(
	ikaConfig: IkaConfig,
	dwalletCap: string,
	centralizedPublicKeyShareAndProof: Uint8Array,
	encryptedCentralizedSecretShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg_second_round`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(dwalletCap),
			tx.pure(bcs.vector(bcs.u8()).serialize(centralizedPublicKeyShareAndProof)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedCentralizedSecretShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function processCheckpointMessageByQuorum(
	ikaConfig: IkaConfig,
	signature: Uint8Array,
	signersBitmap: Uint8Array,
	message: Uint8Array,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_quorum`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function initiateMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	systemCurrentStatusInfo: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::initiate_mid_epoch_reconfiguration`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(systemCurrentStatusInfo)],
	});
}

export function requestNetworkEncryptionKeyMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	dwalletNetworkEncryptionKeyId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_network_encryption_key_mid_epoch_reconfiguration`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.pure.id(dwalletNetworkEncryptionKeyId)],
	});
}

export function advanceEpoch(ikaConfig: IkaConfig, advanceEpochApprover: string, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::advance_epoch`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(advanceEpochApprover)],
	});
}

export function requestDwalletNetworkEncryptionKeyDkgByCap(
	ikaConfig: IkaConfig,
	paramsForNetwork: Uint8Array,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_network_encryption_key_dkg_by_cap`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(paramsForNetwork)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function processCheckpointMessageByCap(
	ikaConfig: IkaConfig,
	message: Uint8Array,
	verifiedProtocolCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_cap`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setGasFeeReimbursementSuiSystemCallValueByCap(
	ikaConfig: IkaConfig,
	gasFeeReimbursementSuiSystemCallValue: number,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::set_gas_fee_reimbursement_sui_system_call_value_by_cap`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.u64(gasFeeReimbursementSuiSystemCallValue),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setPausedCurvesAndSignatureAlgorithms(
	ikaConfig: IkaConfig,
	pausedCurves: number[],
	pausedSignatureAlgorithms: number[],
	pausedHashSchemes: number[],
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::set_paused_curves_and_signature_algorithms`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedCurves)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedSignatureAlgorithms)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedHashSchemes)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function requestLockEpochSessions(
	ikaConfig: IkaConfig,
	systemCurrentStatusInfo: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_lock_epoch_sessions`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(systemCurrentStatusInfo)],
	});
}

export function requestImportedKeyDwalletVerification(
	ikaConfig: IkaConfig,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	centralizedPartyMessage: Uint8Array,
	encryptedCentralizedSecretShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_dwallet_verification`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(centralizedPartyMessage)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedCentralizedSecretShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestMakeDwalletUserSecretKeySharesPublic(
	ikaConfig: IkaConfig,
	dwalletId: string,
	publicUserSecretKeyShares: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_make_dwallet_user_secret_key_shares_public`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletId),
			tx.pure(bcs.vector(bcs.u8()).serialize(publicUserSecretKeyShares)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestReEncryptUserShareFor(
	ikaConfig: IkaConfig,
	dwalletId: string,
	destinationEncryptionKeyAddress: string,
	encryptedCentralizedSecretShareAndProof: Uint8Array,
	sourceEncryptedUserSecretKeyShareId: string,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_re_encrypt_user_share_for`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletId),
			tx.pure.address(destinationEncryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedCentralizedSecretShareAndProof)),
			tx.pure.id(sourceEncryptedUserSecretKeyShareId),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function acceptEncryptedUserShare(
	ikaConfig: IkaConfig,
	dwalletId: string,
	encryptedUserSecretKeyShareId: string,
	userOutputSignature: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::accept_encrypted_user_share`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletId),
			tx.pure.id(encryptedUserSecretKeyShareId),
			tx.pure(bcs.vector(bcs.u8()).serialize(userOutputSignature)),
		],
	});
}

export function requestPresign(
	ikaConfig: IkaConfig,
	dwalletId: string,
	signatureAlgorithm: number,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_presign`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletId),
			tx.pure.u32(signatureAlgorithm),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestGlobalPresign(
	ikaConfig: IkaConfig,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	signatureAlgorithm: number,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_global_presign`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure.u32(signatureAlgorithm),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function isPresignValid(
	ikaConfig: IkaConfig,
	presignCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::is_presign_valid`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(presignCap)],
	});
}

export function verifyPresignCap(
	ikaConfig: IkaConfig,
	unverifiedPresignCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_presign_cap`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(unverifiedPresignCap)],
	});
}

export function requestSign(
	ikaConfig: IkaConfig,
	verifiedPresignCap: string,
	messageApproval: string,
	messageCentralizedSignature: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPresignCap),
			tx.object(messageApproval),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageCentralizedSignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestImportedKeySign(
	ikaConfig: IkaConfig,
	verifiedPresignCap: string,
	importedKeyMessageApproval: string,
	messageCentralizedSignature: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPresignCap),
			tx.object(importedKeyMessageApproval),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageCentralizedSignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestFutureSign(
	ikaConfig: IkaConfig,
	dwalletId: string,
	verifiedPresignCap: string,
	message: Uint8Array,
	hashScheme: number,
	messageCentralizedSignature: Uint8Array,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_future_sign`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.pure.id(dwalletId),
			tx.object(verifiedPresignCap),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageCentralizedSignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function isPartialUserSignatureValid(
	ikaConfig: IkaConfig,
	unverifiedPartialUserSignatureCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::is_partial_user_signature_valid`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(unverifiedPartialUserSignatureCap),
		],
	});
}

export function verifyPartialUserSignatureCap(
	ikaConfig: IkaConfig,
	unverifiedPartialUserSignatureCap: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_partial_user_signature_cap`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(unverifiedPartialUserSignatureCap),
		],
	});
}

export function requestSignWithPartialUserSignature(
	ikaConfig: IkaConfig,
	verifiedPartialUserSignatureCap: string,
	messageApproval: string,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign_with_partial_user_signature`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestImportedKeySignWithPartialUserSignature(
	ikaConfig: IkaConfig,
	verifiedPartialUserSignatureCap: string,
	importedKeyMessageApproval: string,
	sessionIdentifier: Uint8Array,
	ikaCoin: TransactionArgument,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign_with_partial_user_signature`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
			tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier)),
			ikaCoin,
			suiCoin,
		],
	});
}

export function matchPartialUserSignatureWithMessageApproval(
	ikaConfig: IkaConfig,
	verifiedPartialUserSignatureCap: string,
	messageApproval: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_message_approval`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
		],
	});
}

export function matchPartialUserSignatureWithImportedKeyMessageApproval(
	ikaConfig: IkaConfig,
	verifiedPartialUserSignatureCap: string,
	importedKeyMessageApproval: string,
	tx: Transaction,
): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_imported_key_message_approval`,
		arguments: [
			getCoordinatorObjectRef(ikaConfig, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
		],
	});
}

export function currentPricing(ikaConfig: IkaConfig, tx: Transaction): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::current_pricing`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx)],
	});
}

export function subsidizeCoordinatorWithSui(
	ikaConfig: IkaConfig,
	suiCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_sui`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), suiCoin],
	});
}

export function subsidizeCoordinatorWithIka(
	ikaConfig: IkaConfig,
	ikaCoin: TransactionArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_ika`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), ikaCoin],
	});
}

export function commitUpgrade(
	ikaConfig: IkaConfig,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(upgradePackageApprover)],
	});
}

export function tryMigrateByCap(
	ikaConfig: IkaConfig,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate_by_cap`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx), tx.object(verifiedProtocolCap)],
	});
}

export function tryMigrate(ikaConfig: IkaConfig, tx: Transaction) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx)],
	});
}

export function version(ikaConfig: IkaConfig, tx: Transaction): TransactionArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::version`,
		arguments: [getCoordinatorObjectRef(ikaConfig, tx)],
	});
}

function getCoordinatorObjectRef(ikaConfig: IkaConfig, tx: Transaction) {
	return tx.sharedObjectRef({
		objectId: ikaConfig.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});
}
