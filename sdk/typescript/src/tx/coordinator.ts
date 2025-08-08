// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { IkaConfig } from '../client/types.js';

export function registerEncryptionKeyTx(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	curve: number,
	encryptionKey: Uint8Array,
	encryptionKeySignature: Uint8Array,
	encryptionKeyAddress: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::register_encryption_key`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKeySignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKeyAddress)),
		],
	});
}

export function registerSessionIdentifier(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	sessionIdentifier: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::register_session_identifier`,
		arguments: [coordinatorObjectRef, sessionIdentifier],
	});
}

export function getActiveEncryptionKey(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	address: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::get_active_encryption_key`,
		arguments: [coordinatorObjectRef, tx.pure.address(address)],
	});
}

export function approveMessage(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletCap: string,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_message`,
		arguments: [
			coordinatorObjectRef,
			tx.object(dwalletCap),
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function approveImportedKeyMessage(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	importedKeyDWalletCap: string,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_imported_key_message`,
		arguments: [
			coordinatorObjectRef,
			tx.object(importedKeyDWalletCap),
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function requestDWalletDKGFirstRound(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyID: string,
	curve: number,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg_first_round`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletNetworkEncryptionKeyID),
			tx.pure.u32(curve),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestDWalletDKGSecondRound(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletCap: TransactionObjectArgument,
	userPublicKeyShareAndProof: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg_second_round`,
		arguments: [
			coordinatorObjectRef,
			dwalletCap,
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicKeyShareAndProof)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function processCheckpointMessageByQuorum(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	signature: Uint8Array,
	signersBitmap: Uint8Array,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_quorum`,
		arguments: [
			coordinatorObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function initiateMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	systemCurrentStatusInfo: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::initiate_mid_epoch_reconfiguration`,
		arguments: [coordinatorObjectRef, tx.object(systemCurrentStatusInfo)],
	});
}

export function requestNetworkEncryptionKeyMidEpochReconfiguration(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_network_encryption_key_mid_epoch_reconfiguration`,
		arguments: [coordinatorObjectRef, tx.pure.id(dwalletNetworkEncryptionKeyId)],
	});
}

export function advanceEpoch(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	advanceEpochApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::advance_epoch`,
		arguments: [coordinatorObjectRef, tx.object(advanceEpochApprover)],
	});
}

export function requestDwalletNetworkEncryptionKeyDkgByCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	paramsForNetwork: Uint8Array,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_network_encryption_key_dkg_by_cap`,
		arguments: [
			coordinatorObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(paramsForNetwork)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function processCheckpointMessageByCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	message: Uint8Array,
	verifiedProtocolCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_cap`,
		arguments: [
			coordinatorObjectRef,
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setGasFeeReimbursementSuiSystemCallValueByCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	gasFeeReimbursementSuiSystemCallValue: number,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::set_gas_fee_reimbursement_sui_system_call_value_by_cap`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.u64(gasFeeReimbursementSuiSystemCallValue),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setPausedCurvesAndSignatureAlgorithms(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	pausedCurves: number[],
	pausedSignatureAlgorithms: number[],
	pausedHashSchemes: number[],
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::set_paused_curves_and_signature_algorithms`,
		arguments: [
			coordinatorObjectRef,
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedCurves)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedSignatureAlgorithms)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedHashSchemes)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function requestLockEpochSessions(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	systemCurrentStatusInfo: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_lock_epoch_sessions`,
		arguments: [coordinatorObjectRef, tx.object(systemCurrentStatusInfo)],
	});
}

export function requestImportedKeyDwalletVerification(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	userOutgoingMessage: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: string,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_dwallet_verification`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(userOutgoingMessage)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			tx.object(sessionIdentifier),
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestMakeDwalletUserSecretKeySharesPublic(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletId: string,
	publicUserSecretKeyShares: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_make_dwallet_user_secret_key_shares_public`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletId),
			tx.pure(bcs.vector(bcs.u8()).serialize(publicUserSecretKeyShares)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestReEncryptUserShareFor(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletId: string,
	destinationEncryptionKeyAddress: string,
	encryptedUserShareAndProof: Uint8Array,
	sourceEncryptedUserSecretKeyShareId: string,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_re_encrypt_user_share_for`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletId),
			tx.pure.address(destinationEncryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.id(sourceEncryptedUserSecretKeyShareId),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function acceptEncryptedUserShare(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletId: string,
	encryptedUserSecretKeyShareId: string,
	userOutputSignature: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::accept_encrypted_user_share`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletId),
			tx.pure.id(encryptedUserSecretKeyShareId),
			tx.pure(bcs.vector(bcs.u8()).serialize(userOutputSignature)),
		],
	});
}

export function requestPresign(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletId: string,
	signatureAlgorithm: number,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_presign`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletId),
			tx.pure.u32(signatureAlgorithm),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestGlobalPresign(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	signatureAlgorithm: number,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_global_presign`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure.u32(signatureAlgorithm),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function isPresignValid(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	presignCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::is_presign_valid`,
		arguments: [coordinatorObjectRef, tx.object(presignCap)],
	});
}

export function verifyPresignCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	unverifiedPresignCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_presign_cap`,
		arguments: [coordinatorObjectRef, tx.object(unverifiedPresignCap)],
	});
}

export function requestSign(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPresignCap: TransactionObjectArgument,
	messageApproval: TransactionObjectArgument,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign`,
		arguments: [
			coordinatorObjectRef,
			verifiedPresignCap,
			messageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestImportedKeySign(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPresignCap: TransactionObjectArgument,
	importedKeyMessageApproval: TransactionObjectArgument,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign`,
		arguments: [
			coordinatorObjectRef,
			verifiedPresignCap,
			importedKeyMessageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestFutureSign(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	dwalletId: string,
	verifiedPresignCap: TransactionObjectArgument,
	message: Uint8Array,
	hashScheme: number,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_future_sign`,
		arguments: [
			coordinatorObjectRef,
			tx.pure.id(dwalletId),
			verifiedPresignCap,
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function isPartialUserSignatureValid(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	unverifiedPartialUserSignatureCap: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::is_partial_user_signature_valid`,
		arguments: [coordinatorObjectRef, tx.object(unverifiedPartialUserSignatureCap)],
	});
}

export function verifyPartialUserSignatureCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	unverifiedPartialUserSignatureCap: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_partial_user_signature_cap`,
		arguments: [coordinatorObjectRef, tx.object(unverifiedPartialUserSignatureCap)],
	});
}

export function requestSignWithPartialUserSignature(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: TransactionObjectArgument,
	messageApproval: TransactionObjectArgument,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign_with_partial_user_signature`,
		arguments: [
			coordinatorObjectRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function requestImportedKeySignWithPartialUserSignature(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: string,
	importedKeyMessageApproval: string,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign_with_partial_user_signature`,
		arguments: [
			coordinatorObjectRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

export function matchPartialUserSignatureWithMessageApproval(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: string,
	messageApproval: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_message_approval`,
		arguments: [
			coordinatorObjectRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
		],
	});
}

export function matchPartialUserSignatureWithImportedKeyMessageApproval(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: string,
	importedKeyMessageApproval: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_imported_key_message_approval`,
		arguments: [
			coordinatorObjectRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
		],
	});
}

export function currentPricing(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::current_pricing`,
		arguments: [coordinatorObjectRef],
	});
}

export function subsidizeCoordinatorWithSui(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_sui`,
		arguments: [coordinatorObjectRef, suiCoin],
	});
}

export function subsidizeCoordinatorWithIka(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_ika`,
		arguments: [coordinatorObjectRef, ikaCoin],
	});
}

export function commitUpgrade(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	upgradePackageApprover: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
		arguments: [coordinatorObjectRef, tx.object(upgradePackageApprover)],
	});
}

export function tryMigrateByCap(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	verifiedProtocolCap: string,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate_by_cap`,
		arguments: [coordinatorObjectRef, tx.object(verifiedProtocolCap)],
	});
}

export function tryMigrate(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate`,
		arguments: [coordinatorObjectRef],
	});
}

export function version(
	ikaConfig: IkaConfig,
	coordinatorObjectRef: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::version`,
		arguments: [coordinatorObjectRef],
	});
}
