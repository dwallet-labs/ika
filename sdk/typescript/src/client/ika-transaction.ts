import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator';
import { PreparedSecondRound } from './cryptography';
import { IkaClient } from './ika-client';
import { DWallet } from './types';
import { UserShareEncrytionKeys } from './user-share-encryption-keys';
import { stringToUint8Array } from './utils';

export type IkaTransactionParams = {
	ikaClient: IkaClient;
	transaction: Transaction;
	userShareEncryptionKeys?: UserShareEncrytionKeys;
};

export class IkaTransaction {
	private ikaClient: IkaClient;
	private transaction: Transaction;
	private userShareEncryptionKeys?: UserShareEncrytionKeys;

	constructor({ ikaClient, transaction, userShareEncryptionKeys }: IkaTransactionParams) {
		this.ikaClient = ikaClient;
		this.transaction = transaction;
		this.userShareEncryptionKeys = userShareEncryptionKeys;
	}

	/**
	 * Request the DKG first round. Fetches the decryption key ID from the IKA client.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @returns DWalletCap
	 */
	async requestDWalletDKGFirstRoundAsync({
		curve,
		ikaCoin,
		suiCoin,
	}: {
		curve: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const dwalletCap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return {
			dwalletCap,
			transaction: this,
		};
	}

	/**
	 * Request the DKG first round.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @returns DWalletCap
	 */
	requestDWalletDKGFirstRound({
		curve,
		decryptionKeyID,
		ikaCoin,
		suiCoin,
	}: {
		curve: number;
		decryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): {
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const dwalletCap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			decryptionKeyID,
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return {
			dwalletCap,
			transaction: this,
		};
	}

	/**
	 * Request the DKG first round and keep the DWalletCap. Fetches the decryption key ID from the IKA client.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @param params.receiver - The receiver of the DWalletCap.
	 */
	async requestDWalletDKGFirstRoundAndKeepAsync({
		curve,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const cap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		this.transaction.transferObjects([cap], receiver);

		return this;
	}

	/**
	 * Request the DKG first round and keep the DWalletCap.
	 * @param params - The parameters for the DKG first round.
	 * @param params.curve - The curve to use for the DKG first round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG first round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG first round.
	 * @param params.receiver - The receiver of the DWalletCap.
	 */
	requestDWalletDKGFirstRoundAndKeep({
		curve,
		decryptionKeyID,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: number;
		decryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const cap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			decryptionKeyID,
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		this.transaction.transferObjects([cap], receiver);

		return this;
	}

	/**
	 * Request the DKG second round.
	 * @param params - The parameters for the DKG second round.
	 * @param params.dWallet - The DWallet to use for the DKG second round.
	 * @param params.preparedSecondRound - The prepared second round to use for the DKG second round.
	 * @param params.signerPublicKey - The signer public key to use for the DKG second round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG second round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG second round.
	 */
	requestDWalletDKGSecondRound({
		dWallet,
		preparedSecondRound,
		signerPublicKey,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		preparedSecondRound: PreparedSecondRound;
		signerPublicKey: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.requestDWalletDKGSecondRound(
			this.ikaClient.ikaConfig,
			this.transaction.object(dWallet.dwallet_cap_id),
			preparedSecondRound.centralizedPublicKeyShareAndProof,
			preparedSecondRound.encryptedUserShareAndProof,
			this.userShareEncryptionKeys.getPublicKey().toSuiAddress(),
			preparedSecondRound.centralizedPublicOutput,
			signerPublicKey,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return this;
	}

	/**
	 * Accept the encrypted user share.
	 * @param params - The parameters for the accept encrypted user share.
	 * @param params.dwalletId - The ID of the DWallet to accept the encrypted user share for.
	 * @param params.encryptedUserSecretKeyShareId - The ID of the encrypted user secret key share to accept.
	 * @param params.userOutputSignature - The user output signature to use for the accept encrypted user share.
	 */
	async acceptEncryptedUserShare({
		dWallet,
		encryptedUserSecretKeyShareId,
	}: {
		dWallet: DWallet;
		encryptedUserSecretKeyShareId: string;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.acceptEncryptedUserShare(
			this.ikaClient.ikaConfig,
			dWallet.id.id,
			encryptedUserSecretKeyShareId,
			await this.userShareEncryptionKeys.getUserOutputSignature(dWallet),
			this.transaction,
		);

		return this;
	}

	async registerEncryptionKey({ curve }: { curve: number }) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.registerEncryptionKey(
			this.ikaClient.ikaConfig,
			curve,
			this.userShareEncryptionKeys.encryptionKey,
			await this.userShareEncryptionKeys.getEncryptionKeySignature(),
			stringToUint8Array(this.userShareEncryptionKeys.getPublicKey().toSuiAddress()),
			this.transaction,
		);

		return this;
	}

	/**
	 * Make the DWallet user secret key shares public.
	 * @param params - The parameters for the make DWallet user secret key shares public.
	 * @param params.dWallet - The DWallet to make the user secret key shares public for.
	 * @param params.secretShare - The secret share to make public.
	 * @param params.ikaCoin - The IKA coin to use for payment of the make DWallet user secret key shares public.
	 * @param params.suiCoin - The SUI coin to use for payment of the make DWallet user secret key shares public.
	 */
	makeDWalletUserSecretKeySharesPublic({
		dWallet,
		secretShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		secretShare: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		coordinatorTx.requestMakeDwalletUserSecretKeySharesPublic(
			this.ikaClient.ikaConfig,
			dWallet.id.id,
			secretShare,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return this;
	}

	/**
	 * Request a presign.
	 * @param params - The parameters for the request presign.
	 * @param params.dWallet - The DWallet to request the presign for.
	 * @param params.signatureAlgorithm - The signature algorithm to use for the presign.
	 * @param params.ikaCoin - The IKA coin to use for payment of the presign.
	 * @param params.suiCoin - The SUI coin to use for payment of the presign.
	 */
	presign({
		dWallet,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): {
		unverifiedPresignCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const unverifiedPresignCap = coordinatorTx.requestPresign(
			this.ikaClient.ikaConfig,
			dWallet.id.id,
			signatureAlgorithm,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return {
			unverifiedPresignCap,
			transaction: this,
		};
	}

	/**
	 * Request a presign and keep the unverified presign cap.
	 * @param params - The parameters for the request presign and keep.
	 * @param params.dWallet - The DWallet to request the presign for.
	 * @param params.signatureAlgorithm - The signature algorithm to use for the presign.
	 * @param params.ikaCoin - The IKA coin to use for payment of the presign.
	 * @param params.suiCoin - The SUI coin to use for payment of the presign.
	 * @param params.receiver - The receiver of the unverified presign cap.
	 */
	presignAndKeep({
		dWallet,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const unverifiedPresignCap = coordinatorTx.requestPresign(
			this.ikaClient.ikaConfig,
			dWallet.id.id,
			signatureAlgorithm,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		this.transaction.transferObjects([unverifiedPresignCap], receiver);

		return this;
	}

	private createSessionIdentifier() {
		const freshObjectAddress = this.transaction.moveCall({
			target: `0x2::tx_context::fresh_object_address`,
			arguments: [],
			typeArguments: [],
		});

		const freshObjectAddressBytes = this.transaction.moveCall({
			target: `0x2::address::to_bytes`,
			arguments: [freshObjectAddress],
			typeArguments: [],
		});

		return coordinatorTx.registerSessionIdentifier(
			this.ikaClient.ikaConfig,
			freshObjectAddressBytes,
			this.transaction,
		);
	}
}
