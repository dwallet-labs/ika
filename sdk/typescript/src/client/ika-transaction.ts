import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator';
import { IkaClient } from './ika-client';

export type IkaTransactionParams = {
	ikaClient: IkaClient;
	transaction: Transaction;
};

export class IkaTransaction {
	private ikaClient: IkaClient;
	private transaction: Transaction;

	constructor({ ikaClient, transaction }: IkaTransactionParams) {
		this.ikaClient = ikaClient;
		this.transaction = transaction;
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
	 * @param params.dwalletCap - The DWalletCap to use for the DKG second round.
	 * @param params.centralizedPublicKeyShareAndProof - The centralized public key share and proof to use for the DKG second round.
	 * @param params.encryptedUserShareAndProof - The encrypted user share and proof to use for the DKG second round.
	 * @param params.encryptionKeyAddress - The address of the encryption key to use for the DKG second round.
	 * @param params.userPublicOutput - The user public output to use for the DKG second round.
	 * @param params.signerPublicKey - The signer public key to use for the DKG second round.
	 * @param params.ikaCoin - The IKA coin to use for payment of the DKG second round.
	 * @param params.suiCoin - The SUI coin to use for payment of the DKG second round.
	 */
	requestDWalletDKGSecondRound({
		dwalletCap,
		centralizedPublicKeyShareAndProof,
		encryptedUserShareAndProof,
		encryptionKeyAddress,
		userPublicOutput,
		signerPublicKey,
		ikaCoin,
		suiCoin,
	}: {
		dwalletCap: string | TransactionObjectArgument;
		centralizedPublicKeyShareAndProof: Uint8Array;
		encryptedUserShareAndProof: Uint8Array;
		centralizedPublicOutput: Uint8Array;
		encryptionKeyAddress: string;
		userPublicOutput: Uint8Array;
		signerPublicKey: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		coordinatorTx.requestDWalletDKGSecondRound(
			this.ikaClient.ikaConfig,
			this.transaction.object(dwalletCap),
			centralizedPublicKeyShareAndProof,
			encryptedUserShareAndProof,
			encryptionKeyAddress,
			userPublicOutput,
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
	acceptEncryptedUserShare({
		dwalletId,
		encryptedUserSecretKeyShareId,
		userOutputSignature,
	}: {
		dwalletId: string;
		encryptedUserSecretKeyShareId: string;
		userOutputSignature: Uint8Array;
	}) {
		coordinatorTx.acceptEncryptedUserShare(
			this.ikaClient.ikaConfig,
			dwalletId,
			encryptedUserSecretKeyShareId,
			userOutputSignature,
			this.transaction,
		);

		return this;
	}

	registerEncryptionKey({
		curve,
		encryptionKey,
		encryptionKeySignature,
		encryptionKeyAddress,
	}: {
		curve: number;
		encryptionKey: Uint8Array;
		encryptionKeySignature: Uint8Array;
		encryptionKeyAddress: Uint8Array;
	}) {
		coordinatorTx.registerEncryptionKey(
			this.ikaClient.ikaConfig,
			curve,
			encryptionKey,
			encryptionKeySignature,
			encryptionKeyAddress,
			this.transaction,
		);

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
