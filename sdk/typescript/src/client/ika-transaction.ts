// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator.js';
import type {
	DKGSecondRoundRequestInput,
	ImportDWalletVerificationRequestInput,
} from './cryptography.js';
import {
	createRandomSessionIdentifier,
	createUserSignMessage,
	encryptSecretShare,
	verifyUserShare,
} from './cryptography.js';
import type { IkaClient } from './ika-client.js';
import type {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	Hash,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
} from './types.js';
import type { UserShareEncrytionKeys } from './user-share-encryption-keys.js';

/**
 * Parameters for creating an IkaTransaction instance
 */
export interface IkaTransactionParams {
	/** The IkaClient instance to use for blockchain interactions */
	ikaClient: IkaClient;
	/** The Sui transaction to wrap */
	transaction: Transaction;
	/** Optional user share encryption keys for cryptographic operations */
	userShareEncryptionKeys?: UserShareEncrytionKeys;
}

/**
 * IkaTransaction class provides a high-level interface for interacting with the Ika network.
 * It wraps Sui transactions and provides methods for DWallet operations including DKG,
 * presigning, signing, and key management.
 */
export class IkaTransaction {
	/** The IkaClient instance for blockchain interactions */
	private ikaClient: IkaClient;
	/** The underlying Sui transaction */
	private transaction: Transaction;
	/** Optional user share encryption keys for cryptographic operations */
	private userShareEncryptionKeys?: UserShareEncrytionKeys;
	/** The shared object ref for the coordinator */
	private coordinatorObjectRef?: TransactionObjectArgument;
	/** The shared object ref for the system */
	private systemObjectRef?: TransactionObjectArgument;

	/**
	 * Creates a new IkaTransaction instance
	 * @param params - Configuration parameters for the transaction
	 */
	constructor({ ikaClient, transaction, userShareEncryptionKeys }: IkaTransactionParams) {
		this.ikaClient = ikaClient;
		this.transaction = transaction;
		this.userShareEncryptionKeys = userShareEncryptionKeys;
	}

	/**
	 * Request the DKG (Distributed Key Generation) first round with automatic decryption key ID fetching.
	 * This initiates the creation of a new DWallet through a distributed key generation process.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to an object containing the DWallet capability and updated transaction
	 * @throws {Error} If the decryption key ID cannot be fetched
	 */
	async requestDWalletDKGFirstRoundAsync({
		curve,
		ikaCoin,
		suiCoin,
	}: {
		curve: Curve;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const dwalletCap = this._requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID: await this.ikaClient.getNetworkEncryptionKeyID(),
			ikaCoin,
			suiCoin,
		});

		return {
			dwalletCap,
			transaction: this,
		};
	}

	/**
	 * Request the DKG (Distributed Key Generation) first round with explicit decryption key ID.
	 * This initiates the creation of a new DWallet through a distributed key generation process.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.networkEncryptionKeyID - The specific network encryption key ID to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Object containing the DWallet capability and updated transaction
	 */
	requestDWalletDKGFirstRound({
		curve,
		networkEncryptionKeyID,
		ikaCoin,
		suiCoin,
	}: {
		curve: Curve;
		networkEncryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): {
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const dwalletCap = this._requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID,
			ikaCoin,
			suiCoin,
		});

		return {
			dwalletCap,
			transaction: this,
		};
	}

	/**
	 * Request the DKG first round and transfer the DWalletCap to a specified receiver.
	 * This method fetches the decryption key ID automatically from the IKA client.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the DWalletCap
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If the decryption key ID cannot be fetched
	 */
	async requestDWalletDKGFirstRoundAndTransferCapAsync({
		curve,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: Curve;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const cap = this._requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID: await this.ikaClient.getNetworkEncryptionKeyID(),
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([cap], receiver);

		return this;
	}

	/**
	 * Request the DKG first round and transfer the DWalletCap to a specified receiver.
	 * This method requires an explicit decryption key ID.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.networkEncryptionKeyID - The specific network encryption key ID to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the DWalletCap
	 * @returns The updated IkaTransaction instance
	 */
	requestDWalletDKGFirstRoundAndTransferCap({
		curve,
		networkEncryptionKeyID,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: Curve;
		networkEncryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const cap = this._requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID,
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([cap], receiver);

		return this;
	}

	/**
	 * Request the DKG (Distributed Key Generation) second round to complete DWallet creation.
	 * This finalizes the distributed key generation process started in the first round.
	 *
	 * @param params - The parameters for the DKG second round
	 * @param params.dWallet - The DWallet object from the first round
	 * @param params.dkgSecondRoundRequestInput - Cryptographic data prepared for the second round
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	requestDWalletDKGSecondRound({
		dWallet,
		dkgSecondRoundRequestInput,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		dkgSecondRoundRequestInput: DKGSecondRoundRequestInput;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.requestDWalletDKGSecondRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			this.transaction.object(dWallet.dwallet_cap_id),
			dkgSecondRoundRequestInput.userDKGMessage,
			dkgSecondRoundRequestInput.encryptedUserShareAndProof,
			this.userShareEncryptionKeys.getSuiAddress(),
			dkgSecondRoundRequestInput.userPublicOutput,
			this.userShareEncryptionKeys.getSigningPublicKeyBytes(),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return this;
	}

	/**
	 * Accept an encrypted user share for a DWallet.
	 * This completes the user's participation in the DKG process by accepting their encrypted share.
	 *
	 * @param params - The parameters for accepting the encrypted user share
	 * @param params.dWallet - The DWallet object to accept the share for
	 * @param params.encryptedUserSecretKeyShareId - The ID of the encrypted user secret key share
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
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
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			encryptedUserSecretKeyShareId,
			await this.userShareEncryptionKeys.getUserOutputSignature(dWallet),
			this.transaction,
		);

		return this;
	}

	/**
	 * Register an encryption key for the current user on the specified curve.
	 * This allows the user to participate in encrypted operations on the network.
	 *
	 * @param params - The parameters for registering the encryption key
	 * @param params.curve - The elliptic curve identifier to register the key for
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async registerEncryptionKey({ curve }: { curve: Curve }) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.registerEncryptionKeyTx(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			curve,
			this.userShareEncryptionKeys.encryptionKey,
			await this.userShareEncryptionKeys.getEncryptionKeySignature(),
			this.userShareEncryptionKeys.getSigningPublicKeyBytes(),
			this.transaction,
		);

		return this;
	}

	/**
	 * Make the DWallet user secret key shares public, allowing them to be used without decryption.
	 * This is useful for scenarios where the secret share can be publicly accessible.
	 *
	 * @param params - The parameters for making the secret key shares public
	 * @param params.dWallet - The DWallet to make the shares public for
	 * @param params.secretShare - The secret share data to make public
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The updated IkaTransaction instance
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
			this.getCoordinatorObjectRef(),
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
	 * Request a presign operation for a DWallet.
	 * Presigning allows for faster signature generation by pre-computing part of the signature.
	 *
	 * @param params - The parameters for requesting the presign
	 * @param params.dWallet - The DWallet to create the presign for
	 * @param params.signatureAlgorithm - The signature algorithm identifier to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Object containing the unverified presign capability and updated transaction
	 */
	requestPresign({
		dWallet,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): {
		unverifiedPresignCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const unverifiedPresignCap = this._requestPresign({
			dWallet,
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});

		return {
			unverifiedPresignCap,
			transaction: this,
		};
	}

	/**
	 * Request a presign operation and transfer the capability to a specified receiver.
	 * This allows delegation of the presign capability to another address.
	 *
	 * @param params - The parameters for requesting the presign
	 * @param params.dWallet - The DWallet to create the presign for
	 * @param params.signatureAlgorithm - The signature algorithm identifier to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the unverified presign capability
	 * @returns The updated IkaTransaction instance
	 */
	requestPresignAndTransferCap({
		dWallet,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const unverifiedPresignCap = this._requestPresign({
			dWallet,
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([unverifiedPresignCap], receiver);

		return this;
	}

	/**
	 * Approve a message for signing with a DWallet.
	 * This creates an approval object that can be used in subsequent signing operations.
	 *
	 * @param params - The parameters for message approval
	 * @param params.dWallet - The DWallet to approve the message for
	 * @param params.signatureAlgorithm - The signature algorithm to use
	 * @param params.hashScheme - The hash scheme to apply to the message
	 * @param params.message - The message bytes to approve for signing
	 * @returns Object containing the message approval and updated transaction
	 */
	approveMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: SignatureAlgorithm;
		hashScheme: Hash;
		message: Uint8Array;
	}): {
		messageApproval: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const messageApproval = coordinatorTx.approveMessage(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
			this.transaction,
		);

		return {
			messageApproval,
			transaction: this,
		};
	}

	/**
	 * Verify a presign capability to ensure it can be used for signing.
	 * This converts an unverified presign capability into a verified one.
	 *
	 * @param params - The parameters for presign verification
	 * @param params.presign - The presign object to verify
	 * @returns Object containing the verified presign capability and updated transaction
	 */
	verifyPresignCap({ presign }: { presign: Presign }): {
		verifiedPresignCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const verifiedPresignCap = coordinatorTx.verifyPresignCap(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			presign.cap_id,
			this.transaction,
		);

		return {
			verifiedPresignCap,
			transaction: this,
		};
	}

	/**
	 * Approve a message for signing with an imported key DWallet.
	 * This is similar to approveMessage but specifically for DWallets created with imported keys.
	 *
	 * @param params - The parameters for imported key message approval
	 * @param params.dWallet - The imported key DWallet to approve the message for
	 * @param params.signatureAlgorithm - The signature algorithm to use
	 * @param params.hashScheme - The hash scheme to apply to the message
	 * @param params.message - The message bytes to approve for signing
	 * @returns Object containing the imported key message approval and updated transaction
	 */
	approveImportedKeyMessage({
		dWallet,
		signatureAlgorithm,
		hashScheme,
		message,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: SignatureAlgorithm;
		hashScheme: Hash;
		message: Uint8Array;
	}): {
		importedKeyMessageApproval: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const importedKeyMessageApproval = coordinatorTx.approveImportedKeyMessage(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
			this.transaction,
		);

		return {
			importedKeyMessageApproval,
			transaction: this,
		};
	}

	/**
	 * Sign a message using a DWallet with encrypted user shares.
	 * This performs the actual signing operation using the presign and user's encrypted share.
	 *
	 * @param params - The parameters for signing
	 * @param params.dWallet - The DWallet to sign with
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.message - The message bytes to sign
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async sign({
		dWallet,
		messageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		message,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		messageApproval: TransactionObjectArgument;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this._requestSign({
			verifiedPresignCap,
			messageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				encryptedUserSecretKeyShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Sign a message using a DWallet with a secret share.
	 * This performs the actual signing operation using the presign and user's secret share.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for signing
	 * @param params.dWallet - The DWallet to sign with
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The secret share to use for signing
	 * @param params.message - The message bytes to sign
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If presign is not completed or user share is not public
	 */
	async signWithSecretShare({
		dWallet,
		messageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		secretShare,
		message,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		messageApproval: TransactionObjectArgument;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		secretShare: Uint8Array;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this._requestSign({
			verifiedPresignCap,
			messageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Sign a message using a DWallet with public user shares.
	 * This method is used when the user's secret key share has been made public.
	 *
	 * @param params - The parameters for public signing
	 * @param params.dWallet - The DWallet to sign with (must have public shares)
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.presign - The completed presign object
	 * @param params.message - The message bytes to sign
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If presign is not completed or user share is not public
	 */
	async signPublic({
		dWallet,
		verifiedPresignCap,
		messageApproval,
		hashScheme,
		presign,
		message,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		verifiedPresignCap: TransactionObjectArgument;
		messageApproval: TransactionObjectArgument;
		hashScheme: Hash;
		presign: Presign;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		this.assertDWalletPublicUserSecretKeyShareSet(dWallet);

		await this._requestSign({
			verifiedPresignCap,
			messageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Request a future sign operation, which creates a partial user signature that can be used later.
	 * This allows for pre-signing messages that can be completed later without revealing the full signature.
	 *
	 * @param params - The parameters for requesting future sign
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to an object containing the unverified partial signature capability and updated transaction
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async requestFutureSign({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		unverifiedPartialUserSignatureCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const unverifiedPartialUserSignatureCap = await this._requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				encryptedUserSecretKeyShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return {
			unverifiedPartialUserSignatureCap,
			transaction: this,
		};
	}

	/**
	 * Request a future sign operation, which creates a partial user signature that can be used later.
	 * This allows for pre-signing messages that can be completed later without revealing the full signature.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for requesting future sign
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to an object containing the unverified partial signature capability and updated transaction
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async requestFutureSignWithSecretShare({
		dWallet,
		verifiedPresignCap,
		presign,
		secretShare,
		message,
		hashScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		secretShare: Uint8Array;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		unverifiedPartialUserSignatureCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const unverifiedPartialUserSignatureCap = await this._requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return {
			unverifiedPartialUserSignatureCap,
			transaction: this,
		};
	}

	/**
	 * Request a future sign operation and transfer the capability to a specified receiver.
	 * This creates a partial user signature capability that can be delegated to another address.
	 *
	 * @param params - The parameters for requesting future sign and keep
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.receiver - The address that will receive the partial signature capability
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async requestFutureSignAndTransferCap({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		receiver,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		message: Uint8Array;
		hashScheme: Hash;
		receiver: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const unverifiedPartialUserSignatureCap = await this._requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				encryptedUserSecretKeyShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([unverifiedPartialUserSignatureCap], receiver);

		return this;
	}

	/**
	 * Request a future sign operation and transfer the capability to a specified receiver.
	 * This creates a partial user signature capability that can be delegated to another address.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for requesting future sign and keep
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.receiver - The address that will receive the partial signature capability
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async requestFutureSignAndTransferCapWithSecretShare({
		dWallet,
		verifiedPresignCap,
		presign,
		secretShare,
		message,
		hashScheme,
		receiver,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		secretShare: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		receiver: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const unverifiedPartialUserSignatureCap = await this._requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([unverifiedPartialUserSignatureCap], receiver);

		return this;
	}

	/**
	 * Complete a future sign operation using a previously created partial user signature.
	 * This method takes a partial signature created earlier and combines it with message approval to create a full signature.
	 *
	 * @param params - The parameters for completing the future sign
	 * @param params.partialUserSignature - The partial user signature created by requestFutureSign
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The updated IkaTransaction instance
	 */
	futureSign({
		partialUserSignature,
		messageApproval,
		ikaCoin,
		suiCoin,
	}: {
		partialUserSignature: PartialUserSignature;
		messageApproval: TransactionObjectArgument;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		coordinatorTx.requestSignWithPartialUserSignature(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			coordinatorTx.verifyPartialUserSignatureCap(
				this.ikaClient.ikaConfig,
				this.getCoordinatorObjectRef(),
				this.transaction.object(partialUserSignature.cap_id),
				this.transaction,
			),
			messageApproval,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return this;
	}

	/**
	 * Request verification for an imported DWallet key.
	 * This method creates a DWallet from an existing cryptographic key that was generated outside the network.
	 *
	 * @param params - The parameters for imported DWallet verification
	 * @param params.importDWalletVerificationRequestInput - The prepared verification data from prepareImportDWalletVerification
	 * @param params.curve - The elliptic curve identifier used for the imported key
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.sessionIdentifier - Unique session identifier for this operation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to an object containing the imported key DWallet capability and updated transaction
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestImportedDWalletVerification({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
	}: {
		importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
		curve: Curve;
		signerPublicKey: Uint8Array;
		sessionIdentifier: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		ImportedKeyDWalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const importedKeyDWalletVerificationCap = await this._requestImportedKeyDwalletVerification({
			importDWalletVerificationRequestInput,
			curve,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		});

		return {
			ImportedKeyDWalletCap: importedKeyDWalletVerificationCap,
			transaction: this,
		};
	}

	/**
	 * Request verification for an imported DWallet key and transfer the capability to a specified receiver.
	 * This creates an imported DWallet and delegates the capability to another address.
	 *
	 * @param params - The parameters for imported DWallet verification and keep
	 * @param params.importDWalletVerificationRequestInput - The prepared verification data from prepareImportDWalletVerification
	 * @param params.curve - The elliptic curve identifier used for the imported key
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.sessionIdentifier - Unique session identifier for this operation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the imported key DWallet capability
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestImportedDWalletVerificationAndTransferCap({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
		curve: Curve;
		signerPublicKey: Uint8Array;
		sessionIdentifier: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const importedKeyDWalletVerificationCap = await this._requestImportedKeyDwalletVerification({
			importDWalletVerificationRequestInput,
			curve,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		});

		this.transaction.transferObjects([importedKeyDWalletVerificationCap], receiver);

		return this;
	}

	/**
	 * Sign a message using a DWallet created from an imported key with encrypted user shares.
	 * This method is specifically for DWallets that were created from imported keys rather than generated through DKG.
	 *
	 * @param params - The parameters for signing with imported DWallet
	 * @param params.dWallet - The imported key DWallet to sign with
	 * @param params.importedKeyMessageApproval - The message approval from approveImportedKeyMessage
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.message - The message bytes to sign
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async signWithImportedDWallet({
		dWallet,
		importedKeyMessageApproval,
		verifiedPresignCap,
		presign,
		hashScheme,
		message,
		encryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		importedKeyMessageApproval: TransactionObjectArgument;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		hashScheme: Hash;
		message: Uint8Array;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this._requestImportedKeySign({
			verifiedPresignCap,
			importedKeyMessageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				encryptedUserSecretKeyShare,
				presign,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Sign a message using a DWallet created from an imported key with encrypted user shares.
	 * This method is specifically for DWallets that were created from imported keys rather than generated through DKG.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for signing with imported DWallet
	 * @param params.dWallet - The imported key DWallet to sign with
	 * @param params.importedKeyMessageApproval - The message approval from approveImportedKeyMessage
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.message - The message bytes to sign
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set or presign is not completed
	 */
	async signWithImportedDWalletWithSecretShare({
		dWallet,
		importedKeyMessageApproval,
		verifiedPresignCap,
		presign,
		hashScheme,
		message,
		secretShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		importedKeyMessageApproval: TransactionObjectArgument;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		hashScheme: Hash;
		message: Uint8Array;
		secretShare: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this._requestImportedKeySign({
			verifiedPresignCap,
			importedKeyMessageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				secretShare,
				presign,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Sign a message using a DWallet created from an imported key with public user shares.
	 * This method is used when the imported DWallet's user secret key share has been made public.
	 *
	 * @param params - The parameters for signing with imported DWallet using public shares
	 * @param params.dWallet - The imported key DWallet to sign with (must have public shares)
	 * @param params.importedKeyMessageApproval - The message approval from approveImportedKeyMessage
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.message - The message bytes to sign
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set, presign is not completed, or DWallet public user secret key share is not set
	 */
	async signWithImportedDWalletPublic({
		dWallet,
		importedKeyMessageApproval,
		verifiedPresignCap,
		presign,
		hashScheme,
		message,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		importedKeyMessageApproval: TransactionObjectArgument;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		hashScheme: Hash;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		this.assertDWalletPublicUserSecretKeyShareSet(dWallet);

		await this._requestImportedKeySign({
			verifiedPresignCap,
			importedKeyMessageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
				presign,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Transfer an encrypted user share from the current user to another address.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 *
	 * @param params - The parameters for transferring encrypted user share
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationEncryptionKeyAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async transferUserShare({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		destinationEncryptionKeyAddress: string;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		await this._requestReEncryptUserShareFor({
			dWallet,
			destinationEncryptionKeyAddress,
			sourceEncryptedUserSecretKeyShare,
			sourceSecretShare: await this.userShareEncryptionKeys.decryptUserShare(
				dWallet,
				sourceEncryptedUserSecretKeyShare,
				await this.ikaClient.getProtocolPublicParameters(),
			),
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Transfer an encrypted user share from the current user to another address.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for transferring encrypted user share
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationEncryptionKeyAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceSecretShare - The current user's unencrypted secret share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async transferUserShareWithSecretShare({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceSecretShare,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		destinationEncryptionKeyAddress: string;
		sourceSecretShare: Uint8Array;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this._requestReEncryptUserShareFor({
			dWallet,
			destinationEncryptionKeyAddress,
			sourceEncryptedUserSecretKeyShare,
			sourceSecretShare,
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Create a unique session identifier for the current transaction.
	 * This generates a fresh address and converts it to bytes for use as a session identifier.
	 *
	 * @returns The session identifier transaction object argument
	 */
	createSessionIdentifier() {
		return coordinatorTx.registerSessionIdentifier(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			createRandomSessionIdentifier(),
			this.transaction,
		);
	}

	private getCoordinatorObjectRef() {
		if (!this.coordinatorObjectRef) {
			this.coordinatorObjectRef = this.transaction.sharedObjectRef({
				objectId: this.ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion:
					this.ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			});
		}

		return this.coordinatorObjectRef;
	}

	// @ts-expect-error - TODO: Add system functions
	private getSystemObjectRef() {
		if (!this.systemObjectRef) {
			this.systemObjectRef = this.transaction.sharedObjectRef({
				objectId: this.ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
				initialSharedVersion: this.ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
				mutable: true,
			});
		}

		return this.systemObjectRef;
	}

	private assertDWalletPublicOutputSet(
		dWallet: DWallet,
	): asserts dWallet is DWallet & { state: { Active: { public_output: Uint8Array } } } {
		if (!dWallet.state.Active?.public_output) {
			throw new Error('DWallet public output is not set');
		}
	}

	private assertDWalletPublicUserSecretKeyShareSet(
		dWallet: DWallet,
	): asserts dWallet is DWallet & { public_user_secret_key_share: Uint8Array } {
		if (!dWallet.public_user_secret_key_share) {
			throw new Error('DWallet public user secret key share is not set');
		}
	}

	private assertPresignCompleted(
		presign: Presign,
	): asserts presign is Presign & { state: { Completed: { presign: Uint8Array } } } {
		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}
	}

	private assertUserShareVerification(
		dWallet: DWallet,
		secretShare: Uint8Array,
		publicParameters: Uint8Array,
	) {
		const userShareVerified = verifyUserShare(
			secretShare,
			// @ts-expect-error - TODO: Fix this
			Uint8Array.from(dWallet.state.Active?.public_output),
			publicParameters,
		);

		if (!userShareVerified) {
			throw new Error('User share verification failed');
		}
	}

	private async _verifySecretShareReturnPublicParameters({
		dWallet,
		secretShare,
		publicParameters: publicParametersFromParam,
	}: {
		dWallet: DWallet;
		secretShare: Uint8Array;
		publicParameters?: Uint8Array;
	}) {
		this.assertDWalletPublicOutputSet(dWallet);

		const publicParameters =
			publicParametersFromParam ?? (await this.ikaClient.getProtocolPublicParameters());

		this.assertUserShareVerification(dWallet, secretShare, publicParameters);

		return publicParameters;
	}

	private async _decryptSecretShareAndVerifySecretShare({
		dWallet,
		encryptedUserSecretKeyShare,
		publicParameters: publicParametersFromParam,
	}: {
		dWallet: DWallet;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		publicParameters?: Uint8Array;
	}): Promise<{
		publicParameters: Uint8Array;
		secretShare: Uint8Array;
	}> {
		// This needs to be like this because of the way the type system is set up in typescript.
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const publicParameters =
			publicParametersFromParam ?? (await this.ikaClient.getProtocolPublicParameters());

		const secretShare = await this.userShareEncryptionKeys.decryptUserShare(
			dWallet,
			encryptedUserSecretKeyShare,
			publicParameters,
		);

		await this._verifySecretShareReturnPublicParameters({
			dWallet,
			secretShare,
			publicParameters,
		});

		return { publicParameters, secretShare };
	}

	private _requestDWalletDKGFirstRound({
		curve,
		networkEncryptionKeyID,
		ikaCoin,
		suiCoin,
	}: {
		curve: Curve;
		networkEncryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		return coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			networkEncryptionKeyID,
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private _requestPresign({
		dWallet,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		signatureAlgorithm: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		return coordinatorTx.requestPresign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			signatureAlgorithm,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private async _requestSign({
		verifiedPresignCap,
		messageApproval,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		messageApproval: TransactionObjectArgument;
		userSignatureInputs: {
			activeDWallet: DWallet;
			secretShare?: Uint8Array;
			encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
			presign: Presign;
			message: Uint8Array;
			hash: number;
		};
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		this.assertPresignCompleted(userSignatureInputs.presign);

		const publicParameters = await this.ikaClient.getProtocolPublicParameters();

		const userSecretKeyShare = await this._getUserSecretKeyShare({
			secretShare: userSignatureInputs.secretShare,
			encryptedUserSecretKeyShare: userSignatureInputs.encryptedUserSecretKeyShare,
			activeDWallet: userSignatureInputs.activeDWallet,
			publicParameters,
		});

		return coordinatorTx.requestSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			messageApproval,
			createUserSignMessage(
				publicParameters,
				userSignatureInputs.activeDWallet,
				userSecretKeyShare,
				userSignatureInputs.presign.state.Completed?.presign,
				userSignatureInputs.message,
				userSignatureInputs.hash,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private async _requestFutureSign({
		verifiedPresignCap,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		userSignatureInputs: {
			activeDWallet: DWallet;
			secretShare?: Uint8Array;
			encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
			presign: Presign;
			message: Uint8Array;
			hash: Hash;
		};
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		this.assertPresignCompleted(userSignatureInputs.presign);

		const publicParameters = await this.ikaClient.getProtocolPublicParameters();

		const userSecretKeyShare = await this._getUserSecretKeyShare({
			secretShare: userSignatureInputs.secretShare,
			encryptedUserSecretKeyShare: userSignatureInputs.encryptedUserSecretKeyShare,
			activeDWallet: userSignatureInputs.activeDWallet,
			publicParameters,
		});

		return coordinatorTx.requestFutureSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			userSignatureInputs.activeDWallet.id.id,
			verifiedPresignCap,
			userSignatureInputs.message,
			userSignatureInputs.hash,
			createUserSignMessage(
				publicParameters,
				userSignatureInputs.activeDWallet,
				userSecretKeyShare,
				userSignatureInputs.presign.state.Completed?.presign,
				userSignatureInputs.message,
				userSignatureInputs.hash,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private async _requestImportedKeySign({
		verifiedPresignCap,
		importedKeyMessageApproval,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		importedKeyMessageApproval: TransactionObjectArgument;
		userSignatureInputs: {
			activeDWallet: DWallet;
			secretShare?: Uint8Array;
			encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
			presign: Presign;
			message: Uint8Array;
			hash: Hash;
		};
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		this.assertPresignCompleted(userSignatureInputs.presign);

		const publicParameters = await this.ikaClient.getProtocolPublicParameters();

		const userSecretKeyShare = await this._getUserSecretKeyShare({
			secretShare: userSignatureInputs.secretShare,
			encryptedUserSecretKeyShare: userSignatureInputs.encryptedUserSecretKeyShare,
			activeDWallet: userSignatureInputs.activeDWallet,
			publicParameters,
		});

		return coordinatorTx.requestImportedKeySign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			importedKeyMessageApproval,
			createUserSignMessage(
				publicParameters,
				userSignatureInputs.activeDWallet,
				userSecretKeyShare,
				userSignatureInputs.presign.state.Completed?.presign,
				userSignatureInputs.message,
				userSignatureInputs.hash,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private async _getUserSecretKeyShare({
		secretShare,
		encryptedUserSecretKeyShare,
		activeDWallet,
		publicParameters,
	}: {
		secretShare?: Uint8Array;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		activeDWallet: DWallet;
		publicParameters: Uint8Array;
	}): Promise<Uint8Array> {
		if (secretShare) {
			return secretShare;
		}

		if (!encryptedUserSecretKeyShare) {
			throw new Error('Encrypted user secret key share is not set');
		}

		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return this._decryptSecretShareAndVerifySecretShare({
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			publicParameters,
		}).then(({ secretShare }) => secretShare);
	}

	private async _requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		sourceSecretShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		destinationEncryptionKeyAddress: string;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		sourceSecretShare: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const publicParameters = await this.ikaClient.getProtocolPublicParameters();

		const destinationEncryptionKeyObj = await this.ikaClient.getActiveEncryptionKey(
			destinationEncryptionKeyAddress,
		);

		return coordinatorTx.requestReEncryptUserShareFor(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			destinationEncryptionKeyAddress,
			encryptSecretShare(
				sourceSecretShare,
				new Uint8Array(destinationEncryptionKeyObj.encryption_key),
				publicParameters,
			),
			sourceEncryptedUserSecretKeyShare.id.id,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	private async _requestImportedKeyDwalletVerification({
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
	}: {
		importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
		curve: Curve;
		signerPublicKey: Uint8Array;
		sessionIdentifier: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		// This needs to be like this because of the way the type system is set up in typescript.
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return coordinatorTx.requestImportedKeyDwalletVerification(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			await this.ikaClient.getNetworkEncryptionKeyID(),
			curve,
			importDWalletVerificationRequestInput.userMessage,
			importDWalletVerificationRequestInput.encryptedUserShareAndProof,
			this.userShareEncryptionKeys.getSuiAddress(),
			importDWalletVerificationRequestInput.userPublicOutput,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}
}
