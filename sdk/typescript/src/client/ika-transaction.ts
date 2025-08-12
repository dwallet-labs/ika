// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import { create_sign_centralized_party_message as create_sign_user_message } from '../../../mpc-wasm/dist/node/dwallet_mpc_wasm.js';
import * as coordinatorTx from '../tx/coordinator.js';
import type {
	DKGSecondRoundRequestInput,
	ImportDWalletVerificationRequestInput,
} from './cryptography.js';
import {
	createRandomSessionIdentifier,
	encryptSecretShare,
	verifyUserShare,
} from './cryptography.js';
import type { IkaClient } from './ika-client.js';
import type {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	EncryptionKey,
	Hash,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
	UserSignatureInputs,
} from './types.js';
import type { UserShareEncryptionKeys } from './user-share-encryption-keys.js';

/**
 * Parameters for creating an IkaTransaction instance
 */
export interface IkaTransactionParams {
	/** The IkaClient instance to use for blockchain interactions */
	ikaClient: IkaClient;
	/** The Sui transaction to wrap */
	transaction: Transaction;
	/** Optional user share encryption keys for cryptographic operations */
	userShareEncryptionKeys?: UserShareEncryptionKeys;
}

/**
 * IkaTransaction class provides a high-level interface for interacting with the Ika network.
 * It wraps Sui transactions and provides methods for DWallet operations including DKG,
 * presigning, signing, and key management.
 */
export class IkaTransaction {
	/** The IkaClient instance for blockchain interactions */
	#ikaClient: IkaClient;
	/** The underlying Sui transaction */
	#transaction: Transaction;
	/** Optional user share encryption keys for cryptographic operations */
	#userShareEncryptionKeys?: UserShareEncryptionKeys;
	/** The shared object ref for the coordinator */
	#coordinatorObjectRef?: TransactionObjectArgument;
	/** The shared object ref for the system */
	#systemObjectRef?: TransactionObjectArgument;

	/**
	 * Creates a new IkaTransaction instance
	 * @param params - Configuration parameters for the transaction
	 */
	constructor({ ikaClient, transaction, userShareEncryptionKeys }: IkaTransactionParams) {
		this.#ikaClient = ikaClient;
		this.#transaction = transaction;
		this.#userShareEncryptionKeys = userShareEncryptionKeys;
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
		const dwalletCap = this.#requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID: (await this.#ikaClient.getConfiguredNetworkEncryptionKey()).id,
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
		const dwalletCap = this.#requestDWalletDKGFirstRound({
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
		const cap = this.#requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID: (await this.#ikaClient.getConfiguredNetworkEncryptionKey()).id,
			ikaCoin,
			suiCoin,
		});

		this.#transaction.transferObjects([cap], receiver);

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
		const cap = this.#requestDWalletDKGFirstRound({
			curve,
			networkEncryptionKeyID,
			ikaCoin,
			suiCoin,
		});

		this.#transaction.transferObjects([cap], receiver);

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
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.requestDWalletDKGSecondRound(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			this.#transaction.object(dWallet.dwallet_cap_id),
			dkgSecondRoundRequestInput.userDKGMessage,
			dkgSecondRoundRequestInput.encryptedUserShareAndProof,
			this.#userShareEncryptionKeys.getSuiAddress(),
			dkgSecondRoundRequestInput.userPublicOutput,
			this.#userShareEncryptionKeys.getSigningPublicKeyBytes(),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);

		return this;
	}

	/**
	 * Accept an encrypted user share for a DWallet.
	 * This completes the user's participation in the DKG process by accepting their encrypted share.
	 *
	 * @param params - The parameters for accepting the encrypted user share
	 * @param params.dWallet - The DWallet object to accept the share for
	 * @param params.userPublicOutput - The user's public output from the DKG process, this is used to verify the user's public output signature.
	 * @param params.encryptedUserSecretKeyShareId - The ID of the encrypted user secret key share
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async acceptEncryptedUserShare({
		dWallet,
		userPublicOutput,
		encryptedUserSecretKeyShareId,
	}: {
		dWallet: DWallet;
		userPublicOutput: Uint8Array;
		encryptedUserSecretKeyShareId: string;
	}) {
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.acceptEncryptedUserShare(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.id.id,
			encryptedUserSecretKeyShareId,
			await this.#userShareEncryptionKeys.getUserOutputSignature(dWallet, userPublicOutput),
			this.#transaction,
		);

		return this;
	}

	/**
	 * Accept an encrypted user share for a transferred DWallet.
	 * This completes the user's participation in the DKG process by accepting their encrypted share.
	 *
	 * SECURITY WARNING: `sourceEncryptionKey` shouldn't be fetched from the network;
	 * the public key of the sender (or its address) should be known to the receiver,
	 * so that the verification here would be impactful.
	 *
	 * @param params - The parameters for accepting the encrypted user share
	 * @param params.dWallet - The DWallet object to accept the share for
	 * @param params.sourceEncryptionKey - The encryption key used to encrypt the user's secret share.
	 * @param params.sourceEncryptedUserSecretKeyShare - The encrypted user secret key share.
	 * @param params.destinationEncryptedUserSecretKeyShare - The encrypted user secret key share.
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async acceptEncryptedUserShareForTransferredDWallet({
		dWallet,
		sourceEncryptionKey,
		sourceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare,
	}: {
		dWallet: DWallet;
		sourceEncryptionKey: EncryptionKey;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		destinationEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	}) {
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.acceptEncryptedUserShare(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.id.id,
			destinationEncryptedUserSecretKeyShare.id.id,
			await this.#userShareEncryptionKeys.getUserOutputSignatureForTransferredDWallet(
				dWallet,
				sourceEncryptedUserSecretKeyShare,
				sourceEncryptionKey,
			),
			this.#transaction,
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
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		coordinatorTx.registerEncryptionKeyTx(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			curve,
			this.#userShareEncryptionKeys.encryptionKey,
			await this.#userShareEncryptionKeys.getEncryptionKeySignature(),
			this.#userShareEncryptionKeys.getSigningPublicKeyBytes(),
			this.#transaction,
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.id.id,
			secretShare,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
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
		const unverifiedPresignCap = this.#requestPresign({
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
		const unverifiedPresignCap = this.#requestPresign({
			dWallet,
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});

		this.#transaction.transferObjects([unverifiedPresignCap], receiver);

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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
			this.#transaction,
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			presign.cap_id,
			this.#transaction,
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.dwallet_cap_id,
			signatureAlgorithm,
			hashScheme,
			message,
			this.#transaction,
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
		await this.#requestSign({
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
	 * SECURITY WARNING: This method does not verify `secretShare` and `publicOutput`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share and public output which should be verified before using this method.
	 *
	 * @param params - The parameters for signing
	 * @param params.dWallet - The DWallet to sign with
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The secret share to use for signing
	 * @param params.publicOutput - The public output to use for signing which should be verified before using this method.
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
		publicOutput,
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
		publicOutput: Uint8Array;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		await this.#requestSign({
			verifiedPresignCap,
			messageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				publicOutput,
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
		this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);
		this.#assertDWalletPublicOutputSet(dWallet);

		await this.#requestSign({
			verifiedPresignCap,
			messageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				// No need to verify public output in public user-share flows, as there is no zero-trust security in this model.
				publicOutput: Uint8Array.from(dWallet.state.Active?.public_output),
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
		const unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
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
	 * WARNING: This method is unsafe and should only be used if you know what you are doing.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share and public output which should be verified before using this method.
	 *
	 * @param params - The parameters for requesting future sign
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.publicOutput - The user's public output
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
		publicOutput,
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
		publicOutput: Uint8Array;
		message: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		unverifiedPartialUserSignatureCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare,
				publicOutput,
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
		const unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
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

		this.#transaction.transferObjects([unverifiedPartialUserSignatureCap], receiver);

		return this;
	}

	/**
	 * Request a future sign operation and transfer the capability to a specified receiver.
	 * This creates a partial user signature capability that can be delegated to another address.
	 *
	 * WARNING: This method is unsafe and should only be used if you know what you are doing.
	 *
	 * This method is used when developer has access to the user's unencrypted secret share.
	 *
	 * @param params - The parameters for requesting future sign and keep
	 * @param params.dWallet - The DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.publicOutput - The user's public output
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
		publicOutput,
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
		publicOutput: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		receiver: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
			verifiedPresignCap,
			userSignatureInputs: {
				activeDWallet: dWallet,
				presign,
				secretShare,
				publicOutput,
				message,
				hash: hashScheme,
			},
			ikaCoin,
			suiCoin,
		});

		this.#transaction.transferObjects([unverifiedPartialUserSignatureCap], receiver);

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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			coordinatorTx.verifyPartialUserSignatureCap(
				this.#ikaClient.ikaConfig,
				this.#getCoordinatorObjectRef(),
				this.#transaction.object(partialUserSignature.cap_id),
				this.#transaction,
			),
			messageApproval,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
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
		const importedKeyDWalletVerificationCap = await this.#requestImportedKeyDwalletVerification({
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
		const importedKeyDWalletVerificationCap = await this.#requestImportedKeyDwalletVerification({
			importDWalletVerificationRequestInput,
			curve,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		});

		this.#transaction.transferObjects([importedKeyDWalletVerificationCap], receiver);

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
		await this.#requestImportedKeySign({
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
	 * WARNING: This method is unsafe and should only be used if you know what you are doing.
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
		await this.#requestImportedKeySign({
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
		this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);

		await this.#requestImportedKeySign({
			verifiedPresignCap,
			importedKeyMessageApproval,
			userSignatureInputs: {
				activeDWallet: dWallet,
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
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const { secretShare: sourceSecretShare } = await this.#userShareEncryptionKeys.decryptUserShare(
			dWallet,
			sourceEncryptedUserSecretKeyShare,
			await this.#ikaClient.getProtocolPublicParameters(dWallet),
		);

		await this.#requestReEncryptUserShareFor({
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
	 * Transfer an encrypted user share from the current user to another address.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 *
	 * WARNING: This method is unsafe and should only be used if you know what you are doing.
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
		await this.#requestReEncryptUserShareFor({
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			createRandomSessionIdentifier(),
			this.#transaction,
		);
	}

	#getCoordinatorObjectRef() {
		if (!this.#coordinatorObjectRef) {
			this.#coordinatorObjectRef = this.#transaction.sharedObjectRef({
				objectId: this.#ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion:
					this.#ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			});
		}

		return this.#coordinatorObjectRef;
	}

	// @ts-expect-error - TODO: Add system functions
	#getSystemObjectRef() {
		if (!this.#systemObjectRef) {
			this.#systemObjectRef = this.#transaction.sharedObjectRef({
				objectId: this.#ikaClient.ikaConfig.objects.ikaSystemObject.objectID,
				initialSharedVersion:
					this.#ikaClient.ikaConfig.objects.ikaSystemObject.initialSharedVersion,
				mutable: true,
			});
		}

		return this.#systemObjectRef;
	}

	#assertDWalletPublicOutputSet(
		dWallet: DWallet,
	): asserts dWallet is DWallet & { state: { Active: { public_output: Uint8Array } } } {
		if (!dWallet.state.Active?.public_output) {
			throw new Error('DWallet public output is not set');
		}
	}

	#assertDWalletPublicUserSecretKeyShareSet(
		dWallet: DWallet,
	): asserts dWallet is DWallet & { public_user_secret_key_share: Uint8Array } {
		if (!dWallet.public_user_secret_key_share) {
			throw new Error('DWallet public user secret key share is not set');
		}
	}

	#assertPresignCompleted(
		presign: Presign,
	): asserts presign is Presign & { state: { Completed: { presign: Uint8Array } } } {
		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}
	}

	async #verifySecretShare({
		verifiedPublicOutput,
		secretShare,
		publicParameters,
	}: {
		verifiedPublicOutput: Uint8Array;
		secretShare: Uint8Array;
		publicParameters: Uint8Array;
	}) {
		const userShareVerified = verifyUserShare(secretShare, verifiedPublicOutput, publicParameters);

		if (!userShareVerified) {
			throw new Error('User share verification failed');
		}
	}

	async #decryptAndVerifySecretShare({
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
		verifiedPublicOutput: Uint8Array;
	}> {
		// This needs to be like this because of the way the type system is set up in typescript.
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const publicParameters =
			publicParametersFromParam ?? (await this.#ikaClient.getProtocolPublicParameters(dWallet));

		const { secretShare, verifiedPublicOutput } =
			await this.#userShareEncryptionKeys.decryptUserShare(
				dWallet,
				encryptedUserSecretKeyShare,
				publicParameters,
			);

		await this.#verifySecretShare({
			verifiedPublicOutput,
			secretShare,
			publicParameters,
		});

		return { publicParameters, secretShare, verifiedPublicOutput };
	}

	#requestDWalletDKGFirstRound({
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			networkEncryptionKeyID,
			curve,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	#requestPresign({
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
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dWallet.id.id,
			signatureAlgorithm,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	async #getUserSignMessage({
		userSignatureInputs,
	}: {
		userSignatureInputs: UserSignatureInputs;
	}): Promise<Uint8Array> {
		this.#assertPresignCompleted(userSignatureInputs.presign);
		this.#assertDWalletPublicOutputSet(userSignatureInputs.activeDWallet);

		const publicParameters = await this.#ikaClient.getProtocolPublicParameters(
			userSignatureInputs.activeDWallet,
		);

		let secretShare, publicOutput;

		// If the dWallet is a shared dWallet, we use the public user secret key share. It is a different trust assumption in which no zero-trust security is assured.
		// Otherwise, we use the secret share from the user signature inputs.
		if (userSignatureInputs.activeDWallet.public_user_secret_key_share) {
			secretShare = Uint8Array.from(userSignatureInputs.activeDWallet.public_user_secret_key_share);
			publicOutput = Uint8Array.from(userSignatureInputs.activeDWallet.state.Active?.public_output);
		} else {
			const userSecretKeyShareResponse = await this.#getUserSecretKeyShare({
				secretShare: userSignatureInputs.secretShare,
				encryptedUserSecretKeyShare: userSignatureInputs.encryptedUserSecretKeyShare,
				activeDWallet: userSignatureInputs.activeDWallet,
				publicParameters,
				publicOutput: userSignatureInputs.publicOutput,
			});

			secretShare = userSecretKeyShareResponse.secretShare;
			publicOutput = userSecretKeyShareResponse.verifiedPublicOutput;
		}

		return this.#createUserSignMessageWithPublicOutput({
			protocolPublicParameters: publicParameters,
			publicOutput,
			userSecretKeyShare: secretShare,
			presign: userSignatureInputs.presign.state.Completed?.presign,
			message: userSignatureInputs.message,
			hash: userSignatureInputs.hash,
		});
	}

	async #requestSign({
		verifiedPresignCap,
		messageApproval,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		messageApproval: TransactionObjectArgument;
		userSignatureInputs: UserSignatureInputs;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const userSignMessage = await this.#getUserSignMessage({
			userSignatureInputs,
		});

		return coordinatorTx.requestSign(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			verifiedPresignCap,
			messageApproval,
			userSignMessage,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	async #requestFutureSign({
		verifiedPresignCap,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		userSignatureInputs: UserSignatureInputs;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const userSignMessage = await this.#getUserSignMessage({
			userSignatureInputs,
		});

		return coordinatorTx.requestFutureSign(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			userSignatureInputs.activeDWallet.id.id,
			verifiedPresignCap,
			userSignatureInputs.message,
			userSignatureInputs.hash,
			userSignMessage,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	async #requestImportedKeySign({
		verifiedPresignCap,
		importedKeyMessageApproval,
		userSignatureInputs,
		ikaCoin,
		suiCoin,
	}: {
		verifiedPresignCap: TransactionObjectArgument;
		importedKeyMessageApproval: TransactionObjectArgument;
		userSignatureInputs: UserSignatureInputs;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const userSignMessage = await this.#getUserSignMessage({
			userSignatureInputs,
		});

		return coordinatorTx.requestImportedKeySign(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			verifiedPresignCap,
			importedKeyMessageApproval,
			userSignMessage,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	async #getUserSecretKeyShare({
		secretShare,
		encryptedUserSecretKeyShare,
		activeDWallet,
		publicParameters,
		publicOutput,
	}: {
		secretShare?: Uint8Array;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		activeDWallet: DWallet;
		publicParameters: Uint8Array;
		publicOutput?: Uint8Array;
	}): Promise<{
		secretShare: Uint8Array;
		verifiedPublicOutput: Uint8Array;
	}> {
		if (secretShare) {
			if (!publicOutput) {
				throw new Error('Public output is required when providing secret share directly');
			}

			return { secretShare, verifiedPublicOutput: publicOutput };
		}

		if (!encryptedUserSecretKeyShare) {
			throw new Error('Encrypted user secret key share is not set');
		}

		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return this.#decryptAndVerifySecretShare({
			dWallet: activeDWallet,
			encryptedUserSecretKeyShare,
			publicParameters,
		});
	}

	async #requestReEncryptUserShareFor({
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
		if (!sourceEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
			throw new Error('User output signature is not set');
		}

		const publicParameters = await this.#ikaClient.getProtocolPublicParameters(dWallet);

		const destinationEncryptionKeyObj = await this.#ikaClient.getActiveEncryptionKey(
			destinationEncryptionKeyAddress,
		);

		const publicKey = new Ed25519PublicKey(
			new Uint8Array(destinationEncryptionKeyObj.signer_public_key),
		);

		if (
			!(await publicKey.verify(
				Uint8Array.from(destinationEncryptionKeyObj.encryption_key),
				Uint8Array.from(destinationEncryptionKeyObj.encryption_key_signature),
			))
		) {
			throw new Error('Destination encryption key signature is not valid');
		}

		if (publicKey.toSuiAddress() !== destinationEncryptionKeyObj.signer_address) {
			throw new Error('Destination encryption key address does not match the public key');
		}

		return coordinatorTx.requestReEncryptUserShareFor(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
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
			this.#transaction,
		);
	}

	async #requestImportedKeyDwalletVerification({
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
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return coordinatorTx.requestImportedKeyDwalletVerification(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			(await this.#ikaClient.getConfiguredNetworkEncryptionKey()).id,
			curve,
			importDWalletVerificationRequestInput.userMessage,
			importDWalletVerificationRequestInput.encryptedUserShareAndProof,
			this.#userShareEncryptionKeys.getSuiAddress(),
			importDWalletVerificationRequestInput.userPublicOutput,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	async #createUserSignMessageWithPublicOutput({
		protocolPublicParameters,
		publicOutput,
		userSecretKeyShare,
		presign,
		message,
		hash,
	}: {
		protocolPublicParameters: Uint8Array;
		publicOutput: Uint8Array;
		userSecretKeyShare: Uint8Array;
		presign: Uint8Array;
		message: Uint8Array;
		hash: number;
	}): Promise<Uint8Array> {
		return new Uint8Array(
			create_sign_user_message(
				protocolPublicParameters,
				publicOutput,
				userSecretKeyShare,
				presign,
				message,
				hash,
			),
		);
	}
}
