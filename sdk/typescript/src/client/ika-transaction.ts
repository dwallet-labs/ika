// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import type {
	Transaction,
	TransactionObjectArgument,
	TransactionResult,
} from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator.js';
import type { DKGRequestInput, ImportDWalletVerificationRequestInput } from './cryptography.js';
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
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	Presign,
	SharedDWallet,
	UserSignatureInputs,
	ZeroTrustDWallet,
} from './types.js';
import { SignatureAlgorithm } from './types.js';
import type { UserShareEncryptionKeys } from './user-share-encryption-keys.js';
import {
	create_sign_centralized_party_message as create_sign,
	create_sign_centralized_party_message_with_centralized_party_dkg_output as create_sign_with_centralized_output,
} from './wasm-loader.js';

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
	 * @param params.ikaClient - The IkaClient instance for network operations
	 * @param params.transaction - The Sui transaction builder to wrap
	 * @param params.userShareEncryptionKeys - Optional encryption keys for user share operations
	 */
	constructor({ ikaClient, transaction, userShareEncryptionKeys }: IkaTransactionParams) {
		this.#ikaClient = ikaClient;
		this.#transaction = transaction;
		this.#userShareEncryptionKeys = userShareEncryptionKeys;
	}

	/**
	 * @deprecated This method is deprecated. Use `requestDWalletDKG` or `requestDWalletDKGWithPublicUserShare` instead.
	 *
	 * Request the DKG (Distributed Key Generation) first round with automatic decryption key ID fetching.
	 * This initiates the creation of a new DWallet through a distributed key generation process.
	 *
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to a DWallet capability
	 * @throws {Error} If the decryption key ID cannot be fetched
	 */
	async requestDWalletDKGFirstRoundAsync(_params: {
		curve: Curve;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		throw new Error(
			'requestDWalletDKGFirstRoundAsync is deprecated. Use requestDWalletDKGFirstRound instead',
		);
	}

	/**
	 * @deprecated This method is deprecated. Use `requestDWalletDKG` or `requestDWalletDKGWithPublicUserShare` instead.
	 *
	 * Request the DKG (Distributed Key Generation) first round with explicit decryption key ID.
	 * This initiates the creation of a new DWallet through a distributed key generation process.
	 *
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.networkEncryptionKeyID - The specific network encryption key ID to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns DWallet capability
	 */
	requestDWalletDKGFirstRound(_params: {
		curve: Curve;
		networkEncryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): TransactionObjectArgument {
		throw new Error('requestDWalletDKGFirstRound is deprecated. Use requestDWalletDKG instead');
	}

	/**
	 * @deprecated This method is deprecated. Use `requestDWalletDKG` or `requestDWalletDKGWithPublicUserShare` instead.
	 *
	 * Request the DKG (Distributed Key Generation) second round to complete DWallet creation.
	 * This finalizes the distributed key generation process started in the first round.
	 *
	 * @param params.dWalletCap - The dWalletCap object from the first round, created for dWallet
	 * @param params.dkgSecondRoundRequestInput - Cryptographic data prepared for the second round
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	requestDWalletDKGSecondRound(_params: {
		dWalletCap: TransactionObjectArgument | string;
		dkgSecondRoundRequestInput: DKGRequestInput;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		throw new Error('requestDWalletDKGSecondRound is deprecated. Use requestDWalletDKG instead');
	}

	/**
	 * Request the DKG (Distributed Key Generation) to create a dWallet.
	 *
	 * @param params.dkgRequestInput - Cryptographic data prepared for the DKG
	 * @param params.sessionIdentifier - The session identifier object
	 * @param params.dwalletNetworkEncryptionKeyId - The dWallet network encryption key ID
	 * @param params.signDuringDKGRequest - The sign during DKG request
	 * @param params.curve - The curve
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 *
	 * @returns The DWallet capability and sign id if signDuringDKGRequest is provided
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestDWalletDKG({
		dkgRequestInput,
		ikaCoin,
		suiCoin,
		sessionIdentifier,
		dwalletNetworkEncryptionKeyId,
		signDuringDKGRequest,
		curve,
	}: {
		dkgRequestInput: DKGRequestInput;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		sessionIdentifier: TransactionObjectArgument;
		dwalletNetworkEncryptionKeyId: string;
		signDuringDKGRequest?: {
			message: Uint8Array;
			presign: Presign;
			verifiedPresignCap: TransactionObjectArgument;
			hashScheme: Hash;
			signatureAlgorithm: SignatureAlgorithm;
		};
		curve: Curve;
	}): Promise<TransactionResult> {
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return coordinatorTx.requestDWalletDKG(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dwalletNetworkEncryptionKeyId,
			curve,
			dkgRequestInput.userDKGMessage,
			dkgRequestInput.encryptedUserShareAndProof,
			this.#userShareEncryptionKeys.getSuiAddress(),
			dkgRequestInput.userPublicOutput,
			this.#userShareEncryptionKeys.getSigningPublicKeyBytes(),
			sessionIdentifier,
			signDuringDKGRequest
				? coordinatorTx.signDuringDKGRequest(
						this.#ikaClient.ikaConfig,
						this.#getCoordinatorObjectRef(),
						signDuringDKGRequest.verifiedPresignCap,
						signDuringDKGRequest.hashScheme,
						signDuringDKGRequest.message,
						await this.#getUserSignMessage({
							userSignatureInputs: {
								secretShare: dkgRequestInput.userSecretKeyShare,
								publicOutput: dkgRequestInput.userPublicOutput,
								hash: signDuringDKGRequest.hashScheme,
								message: signDuringDKGRequest.message,
								signatureScheme: signDuringDKGRequest.signatureAlgorithm,
								presign: signDuringDKGRequest.presign,
								curve,
							},
						}),
						this.#transaction,
					)
				: null,
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	/**
	 * Request the DKG (Distributed Key Generation) with public user share to create a dWallet.
	 *
	 * @param params.sessionIdentifier - The session identifier object ID
	 * @param params.dwalletNetworkEncryptionKeyId - The dWallet network encryption key ID
	 * @param params.curve - The curve
	 * @param params.publicKeyShareAndProof - The public key share and proof
	 * @param params.publicUserSecretKeyShare - The public user secret key share
	 * @param params.signDuringDKGRequest - The sign during DKG request
	 * @param params.userPublicOutput - The user's public output from the DKG process
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 *
	 * @returns The DWallet capability and sign id if signDuringDKGRequest is provided
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestDWalletDKGWithPublicUserShare({
		sessionIdentifier,
		dwalletNetworkEncryptionKeyId,
		curve,
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		signDuringDKGRequest,
		userPublicOutput,
		ikaCoin,
		suiCoin,
	}: {
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		sessionIdentifier: TransactionObjectArgument;
		dwalletNetworkEncryptionKeyId: string;
		curve: Curve;
		publicKeyShareAndProof: Uint8Array;
		publicUserSecretKeyShare: Uint8Array;
		userPublicOutput: Uint8Array;
		signDuringDKGRequest?: {
			message: Uint8Array;
			presign: Presign;
			verifiedPresignCap: TransactionObjectArgument;
			hashScheme: Hash;
			signatureAlgorithm: SignatureAlgorithm;
		};
	}): Promise<TransactionResult> {
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		return coordinatorTx.requestDWalletDKGWithPublicUserSecretKeyShare(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dwalletNetworkEncryptionKeyId,
			curve,
			publicKeyShareAndProof,
			publicUserSecretKeyShare,
			userPublicOutput,
			sessionIdentifier,
			signDuringDKGRequest
				? coordinatorTx.signDuringDKGRequest(
						this.#ikaClient.ikaConfig,
						this.#getCoordinatorObjectRef(),
						signDuringDKGRequest.verifiedPresignCap,
						signDuringDKGRequest.hashScheme,
						signDuringDKGRequest.message,
						await this.#getUserSignMessage({
							userSignatureInputs: {
								hash: signDuringDKGRequest.hashScheme,
								message: signDuringDKGRequest.message,
								signatureScheme: signDuringDKGRequest.signatureAlgorithm,
								presign: signDuringDKGRequest.presign,
								curve,
							},
						}),
						this.#transaction,
					)
				: null,
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	/**
	 * This completes the user's participation in the DKG process by accepting their encrypted share.
	 *
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
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		userPublicOutput: Uint8Array;
		encryptedUserSecretKeyShareId: string;
	}): Promise<IkaTransaction>;

	/**
	 * Accept an encrypted user share for a transferred DWallet.
	 * This completes the user's participation in the DKG process by accepting their encrypted share.
	 *
	 * SECURITY WARNING: `sourceEncryptionKey` shouldn't be fetched from the network;
	 * the public key of the sender (or its address) should be known to the receiver,
	 * so that the verification here would be impactful.
	 *
	 * @param params.dWallet - The DWallet object to accept the share for
	 * @param params.sourceEncryptionKey - The encryption key used to encrypt the user's secret share.
	 * @param params.sourceEncryptedUserSecretKeyShare - The encrypted user secret key share.
	 * @param params.destinationEncryptedUserSecretKeyShare - The encrypted user secret key share.
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async acceptEncryptedUserShare({
		dWallet,
		sourceEncryptionKey,
		sourceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare,
	}: {
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		sourceEncryptionKey: EncryptionKey;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		destinationEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	}): Promise<IkaTransaction>;

	async acceptEncryptedUserShare({
		dWallet,
		userPublicOutput,
		encryptedUserSecretKeyShareId,
		sourceEncryptionKey,
		sourceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare,
	}: {
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		userPublicOutput?: Uint8Array;
		encryptedUserSecretKeyShareId?: string;
		sourceEncryptionKey?: EncryptionKey;
		sourceEncryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		destinationEncryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	}) {
		if (!this.#userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		// Regular DWallet encrypted user share acceptance
		if (userPublicOutput && encryptedUserSecretKeyShareId) {
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

		// Transferred DWallet encrypted user share acceptance
		if (
			sourceEncryptionKey &&
			sourceEncryptedUserSecretKeyShare &&
			destinationEncryptedUserSecretKeyShare
		) {
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

		throw new Error(
			'Invalid parameters: must provide either (userPublicOutput, encryptedUserSecretKeyShareId) for regular DWallet or (sourceEncryptionKey, sourceEncryptedUserSecretKeyShare, destinationEncryptedUserSecretKeyShare) for transferred DWallet',
		);
	}

	/**
	 * Register an encryption key for the current user on the specified curve.
	 * This allows the user to participate in encrypted operations on the network.
	 *
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
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
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
	 * @param params.dWallet - The DWallet to create the presign for
	 * @param params.signatureAlgorithm - The signature algorithm identifier to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Unverified presign capability
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
	}): TransactionObjectArgument {
		const unverifiedPresignCap = this.#requestPresign({
			dWallet,
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});

		return unverifiedPresignCap;
	}

	/**
	 * Request a global presign operation.
	 *
	 * @param params.dwalletNetworkEncryptionKeyId - The network encryption key ID to use for the presign
	 * @param params.curve - The curve to use for the presign
	 * @param params.signatureAlgorithm - The signature algorithm to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Unverified presign capability
	 */
	requestGlobalPresign({
		dwalletNetworkEncryptionKeyId,
		curve,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
	}: {
		dwalletNetworkEncryptionKeyId: string;
		curve: Curve;
		signatureAlgorithm: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		const unverifiedPresignCap = this.#requestGlobalPresign({
			dwalletNetworkEncryptionKeyId,
			curve,
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});

		return unverifiedPresignCap;
	}

	/**
	 * Approve a message for signing with a DWallet.
	 * This creates an approval object that can be used in subsequent signing operations.
	 *
	 * @param params.dWalletCap - The dWalletCap object, that owns the dWallet
	 * @param params.signatureAlgorithm - The signature algorithm to use
	 * @param params.hashScheme - The hash scheme to apply to the message
	 * @param params.message - The message bytes to approve for signing
	 * @returns Message approval
	 */
	approveMessage({
		dWalletCap,
		signatureAlgorithm,
		hashScheme,
		message,
	}: {
		dWalletCap: TransactionObjectArgument | string;
		signatureAlgorithm: SignatureAlgorithm;
		hashScheme: Hash;
		message: Uint8Array;
	}): TransactionObjectArgument {
		const messageApproval = coordinatorTx.approveMessage(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			this.#transaction.object(dWalletCap),
			signatureAlgorithm,
			hashScheme,
			message,
			this.#transaction,
		);

		return messageApproval;
	}

	/**
	 * Verify a presign capability to ensure it can be used for signing.
	 * This converts an unverified presign capability into a verified one.
	 *
	 * @param params.presign - The presign object to verify
	 * @returns Verified presign capability
	 */
	verifyPresignCap({ presign }: { presign: Presign }): TransactionObjectArgument;

	/**
	 * Verify a presign capability to ensure it can be used for signing.
	 * This converts an unverified presign capability into a verified one.
	 *
	 * @param params.unverifiedPresignCap - The unverified presign capability object or ID
	 * @returns Verified presign capability
	 */
	verifyPresignCap({
		unverifiedPresignCap,
	}: {
		unverifiedPresignCap: TransactionObjectArgument | string;
	}): TransactionObjectArgument;

	verifyPresignCap({
		presign,
		unverifiedPresignCap,
	}: {
		presign?: Presign;
		unverifiedPresignCap?: TransactionObjectArgument | string;
	}): TransactionObjectArgument {
		let capId: TransactionObjectArgument | string;

		if (unverifiedPresignCap) {
			capId = unverifiedPresignCap;
		} else if (presign?.cap_id) {
			capId = presign.cap_id;
		} else {
			throw new Error('Either presign or unverifiedPresignCap must be provided');
		}

		const verifiedPresignCap = coordinatorTx.verifyPresignCap(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			this.#transaction.object(capId),
			this.#transaction,
		);

		return verifiedPresignCap;
	}

	/**
	 * Approve a message for signing with an imported key DWallet.
	 * This is similar to approveMessage but specifically for DWallets created with imported keys.
	 *
	 * @param params.dWalletCap - The dWalletCap object, that owns the dWallet
	 * @param params.signatureAlgorithm - The signature algorithm to use
	 * @param params.hashScheme - The hash scheme to apply to the message
	 * @param params.message - The message bytes to approve for signing
	 * @returns Imported key message approval
	 */
	approveImportedKeyMessage({
		dWalletCap,
		signatureAlgorithm,
		hashScheme,
		message,
	}: {
		dWalletCap: TransactionObjectArgument | string;
		signatureAlgorithm: SignatureAlgorithm;
		hashScheme: Hash;
		message: Uint8Array;
	}): TransactionObjectArgument {
		const importedKeyMessageApproval = coordinatorTx.approveImportedKeyMessage(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			this.#transaction.object(dWalletCap),
			signatureAlgorithm,
			hashScheme,
			message,
			this.#transaction,
		);

		return importedKeyMessageApproval;
	}

	/**
	 * Sign a message using a DWallet.
	 * This performs the actual signing operation using the presign and user's share (encrypted, secret, or public).
	 * Only supports ZeroTrust and Shared DWallets. For Imported Key DWallets, use requestSignWithImportedKey instead.
	 *
	 * SECURITY WARNING: When using unencrypted shares, this method does not verify `secretShare` and `publicOutput`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * @param params.dWallet - The DWallet to sign with (ZeroTrust or Shared DWallet)
	 * @param params.messageApproval - Message approval
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - Optional: encrypted user secret key share (for ZeroTrust DWallets)
	 * @param params.secretShare - Optional: unencrypted secret share (requires publicOutput, for ZeroTrust DWallets)
	 * @param params.publicOutput - Optional: public output (required when using secretShare, for ZeroTrust DWallets)
	 * @param params.message - The message bytes to sign
	 * @param params.signatureScheme - The signature algorithm to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the signature ID
	 *
	 * @example
	 * // ZeroTrust DWallet - Zero-trust signing (encrypted shares)
	 * const signatureId = await tx.requestSign({
	 *   dWallet, // ZeroTrustDWallet
	 *   messageApproval,
	 *   encryptedUserSecretKeyShare,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ZeroTrust DWallet - Secret share signing
	 * const signatureId = await tx.requestSign({
	 *   dWallet, // ZeroTrustDWallet
	 *   messageApproval,
	 *   secretShare,
	 *   publicOutput,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // Shared DWallet - Public share signing (no secret params needed)
	 * const signatureId = await tx.requestSign({
	 *   dWallet, // SharedDWallet
	 *   messageApproval,
	 *   // ... other params (no secretShare/publicOutput needed)
	 * });
	 */
	async requestSign({
		dWallet,
		messageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet | SharedDWallet;
		messageApproval: TransactionObjectArgument;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		secretShare?: Uint8Array;
		publicOutput?: Uint8Array;
		message: Uint8Array;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		// Auto-detect share availability
		const hasPublicShares = !!dWallet.public_user_secret_key_share;

		// Regular DWallet signing (ZeroTrust and Shared only)
		if (encryptedUserSecretKeyShare) {
			// Encrypted shares
			return this.#requestSign({
				verifiedPresignCap,
				messageApproval,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					encryptedUserSecretKeyShare,
					message,
					hash: hashScheme,
					signatureScheme: signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (secretShare && publicOutput) {
			// Secret share provided
			return this.#requestSign({
				verifiedPresignCap,
				messageApproval,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					secretShare,
					publicOutput,
					message,
					hash: hashScheme,
					signatureScheme: signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (hasPublicShares) {
			// Public shares available on DWallet
			this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);
			this.#assertDWalletPublicOutputSet(dWallet);

			return this.#requestSign({
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
					signatureScheme: signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else {
			throw new Error(
				'DWallet signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
			);
		}
	}

	/**
	 * Sign a message using an Imported Key DWallet.
	 * This performs the actual signing operation using the presign and user's share (encrypted, secret, or public).
	 *
	 * SECURITY WARNING: When using unencrypted shares, this method does not verify `secretShare` and `publicOutput`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * @param params.dWallet - The Imported Key DWallet to sign with (type and share availability auto-detected)
	 * @param params.importedKeyMessageApproval - Imported key message approval
	 * @param params.hashScheme - The hash scheme used for the message
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - Optional: encrypted user secret key share (for ImportedKeyDWallet)
	 * @param params.secretShare - Optional: unencrypted secret share (requires publicOutput, for ImportedKeyDWallet)
	 * @param params.publicOutput - Optional: public output (required when using secretShare, for ImportedKeyDWallet)
	 * @param params.message - The message bytes to sign
	 * @param params.signatureScheme - Optional: signature algorithm (defaults to ECDSASecp256k1)
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the signature ID
	 *
	 * @example
	 * // ImportedKeyDWallet - Zero-trust signing (encrypted shares)
	 * const signatureId = await tx.requestSignWithImportedKey({
	 *   dWallet, // ImportedKeyDWallet
	 *   importedKeyMessageApproval,
	 *   encryptedUserSecretKeyShare,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ImportedKeyDWallet - Secret share signing
	 * const signatureId = await tx.requestSignWithImportedKey({
	 *   dWallet, // ImportedKeyDWallet
	 *   importedKeyMessageApproval,
	 *   secretShare,
	 *   publicOutput,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ImportedSharedDWallet - Public share signing (no secret params needed)
	 * const signatureId = await tx.requestSignWithImportedKey({
	 *   dWallet, // ImportedSharedDWallet
	 *   importedKeyMessageApproval,
	 *   // ... other params (no secretShare/publicOutput needed)
	 * });
	 */
	async requestSignWithImportedKey({
		dWallet,
		importedKeyMessageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ImportedKeyDWallet | ImportedSharedDWallet;
		importedKeyMessageApproval: TransactionObjectArgument;
		hashScheme: Hash;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		secretShare?: Uint8Array;
		publicOutput?: Uint8Array;
		message: Uint8Array;
		signatureScheme?: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		if (!dWallet.is_imported_key_dwallet) {
			throw new Error('dWallet must be an ImportedKeyDWallet');
		}

		// Auto-detect share availability
		const hasPublicShares = !!dWallet.public_user_secret_key_share;

		// Auto-detect signing method based on available shares and parameters
		if (encryptedUserSecretKeyShare) {
			// Encrypted shares
			return this.#requestImportedKeySign({
				verifiedPresignCap,
				importedKeyMessageApproval,
				userSignatureInputs: {
					activeDWallet: dWallet,
					encryptedUserSecretKeyShare,
					presign,
					message,
					hash: hashScheme,
					signatureScheme: signatureScheme || SignatureAlgorithm.ECDSASecp256k1,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (secretShare && publicOutput) {
			// Secret share provided
			return this.#requestImportedKeySign({
				verifiedPresignCap,
				importedKeyMessageApproval,
				userSignatureInputs: {
					activeDWallet: dWallet,
					secretShare,
					publicOutput,
					presign,
					message,
					hash: hashScheme,
					signatureScheme: signatureScheme || SignatureAlgorithm.ECDSASecp256k1,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (hasPublicShares) {
			// Public shares available on DWallet
			this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);
			return this.#requestImportedKeySign({
				verifiedPresignCap,
				importedKeyMessageApproval,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					message,
					hash: hashScheme,
					signatureScheme: signatureScheme || SignatureAlgorithm.ECDSASecp256k1,
				},
				ikaCoin,
				suiCoin,
			});
		} else {
			throw new Error(
				'Imported Key DWallet signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
			);
		}
	}

	/**
	 * Request a future sign operation with encrypted shares for ZeroTrust DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 *
	 * @param params.dWallet - The ZeroTrust DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSign({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Request a future sign operation with secret shares for ZeroTrust DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 *
	 * SECURITY WARNING: This method does not verify `secretShare` and `publicOutput`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * @param params.dWallet - The ZeroTrust DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.publicOutput - The user's public output
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSign({
		dWallet,
		verifiedPresignCap,
		presign,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		secretShare: Uint8Array;
		publicOutput: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Request a future sign operation with public shares for Shared DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 * No secret share or public output parameters are needed as they are available on the DWallet.
	 *
	 * @param params.dWallet - The Shared DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSign({
		dWallet,
		verifiedPresignCap,
		presign,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: SharedDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Universal requestFutureSign method implementation that automatically detects DWallet type and share availability.
	 * This method intelligently routes to the appropriate future signing implementation.
	 * Only supports ZeroTrust and Shared DWallets. For Imported Key DWallets, use requestFutureSignWithImportedKey instead.
	 *
	 * @param params.dWallet - The DWallet to create the future sign for (ZeroTrust or Shared DWallet)
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - Optional: encrypted user secret key share (for ZeroTrust DWallets)
	 * @param params.secretShare - Optional: unencrypted secret share (requires publicOutput, for ZeroTrust DWallets)
	 * @param params.publicOutput - Optional: public output (required when using secretShare, for ZeroTrust DWallets)
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to unverified partial user signature capability
	 *
	 * @example
	 * // ZeroTrust DWallet - Keep capability (encrypted shares)
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSign({
	 *   dWallet, // ZeroTrustDWallet
	 *   encryptedUserSecretKeyShare,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ZeroTrust DWallet
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSign({
	 *   dWallet, // ZeroTrustDWallet
	 *   secretShare,
	 *   publicOutput,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // Shared DWallet - Public share signing (no secret params needed)
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSign({
	 *   dWallet, // SharedDWallet
	 *   // ... other params (no secretShare/publicOutput needed)
	 * });
	 */
	async requestFutureSign({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet | SharedDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		secretShare?: Uint8Array;
		publicOutput?: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		// Auto-detect share availability
		const hasPublicShares = !!dWallet.public_user_secret_key_share;

		let unverifiedPartialUserSignatureCap: TransactionObjectArgument;

		// Auto-detect signing method based on available shares and parameters
		if (encryptedUserSecretKeyShare) {
			// Encrypted shares
			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					encryptedUserSecretKeyShare,
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (secretShare && publicOutput) {
			// Secret share provided
			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					secretShare,
					publicOutput,
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (hasPublicShares) {
			// Public shares available on DWallet
			this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);
			this.#assertDWalletPublicOutputSet(dWallet);

			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					// No need to verify public output in public user-share flows, as there is no zero-trust security in this model.
					publicOutput: Uint8Array.from(dWallet.state.Active?.public_output),
					secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else {
			throw new Error(
				'DWallet future signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
			);
		}

		return unverifiedPartialUserSignatureCap;
	}

	/**
	 * Request a future sign operation with encrypted shares for Imported Key DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 *
	 * @param params.dWallet - The Imported Key DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - The user's encrypted secret key share
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSignWithImportedKey({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ImportedKeyDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Request a future sign operation with secret shares for Imported Key DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 *
	 * SECURITY WARNING: This method does not verify `secretShare` and `publicOutput`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * @param params.dWallet - The Imported Key DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.secretShare - The user's unencrypted secret share
	 * @param params.publicOutput - The user's public output
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSignWithImportedKey({
		dWallet,
		verifiedPresignCap,
		presign,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ImportedKeyDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		secretShare: Uint8Array;
		publicOutput: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Request a future sign operation with public shares for ImportedShared DWallets and keep capability.
	 * This creates a partial user signature capability that is returned with the transaction.
	 * No secret share or public output parameters are needed as they are available on the DWallet.
	 *
	 * @param params.dWallet - The ImportedShared DWallet to create the future sign for
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the unverified partial user signature capability
	 */
	async requestFutureSignWithImportedKey({
		dWallet,
		verifiedPresignCap,
		presign,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ImportedSharedDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument>;

	/**
	 * Universal requestFutureSignWithImportedKey method implementation that automatically detects the Imported Key DWallet type and signing method.
	 * This method intelligently routes to the appropriate future signing implementation for Imported Key DWallets.
	 *
	 * @param params.dWallet - The Imported Key DWallet to create the future sign for (type and share availability auto-detected)
	 * @param params.verifiedPresignCap - The verified presign capability
	 * @param params.presign - The completed presign object
	 * @param params.encryptedUserSecretKeyShare - Optional: encrypted user secret key share (for ImportedKeyDWallet)
	 * @param params.secretShare - Optional: unencrypted secret share (requires publicOutput, for ImportedKeyDWallet)
	 * @param params.publicOutput - Optional: public output (required when using secretShare, for ImportedKeyDWallet)
	 * @param params.message - The message bytes to pre-sign
	 * @param params.hashScheme - The hash scheme to use for the message
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to unverified partial user signature capability
	 *
	 * @example
	 * // ImportedKeyDWallet - Keep capability (encrypted shares)
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSignWithImportedKey({
	 *   dWallet, // ImportedKeyDWallet
	 *   encryptedUserSecretKeyShare,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ImportedKeyDWallet
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSignWithImportedKey({
	 *   dWallet, // ImportedKeyDWallet
	 *   secretShare,
	 *   publicOutput,
	 *   // ... other params
	 * });
	 *
	 * @example
	 * // ImportedSharedDWallet - Public share signing (no secret params needed)
	 * const unverifiedPartialUserSignatureCap = await tx.requestFutureSignWithImportedKey({
	 *   dWallet, // ImportedSharedDWallet
	 *   // ... other params (no secretShare/publicOutput needed)
	 * });
	 */
	async requestFutureSignWithImportedKey({
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ImportedKeyDWallet | ImportedSharedDWallet;
		verifiedPresignCap: TransactionObjectArgument;
		presign: Presign;
		encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
		secretShare?: Uint8Array;
		publicOutput?: Uint8Array;
		message: Uint8Array;
		hashScheme: Hash;
		signatureScheme: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<TransactionObjectArgument> {
		// Auto-detect share availability
		const hasPublicShares = !!dWallet.public_user_secret_key_share;

		let unverifiedPartialUserSignatureCap: TransactionObjectArgument;

		// Auto-detect signing method based on available shares and parameters
		if (encryptedUserSecretKeyShare) {
			// Encrypted shares
			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					encryptedUserSecretKeyShare,
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (secretShare && publicOutput) {
			// Secret share provided
			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					secretShare,
					publicOutput,
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else if (hasPublicShares) {
			// Public shares available on DWallet
			this.#assertDWalletPublicUserSecretKeyShareSet(dWallet);

			unverifiedPartialUserSignatureCap = await this.#requestFutureSign({
				verifiedPresignCap,
				userSignatureInputs: {
					activeDWallet: dWallet,
					presign,
					message,
					hash: hashScheme,
					signatureScheme,
				},
				ikaCoin,
				suiCoin,
			});
		} else {
			throw new Error(
				'Imported Key DWallet future signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
			);
		}

		return unverifiedPartialUserSignatureCap;
	}

	/**
	 * Complete a future sign operation using a previously created partial user signature.
	 * This method takes a partial signature created earlier and combines it with message approval to create a full signature.
	 *
	 * @param params.partialUserSignatureCap - The partial user signature capability created by requestFutureSign
	 * @param params.messageApproval - The message approval from approveMessage
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The signature ID
	 */
	futureSign({
		partialUserSignatureCap,
		messageApproval,
		ikaCoin,
		suiCoin,
	}: {
		partialUserSignatureCap: TransactionObjectArgument | string;
		messageApproval: TransactionObjectArgument;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		return coordinatorTx.requestSignWithPartialUserSignatureAndReturnId(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			coordinatorTx.verifyPartialUserSignatureCap(
				this.#ikaClient.ikaConfig,
				this.#getCoordinatorObjectRef(),
				this.#transaction.object(partialUserSignatureCap),
				this.#transaction,
			),
			messageApproval,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	/**
	 * Complete a future sign operation for imported key using a previously created partial user signature.
	 * This method takes a partial signature created earlier and combines it with imported key message approval to create a full signature.
	 *
	 * @param params.partialUserSignatureCap - The partial user signature capability created by requestFutureSignWithImportedKey
	 * @param params.importedKeyMessageApproval - The imported key message approval from approveImportedKeyMessage
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The signature ID
	 */
	futureSignWithImportedKey({
		partialUserSignatureCap,
		importedKeyMessageApproval,
		ikaCoin,
		suiCoin,
	}: {
		partialUserSignatureCap: TransactionObjectArgument | string;
		importedKeyMessageApproval: TransactionObjectArgument | string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		return coordinatorTx.requestImportedKeySignWithPartialUserSignatureAndReturnId(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			partialUserSignatureCap,
			importedKeyMessageApproval,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.#transaction,
		);
	}

	/**
	 * Request verification for an Imported Key DWallet key and keep the capability.
	 * This method creates a DWallet from an existing cryptographic key that was generated outside the network.
	 *
	 * @param params.importDWalletVerificationRequestInput - The prepared verification data from prepareImportedKeyDWalletVerification
	 * @param params.curve - The elliptic curve identifier used for the imported key
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.sessionIdentifier - Unique session identifier for this operation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to imported key DWallet capability
	 */
	async requestImportedKeyDWalletVerification({
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
	}): Promise<TransactionObjectArgument> {
		const importedKeyDWalletVerificationCap = await this.#requestImportedKeyDwalletVerification({
			importDWalletVerificationRequestInput,
			curve,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		});

		return importedKeyDWalletVerificationCap;
	}

	/**
	 * Transfer an encrypted user share from the current user to another address using encrypted shares.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 * The encrypted share is automatically decrypted internally.
	 *
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationEncryptionKeyAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 */
	async requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		destinationEncryptionKeyAddress: string;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<IkaTransaction>;

	/**
	 * Transfer an encrypted user share from the current user to another address using unencrypted secret shares.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 *
	 * SECURITY WARNING: This method does not verify `sourceSecretShare`,
	 * which must be verified by the caller in order to guarantee zero-trust security.
	 *
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationEncryptionKeyAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceSecretShare - The current user's unencrypted secret share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 */
	async requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceSecretShare,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		destinationEncryptionKeyAddress: string;
		sourceSecretShare: Uint8Array;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<IkaTransaction>;

	/**
	 * Universal transferUserShare method implementation.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 * When sourceSecretShare is provided, it's used directly; otherwise, the encrypted share is decrypted automatically.
	 *
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationEncryptionKeyAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.sourceSecretShare - Optional: The current user's unencrypted secret share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		sourceSecretShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
		destinationEncryptionKeyAddress: string;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		sourceSecretShare?: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<IkaTransaction> {
		let finalSourceSecretShare: Uint8Array;

		if (sourceSecretShare) {
			// Use provided secret share directly
			finalSourceSecretShare = sourceSecretShare;
		} else {
			// Decrypt the encrypted share automatically
			if (!this.#userShareEncryptionKeys) {
				throw new Error('User share encryption keys are not set');
			}

			const { secretShare: decryptedSecretShare } =
				await this.#userShareEncryptionKeys.decryptUserShare(
					dWallet,
					sourceEncryptedUserSecretKeyShare,
					await this.#ikaClient.getProtocolPublicParameters(dWallet),
				);
			finalSourceSecretShare = decryptedSecretShare;
		}

		await this.#requestReEncryptUserShareFor({
			dWallet,
			destinationEncryptionKeyAddress,
			sourceEncryptedUserSecretKeyShare,
			sourceSecretShare: finalSourceSecretShare,
			ikaCoin,
			suiCoin,
		});

		return this;
	}

	/**
	 * Create a unique session identifier for the current transaction and register it with the coordinator.
	 *
	 * @returns The session identifier transaction object argument
	 */
	createSessionIdentifier() {
		return this.registerSessionIdentifier(createRandomSessionIdentifier());
	}

	/**
	 * Register a unique session identifier for the current transaction.
	 *
	 * @returns The session identifier transaction object argument
	 */
	registerSessionIdentifier(sessionIdentifier: Uint8Array) {
		return coordinatorTx.registerSessionIdentifier(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			sessionIdentifier,
			this.#transaction,
		);
	}

	/**
	 * Check if a DWallet with the specified ID exists in the coordinator.
	 * This is useful for validating DWallet existence before performing operations.
	 *
	 * @param params.dwalletId - The ID of the DWallet to check
	 * @returns Transaction result indicating whether the DWallet exists (returns a boolean)
	 */
	hasDWallet({ dwalletId }: { dwalletId: string }): TransactionObjectArgument {
		return coordinatorTx.hasDWallet(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dwalletId,
			this.#transaction,
		);
	}

	/**
	 * Get a reference to a DWallet object from the coordinator.
	 * This returns an immutable reference to the DWallet that can be used in the same transaction.
	 *
	 * @param params.dwalletId - The ID of the DWallet to retrieve
	 * @returns Transaction result containing a reference to the DWallet object
	 */
	getDWallet({ dwalletId }: { dwalletId: string }): TransactionObjectArgument {
		return coordinatorTx.getDWallet(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dwalletId,
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

	#requestGlobalPresign({
		dwalletNetworkEncryptionKeyId,
		curve,
		signatureAlgorithm,
		ikaCoin,
		suiCoin,
	}: {
		dwalletNetworkEncryptionKeyId: string;
		curve: Curve;
		signatureAlgorithm: SignatureAlgorithm;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		return coordinatorTx.requestGlobalPresign(
			this.#ikaClient.ikaConfig,
			this.#getCoordinatorObjectRef(),
			dwalletNetworkEncryptionKeyId,
			curve,
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

		const publicParameters = await this.#ikaClient.getProtocolPublicParameters(
			userSignatureInputs.activeDWallet,
			userSignatureInputs.curve,
		);

		let secretShare, publicOutput;

		if (userSignatureInputs.activeDWallet) {
			// If the dWallet is a public user-share dWallet, we use the public user secret key share. It is a different trust assumption in which no zero-trust security is assured.
			// Otherwise, we use the secret share from the user signature inputs.
			if (
				userSignatureInputs.activeDWallet.public_user_secret_key_share &&
				userSignatureInputs.activeDWallet.state.Active?.public_output
			) {
				secretShare = Uint8Array.from(
					userSignatureInputs.activeDWallet.public_user_secret_key_share,
				);
				publicOutput = Uint8Array.from(
					userSignatureInputs.activeDWallet.state.Active?.public_output,
				);
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
		} else {
			if (!userSignatureInputs.secretShare || !userSignatureInputs.publicOutput) {
				throw new Error(
					'Secret share and public output are required when activeDWallet is not set',
				);
			}

			secretShare = userSignatureInputs.secretShare;
			publicOutput = userSignatureInputs.publicOutput;

			if (userSignatureInputs.curve === undefined) {
				await this.#verifySecretShare({
					verifiedPublicOutput: publicOutput,
					secretShare,
					publicParameters,
				});
			}
		}

		return this.#createUserSignMessageWithPublicOutput({
			protocolPublicParameters: publicParameters,
			publicOutput,
			userSecretKeyShare: secretShare,
			presign: userSignatureInputs.presign.state.Completed?.presign,
			message: userSignatureInputs.message,
			hash: userSignatureInputs.hash,
			signatureScheme: userSignatureInputs.signatureScheme,
			curve: userSignatureInputs.curve,
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
	}): Promise<TransactionObjectArgument> {
		const userSignMessage = await this.#getUserSignMessage({
			userSignatureInputs,
		});

		return coordinatorTx.requestSignAndReturnId(
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
		if (!userSignatureInputs.activeDWallet) {
			throw new Error('Active DWallet is required');
		}

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
	}): Promise<TransactionObjectArgument> {
		const userSignMessage = await this.#getUserSignMessage({
			userSignatureInputs,
		});

		return coordinatorTx.requestImportedKeySignAndReturnId(
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
			await encryptSecretShare(
				destinationEncryptionKeyObj.curve as Curve,
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
		signatureScheme,
		curve,
	}: {
		protocolPublicParameters: Uint8Array;
		publicOutput: Uint8Array;
		userSecretKeyShare: Uint8Array;
		presign: Uint8Array;
		message: Uint8Array;
		hash: Hash;
		signatureScheme: SignatureAlgorithm;
		curve?: Curve;
	}): Promise<Uint8Array> {
		if (curve !== undefined) {
			return new Uint8Array(
				await create_sign_with_centralized_output(
					protocolPublicParameters,
					publicOutput,
					userSecretKeyShare,
					presign,
					message,
					hash,
					signatureScheme,
				),
			);
		} else {
			return new Uint8Array(
				await create_sign(
					protocolPublicParameters,
					publicOutput,
					userSecretKeyShare,
					presign,
					message,
					hash,
					signatureScheme,
				),
			);
		}
	}
}
