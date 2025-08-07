import { verify_user_share } from '@dwallet-network/dwallet-mpc-wasm';
import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import * as coordinatorTx from '../tx/coordinator';
import {
	createSignCentralizedOutput,
	encryptSecretShare,
	PreparedImportDWalletVerification,
	PreparedSecondRound,
} from './cryptography';
import { IkaClient } from './ika-client';
import {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	Hash,
	PartialUserSignature,
	Presign,
	SignatureAlgorithm,
} from './types';
import { UserShareEncrytionKeys } from './user-share-encryption-keys';

/**
 * Parameters for creating an IkaTransaction instance
 */
export type IkaTransactionParams = {
	/** The IkaClient instance to use for blockchain interactions */
	ikaClient: IkaClient;
	/** The Sui transaction to wrap */
	transaction: Transaction;
	/** Optional user share encryption keys for cryptographic operations */
	userShareEncryptionKeys?: UserShareEncrytionKeys;
};

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
		curve: number;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		const dwalletCap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
	 * Request the DKG (Distributed Key Generation) first round with explicit decryption key ID.
	 * This initiates the creation of a new DWallet through a distributed key generation process.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.decryptionKeyID - The specific decryption key ID to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Object containing the DWallet capability and updated transaction
	 */
	requestDWalletDKGFirstRound({
		curve,
		decryptionKeyID,
		ikaCoin,
		suiCoin,
	}: {
		curve: Curve;
		decryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): {
		dwalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	} {
		const dwalletCap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
	async requestDWalletDKGFirstRoundAndKeepAsync({
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
		const cap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
	 * Request the DKG first round and transfer the DWalletCap to a specified receiver.
	 * This method requires an explicit decryption key ID.
	 *
	 * @param params - The parameters for the DKG first round
	 * @param params.curve - The elliptic curve identifier to use for key generation
	 * @param params.decryptionKeyID - The specific decryption key ID to use
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the DWalletCap
	 * @returns The updated IkaTransaction instance
	 */
	requestDWalletDKGFirstRoundAndKeep({
		curve,
		decryptionKeyID,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		curve: Curve;
		decryptionKeyID: string;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		const cap = coordinatorTx.requestDWalletDKGFirstRound(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
	 * Request the DKG (Distributed Key Generation) second round to complete DWallet creation.
	 * This finalizes the distributed key generation process started in the first round.
	 *
	 * @param params - The parameters for the DKG second round
	 * @param params.dWallet - The DWallet object from the first round
	 * @param params.preparedSecondRound - Cryptographic data prepared for the second round
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns The updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
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
			this.getCoordinatorObjectRef(),
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
			this.userShareEncryptionKeys.getPublicKeyBytes(),
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
	presign({
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
		const unverifiedPresignCap = coordinatorTx.requestPresign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
	presignAndKeep({
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
		const unverifiedPresignCap = coordinatorTx.requestPresign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
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
			presign.id.id,
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
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		if (!dWallet.state.Active?.public_output) {
			throw new Error('DWallet is not active');
		}

		const userShare = await this.userShareEncryptionKeys.decryptUserShare(
			dWallet,
			encryptedUserSecretKeyShare,
			await this.ikaClient.getNetworkPublicParameters(),
		);

		const userShareVerified = verify_user_share(
			userShare,
			Uint8Array.from(dWallet.state.Active?.public_output),
			await this.ikaClient.getNetworkPublicParameters(),
		);

		if (!userShareVerified) {
			throw new Error('User share verification failed');
		}

		coordinatorTx.requestSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			messageApproval,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				userShare,
				Uint8Array.from(presign.state.Completed.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		if (!dWallet.public_user_secret_key_share) {
			throw new Error('User share must be public to use this method');
		}

		coordinatorTx.requestSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			messageApproval,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				Uint8Array.from(dWallet.public_user_secret_key_share),
				Uint8Array.from(presign.state.Completed?.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		const unverifiedPartialUserSignatureCap = coordinatorTx.requestFutureSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			verifiedPresignCap,
			message,
			hashScheme,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				await this.userShareEncryptionKeys.decryptUserShare(
					dWallet,
					encryptedUserSecretKeyShare,
					await this.ikaClient.getNetworkPublicParameters(),
				),
				Uint8Array.from(presign.state.Completed?.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
	async requestFutureSignAndKeep({
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
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		const unverifiedPartialUserSignatureCap = coordinatorTx.requestFutureSign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			verifiedPresignCap,
			message,
			hashScheme,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				await this.userShareEncryptionKeys.decryptUserShare(
					dWallet,
					encryptedUserSecretKeyShare,
					await this.ikaClient.getNetworkPublicParameters(),
				),
				Uint8Array.from(presign.state.Completed?.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
	 * @param params.preparedImportDWalletVerification - The prepared verification data from prepareImportDWalletVerification
	 * @param params.curve - The elliptic curve identifier used for the imported key
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.sessionIdentifier - Unique session identifier for this operation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to an object containing the imported key DWallet capability and updated transaction
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestImportedDWalletVerification({
		preparedImportDWalletVerification,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
	}: {
		preparedImportDWalletVerification: PreparedImportDWalletVerification;
		curve: Curve;
		signerPublicKey: Uint8Array;
		sessionIdentifier: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}): Promise<{
		ImportedKeyDWalletCap: TransactionObjectArgument;
		transaction: IkaTransaction;
	}> {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const importedKeyDWalletVerificationCap = coordinatorTx.requestImportedKeyDwalletVerification(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			preparedImportDWalletVerification.outgoing_message,
			preparedImportDWalletVerification.encryptedUserShareAndProof,
			this.userShareEncryptionKeys.getSuiAddress(),
			preparedImportDWalletVerification.public_output,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
	 * @param params.preparedImportDWalletVerification - The prepared verification data from prepareImportDWalletVerification
	 * @param params.curve - The elliptic curve identifier used for the imported key
	 * @param params.signerPublicKey - The public key of the transaction signer
	 * @param params.sessionIdentifier - Unique session identifier for this operation
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @param params.receiver - The address that will receive the imported key DWallet capability
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async requestImportedDWalletVerificationAndKeep({
		preparedImportDWalletVerification,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
		receiver,
	}: {
		preparedImportDWalletVerification: PreparedImportDWalletVerification;
		curve: Curve;
		signerPublicKey: Uint8Array;
		sessionIdentifier: Uint8Array;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
		receiver: string;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const importedKeyDWalletVerificationCap = coordinatorTx.requestImportedKeyDwalletVerification(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			await this.ikaClient.getDecryptionKeyID(),
			curve,
			preparedImportDWalletVerification.outgoing_message,
			preparedImportDWalletVerification.encryptedUserShareAndProof,
			this.userShareEncryptionKeys.getSuiAddress(),
			preparedImportDWalletVerification.public_output,
			signerPublicKey,
			sessionIdentifier,
			ikaCoin,
			suiCoin,
			this.transaction,
		);

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
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		coordinatorTx.requestImportedKeySign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			importedKeyMessageApproval,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				await this.userShareEncryptionKeys.decryptUserShare(
					dWallet,
					encryptedUserSecretKeyShare,
					await this.ikaClient.getNetworkPublicParameters(),
				),
				Uint8Array.from(presign.state.Completed?.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
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
	 * @throws {Error} If user share encryption keys are not set, presign is not completed, or DWallet public output is not set
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
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		if (!presign.state.Completed?.presign) {
			throw new Error('Presign is not completed');
		}

		if (!dWallet.public_user_secret_key_share) {
			throw new Error('DWallet public output is not set');
		}

		coordinatorTx.requestImportedKeySign(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			verifiedPresignCap,
			importedKeyMessageApproval,
			createSignCentralizedOutput(
				await this.ikaClient.getNetworkPublicParameters(),
				dWallet,
				Uint8Array.from(dWallet.public_user_secret_key_share),
				Uint8Array.from(presign.state.Completed?.presign),
				message,
				hashScheme,
			),
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);
	}

	/**
	 * Transfer an encrypted user share from the current user to another address.
	 * This re-encrypts the user's share with the destination address's encryption key.
	 *
	 * @param params - The parameters for transferring encrypted user share
	 * @param params.dWallet - The DWallet whose user share is being transferred
	 * @param params.destinationSuiAddress - The Sui address that will receive the re-encrypted share
	 * @param params.sourceEncryptedUserSecretKeyShare - The current user's encrypted secret key share
	 * @param params.ikaCoin - The IKA coin object to use for transaction fees
	 * @param params.suiCoin - The SUI coin object to use for gas fees
	 * @returns Promise resolving to the updated IkaTransaction instance
	 * @throws {Error} If user share encryption keys are not set
	 */
	async transferEncryptedUserShare({
		dWallet,
		destinationSuiAddress,
		sourceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	}: {
		dWallet: DWallet;
		destinationSuiAddress: string;
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
		ikaCoin: TransactionObjectArgument;
		suiCoin: TransactionObjectArgument;
	}) {
		if (!this.userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const publicParameters = await this.ikaClient.getNetworkPublicParameters();

		const destinationEncryptionKeyObj =
			await this.ikaClient.getActiveEncryptionKey(destinationSuiAddress);

		coordinatorTx.requestReEncryptUserShareFor(
			this.ikaClient.ikaConfig,
			this.getCoordinatorObjectRef(),
			dWallet.id.id,
			destinationSuiAddress,
			encryptSecretShare(
				await this.userShareEncryptionKeys.decryptUserShare(
					dWallet,
					sourceEncryptedUserSecretKeyShare,
					publicParameters,
				),
				new Uint8Array(destinationEncryptionKeyObj.encryption_key),
				publicParameters,
			),
			sourceEncryptedUserSecretKeyShare.id.id,
			this.createSessionIdentifier(),
			ikaCoin,
			suiCoin,
			this.transaction,
		);

		return this;
	}

	/**
	 * Create a unique session identifier for the current transaction.
	 * This generates a fresh address and converts it to bytes for use as a session identifier.
	 *
	 * @returns The session identifier transaction object argument
	 * @private
	 */
	createSessionIdentifier() {
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
			this.getCoordinatorObjectRef(),
			freshObjectAddressBytes,
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
}
