// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { toHex } from '@mysten/sui/utils';

import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as CoordinatorModule from '../generated/ika_dwallet_2pc_mpc/coordinator.js';
import { TableVec } from '../generated/ika_system/deps/sui/table_vec.js';
import * as SystemModule from '../generated/ika_system/system.js';
import { getActiveEncryptionKey as getActiveEncryptionKeyFromCoordinator } from '../tx/coordinator.js';
import {
	networkDkgPublicOutputToProtocolPublicParameters,
	parseSignatureFromSignOutput,
	reconfigurationPublicOutputToProtocolPublicParameters,
} from './cryptography.js';
import { InvalidObjectError, NetworkError, ObjectNotFoundError } from './errors.js';
import { fromNumberToCurve, validateCurveSignatureAlgorithm } from './hash-signature-validation.js';
import type { ValidSignatureAlgorithmForCurve } from './hash-signature-validation.js';
import { CoordinatorInnerDynamicField, DynamicField, SystemInnerDynamicField } from './types.js';
import type {
	CoordinatorInner,
	Curve,
	DWallet,
	DWalletCap,
	DWalletInternal,
	DWalletKind,
	DWalletState,
	DWalletWithState,
	EncryptedUserSecretKeyShare,
	EncryptedUserSecretKeyShareState,
	EncryptedUserSecretKeyShareWithState,
	EncryptionKey,
	EncryptionKeyOptions,
	IkaClientOptions,
	IkaConfig,
	NetworkEncryptionKey,
	PartialUserSignature,
	PartialUserSignatureState,
	PartialUserSignatureWithState,
	Presign,
	PresignState,
	PresignWithState,
	SharedObjectOwner,
	Sign,
	SignatureAlgorithm,
	SignState,
	SignWithState,
	SystemInner,
} from './types.js';
import { fetchAllDynamicFields, objResToBcs } from './utils.js';

/**
 * IkaClient provides a high-level interface for interacting with the Ika network.
 * It handles network configuration, object fetching, caching, and provides methods
 * for retrieving DWallets, presigns, and other network objects.
 */
export class IkaClient {
	/** The Ika network configuration including package IDs and object references */
	public ikaConfig: IkaConfig;
	/** Default encryption key options for the client */
	public encryptionKeyOptions: EncryptionKeyOptions;

	/** The underlying Sui client for blockchain interactions */
	private client: SuiClient;
	/** Whether to enable caching of network objects and parameters */
	private cache: boolean;
	/** Cached network public parameters by encryption key ID and curve to avoid repeated fetching */
	private cachedProtocolPublicParameters: Map<
		string,
		{
			networkEncryptionKeyPublicOutputID: string;
			epoch: number;
			curve: Curve;
			protocolPublicParameters: Uint8Array;
		}
	> = new Map();
	/** Cached network objects (coordinator and system inner objects) - separate from encryption keys */
	private cachedObjects?: {
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
	};
	/** Cached encryption keys by ID for efficient access */
	private cachedEncryptionKeys: Map<string, NetworkEncryptionKey> = new Map();
	/** Promise for ongoing object fetching to prevent duplicate requests */
	private objectsPromise?: Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
	}>;
	/** Promise for ongoing encryption key fetching to prevent duplicate requests */
	private encryptionKeysPromise?: Promise<NetworkEncryptionKey[]>;

	/**
	 * Creates a new IkaClient instance
	 *
	 * @param options - Configuration options for the client
	 * @param options.suiClient - The Sui client instance to use for blockchain interactions
	 * @param options.config - The Ika network configuration
	 * @param options.cache - Whether to enable caching (default: true)
	 */
	constructor({ suiClient, config, cache = true, encryptionKeyOptions }: IkaClientOptions) {
		this.client = suiClient;
		this.ikaConfig = config;
		this.cache = cache;
		this.encryptionKeyOptions = encryptionKeyOptions || { autoDetect: true };
	}

	/**
	 * Invalidate all cached data including objects and public parameters.
	 * This forces the client to refetch data on the next request.
	 */
	invalidateCache(): void {
		this.cachedObjects = undefined;
		this.cachedProtocolPublicParameters.clear();
		this.objectsPromise = undefined;
		this.cachedEncryptionKeys.clear();
		this.encryptionKeysPromise = undefined;
	}

	/**
	 * Invalidate only the cached objects (coordinator and system inner objects).
	 * Public parameters and encryption key caches are preserved.
	 */
	invalidateObjectCache(): void {
		this.cachedObjects = undefined;
		this.objectsPromise = undefined;
	}

	/**
	 * Invalidate only the cached encryption keys.
	 * Network objects and public parameters caches are preserved.
	 */
	invalidateEncryptionKeyCache(): void {
		this.cachedEncryptionKeys.clear();
		this.encryptionKeysPromise = undefined;
	}

	/**
	 * Invalidate cached protocol public parameters for a specific encryption key and/or curve.
	 * If no parameters are provided, clears all cached protocol parameters.
	 * If only encryptionKeyID is provided, clears all curves for that key.
	 * If both are provided, clears only that specific combination.
	 *
	 * @param encryptionKeyID - Optional specific encryption key ID to invalidate
	 * @param curve - Optional specific curve to invalidate
	 */
	invalidateProtocolPublicParametersCache(encryptionKeyID?: string, curve?: Curve): void {
		if (encryptionKeyID !== undefined && curve !== undefined) {
			this.cachedProtocolPublicParameters.delete(this.#getCacheKey(encryptionKeyID, curve));
		} else if (encryptionKeyID !== undefined) {
			// Clear all curves for this encryption key
			for (const key of this.cachedProtocolPublicParameters.keys()) {
				if (key.startsWith(`${encryptionKeyID}-`)) {
					this.cachedProtocolPublicParameters.delete(key);
				}
			}
		} else {
			this.cachedProtocolPublicParameters.clear();
		}
	}

	/**
	 * Initialize the client by fetching and caching network objects.
	 * This method should be called before using other client methods.
	 *
	 * @returns Promise that resolves when initialization is complete
	 */
	async initialize(): Promise<void> {
		await this.ensureInitialized();
	}

	/**
	 * Ensure the client is initialized with core network objects.
	 * This method handles caching and prevents duplicate initialization requests.
	 *
	 * @returns Promise resolving to the core network objects
	 * @throws {NetworkError} If initialization fails
	 * @private
	 */
	async ensureInitialized(): Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
	}> {
		if (!this.cache) {
			return this.#getObjects();
		}

		if (this.cachedObjects) {
			return this.cachedObjects;
		}

		if (this.objectsPromise) {
			await this.objectsPromise;
			return this.cachedObjects!;
		}

		await this.#getObjects();
		return this.cachedObjects!;
	}

	/**
	 * Get all available network encryption keys.
	 * This method fetches and caches all encryption keys for efficient access.
	 *
	 * @returns Promise resolving to an array of all network encryption keys
	 * @throws {NetworkError} If the encryption keys cannot be fetched
	 */
	async getAllNetworkEncryptionKeys(): Promise<NetworkEncryptionKey[]> {
		if (!this.cache) {
			return this.#fetchEncryptionKeys();
		}

		if (this.cachedEncryptionKeys.size > 0) {
			return Array.from(this.cachedEncryptionKeys.values());
		}

		if (this.encryptionKeysPromise) {
			await this.encryptionKeysPromise;
			return Array.from(this.cachedEncryptionKeys.values());
		}

		await this.#fetchEncryptionKeys();
		return Array.from(this.cachedEncryptionKeys.values());
	}

	/**
	 * Get the latest network encryption key.
	 * This is the most recent encryption key created for the network.
	 *
	 * @returns Promise resolving to the latest network encryption key
	 * @throws {NetworkError} If the encryption keys cannot be fetched
	 */
	async getLatestNetworkEncryptionKey(): Promise<NetworkEncryptionKey> {
		const keys = await this.getAllNetworkEncryptionKeys();
		if (keys.length === 0) {
			throw new NetworkError('No network encryption keys found');
		}
		return keys[keys.length - 1];
	}

	/**
	 * Get a specific network encryption key by ID.
	 *
	 * @param encryptionKeyID - The ID of the encryption key to retrieve
	 * @returns Promise resolving to the specified network encryption key
	 * @throws {ObjectNotFoundError} If the encryption key is not found
	 * @throws {NetworkError} If the encryption keys cannot be fetched
	 */
	async getNetworkEncryptionKey(encryptionKeyID: string): Promise<NetworkEncryptionKey> {
		const keys = await this.getAllNetworkEncryptionKeys();
		const key = keys.find((k) => k.id === encryptionKeyID);
		if (!key) {
			throw new ObjectNotFoundError(`Network encryption key ${encryptionKeyID} not found`);
		}
		return key;
	}

	/**
	 * Get the network encryption key used by a specific dWallet.
	 * This method automatically detects which encryption key the dWallet uses.
	 *
	 * @param dwalletID - The ID of the dWallet to check
	 * @returns Promise resolving to the network encryption key used by the dWallet
	 * @throws {InvalidObjectError} If the dWallet cannot be parsed
	 * @throws {NetworkError} If the network request fails
	 */
	async getDWalletNetworkEncryptionKey(dwalletID: string): Promise<NetworkEncryptionKey> {
		const dWallet = await this.getDWallet(dwalletID);

		const encryptionKeyID = dWallet.dwallet_network_encryption_key_id;

		return this.getNetworkEncryptionKey(encryptionKeyID);
	}

	/**
	 * Get the network encryption key based on client configuration.
	 * This method respects the client's encryption key options.
	 *
	 * @returns Promise resolving to the appropriate network encryption key
	 * @throws {NetworkError} If the encryption keys cannot be fetched
	 */
	async getConfiguredNetworkEncryptionKey(): Promise<NetworkEncryptionKey> {
		if (this.encryptionKeyOptions.encryptionKeyID) {
			// Use specific encryption key if configured
			return this.getNetworkEncryptionKey(this.encryptionKeyOptions.encryptionKeyID);
		}

		// Default to latest encryption key
		return this.getLatestNetworkEncryptionKey();
	}

	/**
	 * Retrieve a DWallet object by its ID.
	 *
	 * @param dwalletID - The unique identifier of the DWallet to retrieve
	 * @returns Promise resolving to the DWallet object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getDWallet(dwalletID: string): Promise<DWallet> {
		await this.ensureInitialized();

		return this.client
			.getObject({
				id: dwalletID,
				options: { showBcs: true },
			})
			.then((obj) => {
				const dWallet = CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj));

				return {
					...dWallet,
					kind: this.#getDWalletKind(dWallet),
				};
			});
	}

	/**
	 * Retrieve a DWallet in a particular state, waiting until it reaches that state.
	 * This method polls the DWallet until it matches the specified state.
	 *
	 * @param dwalletID - The unique identifier of the DWallet to retrieve
	 * @param state - The target state to wait for
	 * @param options - Optional configuration for polling behavior
	 * @param options.timeout - Maximum time to wait in milliseconds (default: 30000)
	 * @param options.interval - Initial polling interval in milliseconds (default: 1000)
	 * @param options.maxInterval - Maximum polling interval with exponential backoff (default: 5000)
	 * @param options.backoffMultiplier - Multiplier for exponential backoff (default: 1.5)
	 * @param options.signal - AbortSignal to cancel the polling
	 * @returns Promise resolving to the DWallet object when it reaches the target state
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 * @throws {Error} If timeout is reached before the target state is achieved or operation is aborted
	 */
	async getDWalletInParticularState<S extends DWalletState>(
		dwalletID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<DWalletWithState<S>>;
	async getDWalletInParticularState(
		dwalletID: string,
		state: DWalletState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<DWallet> {
		return this.#pollUntilState(
			() => this.getDWallet(dwalletID),
			state,
			`DWallet ${dwalletID} to reach state ${state}`,
			options,
		) as Promise<DWallet>;
	}

	/**
	 * Retrieve a presign session object by its ID.
	 *
	 * @param presignID - The unique identifier of the presign session to retrieve
	 * @returns Promise resolving to the Presign object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getPresign(presignID: string): Promise<Presign> {
		await this.ensureInitialized();

		return this.client
			.getObject({
				id: presignID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PresignSession.fromBase64(objResToBcs(obj));
			});
	}

	/**
	 * Retrieve a presign session object in a particular state, waiting until it reaches that state.
	 * This method polls the presign until it matches the specified state.
	 *
	 * @param presignID - The unique identifier of the presign session to retrieve
	 * @param state - The target state to wait for
	 * @param options - Optional configuration for polling behavior
	 * @param options.timeout - Maximum time to wait in milliseconds (default: 30000)
	 * @param options.interval - Initial polling interval in milliseconds (default: 1000)
	 * @param options.maxInterval - Maximum polling interval with exponential backoff (default: 5000)
	 * @param options.backoffMultiplier - Multiplier for exponential backoff (default: 1.5)
	 * @param options.signal - AbortSignal to cancel the polling
	 * @returns Promise resolving to the Presign object when it reaches the target state
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 * @throws {Error} If timeout is reached before the target state is achieved or operation is aborted
	 */
	async getPresignInParticularState<S extends PresignState>(
		presignID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<PresignWithState<S>>;
	async getPresignInParticularState(
		presignID: string,
		state: PresignState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<Presign> {
		return this.#pollUntilState(
			() => this.getPresign(presignID),
			state,
			`presign ${presignID} to reach state ${state}`,
			options,
		) as Promise<Presign>;
	}

	/**
	 * Retrieve an encrypted user secret key share object by its ID.
	 *
	 * @param encryptedUserSecretKeyShareID - The unique identifier of the encrypted share to retrieve
	 * @returns Promise resolving to the EncryptedUserSecretKeyShare object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareID: string,
	): Promise<EncryptedUserSecretKeyShare> {
		await this.ensureInitialized();

		return this.client
			.getObject({
				id: encryptedUserSecretKeyShareID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.EncryptedUserSecretKeyShare.fromBase64(objResToBcs(obj));
			});
	}

	/**
	 * Retrieve an encrypted user secret key share object by its ID.
	 *
	 * @param encryptedUserSecretKeyShareID - The unique identifier of the encrypted share to retrieve
	 * @param state - The target state to wait for
	 * @param options - Optional configuration for polling behavior
	 * @param options.timeout - Maximum time to wait in milliseconds (default: 30000)
	 * @param options.interval - Initial polling interval in milliseconds (default: 1000)
	 * @param options.maxInterval - Maximum polling interval with exponential backoff (default: 5000)
	 * @param options.backoffMultiplier - Multiplier for exponential backoff (default: 1.5)
	 * @param options.signal - AbortSignal to cancel the polling
	 * @returns Promise resolving to the EncryptedUserSecretKeyShare object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 * @throws {Error} If timeout is reached before the target state is achieved or operation is aborted
	 */
	async getEncryptedUserSecretKeyShareInParticularState<S extends EncryptedUserSecretKeyShareState>(
		encryptedUserSecretKeyShareID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<EncryptedUserSecretKeyShareWithState<S>>;
	async getEncryptedUserSecretKeyShareInParticularState(
		encryptedUserSecretKeyShareID: string,
		state: EncryptedUserSecretKeyShareState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<EncryptedUserSecretKeyShare> {
		return this.#pollUntilState(
			() => this.getEncryptedUserSecretKeyShare(encryptedUserSecretKeyShareID),
			state,
			`encrypted user secret key share ${encryptedUserSecretKeyShareID} to reach state ${state}`,
			options,
		) as Promise<EncryptedUserSecretKeyShare>;
	}

	/**
	 * Retrieve a partial user signature object by its ID.
	 *
	 * @param partialCentralizedSignedMessageID - The unique identifier of the partial signature to retrieve
	 * @returns Promise resolving to the PartialUserSignature object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getPartialUserSignature(
		partialCentralizedSignedMessageID: string,
	): Promise<PartialUserSignature> {
		await this.ensureInitialized();

		return this.client
			.getObject({
				id: partialCentralizedSignedMessageID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PartialUserSignature.fromBase64(objResToBcs(obj));
			});
	}

	async getPartialUserSignatureInParticularState<S extends PartialUserSignatureState>(
		partialCentralizedSignedMessageID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<PartialUserSignatureWithState<S>>;
	async getPartialUserSignatureInParticularState(
		partialCentralizedSignedMessageID: string,
		state: PartialUserSignatureState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<PartialUserSignature> {
		return this.#pollUntilState(
			() => this.getPartialUserSignature(partialCentralizedSignedMessageID),
			state,
			`partial user signature ${partialCentralizedSignedMessageID} to reach state ${state}`,
			options,
		) as Promise<PartialUserSignature>;
	}

	/**
	 * Retrieve a sign session object by its ID.
	 *
	 * @param signID - The unique identifier of the sign session to retrieve
	 * @param curve - The curve to use for parsing
	 * @param signatureAlgorithm - The signature algorithm to use for parsing (must be valid for the curve)
	 *
	 * @returns Promise resolving to the Sign object
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getSign<C extends Curve>(
		signID: string,
		curve: C,
		signatureAlgorithm: ValidSignatureAlgorithmForCurve<C>,
	): Promise<Sign> {
		await this.ensureInitialized();

		validateCurveSignatureAlgorithm(curve, signatureAlgorithm);

		const unparsedSign = await this.client.getObject({
			id: signID,
			options: { showBcs: true },
		});

		const sign = CoordinatorInnerModule.SignSession.fromBase64(objResToBcs(unparsedSign));

		if (sign.state.$kind === 'Completed') {
			sign.state.Completed.signature = Array.from(
				await parseSignatureFromSignOutput(
					curve,
					signatureAlgorithm,
					Uint8Array.from(sign.state.Completed.signature),
				),
			);
		}

		return sign;
	}

	/**
	 * Retrieve a sign session object in a particular state, waiting until it reaches that state.
	 * This method polls the sign until it matches the specified state.
	 *
	 * @param signID - The unique identifier of the sign session to retrieve
	 * @param curve - The curve to use for parsing
	 * @param signatureAlgorithm - The signature algorithm to use for parsing (must be valid for the curve)
	 * @param state - The target state to wait for
	 * @param options - Optional configuration for polling behavior
	 * @param options.timeout - Maximum time to wait in milliseconds (default: 30000)
	 * @param options.interval - Initial polling interval in milliseconds (default: 1000)
	 * @param options.maxInterval - Maximum polling interval with exponential backoff (default: 5000)
	 * @param options.backoffMultiplier - Multiplier for exponential backoff (default: 1.5)
	 * @param options.signal - AbortSignal to cancel the polling
	 * @returns Promise resolving to the Sign object when it reaches the target state
	 * @throws {InvalidObjectError} If the object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 * @throws {Error} If timeout is reached before the target state is achieved or operation is aborted
	 */
	async getSignInParticularState<S extends SignState>(
		signID: string,
		curve: Curve,
		signatureAlgorithm: SignatureAlgorithm,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<SignWithState<S>>;
	async getSignInParticularState(
		signID: string,
		curve: Curve,
		signatureAlgorithm: SignatureAlgorithm,
		state: SignState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<Sign> {
		return this.#pollUntilState(
			() => this.getSign(signID, curve, signatureAlgorithm),
			state,
			`sign ${signID} to reach state ${state}`,
			options,
		) as Promise<Sign>;
	}

	/**
	 * Retrieve multiple DWallet objects by their IDs in a single batch request.
	 * This is more efficient than making individual requests for multiple DWallets.
	 *
	 * @param dwalletIDs - Array of unique identifiers for the DWallets to retrieve
	 * @returns Promise resolving to an array of DWallet objects
	 * @throws {InvalidObjectError} If any object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getMultipleDWallets(dwalletIDs: string[]): Promise<DWallet[]> {
		await this.ensureInitialized();

		return this.client
			.multiGetObjects({
				ids: dwalletIDs,
				options: { showBcs: true },
			})
			.then((objs) => {
				return objs.map((obj) => {
					const dWallet = CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj));

					return {
						...dWallet,
						kind: this.#getDWalletKind(dWallet),
					};
				});
			});
	}

	/**
	 * Retrieve DWallet capabilities owned by a specific address.
	 * DWallet capabilities grant the holder permission to use the associated DWallet.
	 *
	 * @param address - The Sui address to query for owned DWallet capabilities
	 * @param cursor - Optional cursor for pagination (from previous request)
	 * @param limit - Optional limit on the number of results to return
	 * @returns Promise resolving to paginated results containing DWallet capabilities
	 * @throws {InvalidObjectError} If any object cannot be parsed or is invalid
	 * @throws {NetworkError} If the network request fails
	 */
	async getOwnedDWalletCaps(
		address: string,
		cursor?: string,
		limit?: number,
	): Promise<{
		dWalletCaps: DWalletCap[];
		cursor: string | null | undefined;
		hasNextPage: boolean;
	}> {
		await this.ensureInitialized();

		const response = await this.client.getOwnedObjects({
			owner: address,
			filter: {
				StructType: `${this.ikaConfig.packages.ikaDwallet2pcMpcOriginalPackage}::coordinator_inner::DWalletCap`,
			},
			options: {
				showBcs: true,
			},
			cursor,
			limit,
		});

		return {
			dWalletCaps: response.data.map((obj) =>
				CoordinatorInnerModule.DWalletCap.fromBase64(objResToBcs(obj)),
			),
			cursor: response.nextCursor,
			hasNextPage: response.hasNextPage,
		};
	}

	/**
	 * Get cached protocol public parameters for a specific encryption key and curve.
	 * Returns undefined if not cached or if the cache is invalid.
	 *
	 * @param encryptionKeyID - The ID of the encryption key to get cached parameters for
	 * @param curve - The curve to get cached parameters for
	 * @returns Cached protocol public parameters or undefined if not cached
	 */
	getCachedProtocolPublicParameters(encryptionKeyID: string, curve: Curve): Uint8Array | undefined {
		const cacheKey = this.#getCacheKey(encryptionKeyID, curve);
		const cachedParams = this.cachedProtocolPublicParameters.get(cacheKey);
		if (!cachedParams) {
			return undefined;
		}

		// Get the current encryption key to check if cache is still valid
		const currentKey = this.cachedEncryptionKeys.get(encryptionKeyID);
		if (!currentKey) {
			// Key not in cache, cache is invalid
			return undefined;
		}

		// Check if the cached parameters match the current key state and curve
		if (
			cachedParams.networkEncryptionKeyPublicOutputID === currentKey.networkDKGOutputID &&
			cachedParams.epoch === currentKey.epoch &&
			cachedParams.curve === curve
		) {
			return cachedParams.protocolPublicParameters;
		}

		// Cache is invalid, remove it
		this.cachedProtocolPublicParameters.delete(cacheKey);
		return undefined;
	}

	/**
	 * Check if protocol public parameters are cached for a specific encryption key and curve.
	 *
	 * @param encryptionKeyID - The ID of the encryption key to check
	 * @param curve - The curve to check
	 * @returns True if valid cached parameters exist, false otherwise
	 */
	isProtocolPublicParametersCached(encryptionKeyID: string, curve: Curve): boolean {
		return this.getCachedProtocolPublicParameters(encryptionKeyID, curve) !== undefined;
	}

	/**
	 * Get the current encryption key options for the client.
	 *
	 * @returns The current encryption key options
	 */
	getEncryptionKeyOptions(): EncryptionKeyOptions {
		return { ...this.encryptionKeyOptions };
	}

	/**
	 * Set the encryption key options for the client.
	 * This affects all subsequent calls to methods that use encryption keys.
	 *
	 * @param options - The new encryption key options
	 */
	setEncryptionKeyOptions(options: EncryptionKeyOptions): void {
		this.encryptionKeyOptions = { ...options };
	}

	/**
	 * Set a specific encryption key ID to use for all operations.
	 * This is a convenience method for setting just the encryption key ID.
	 *
	 * @param encryptionKeyID - The encryption key ID to use
	 */
	setEncryptionKeyID(encryptionKeyID: string): void {
		this.encryptionKeyOptions = { ...this.encryptionKeyOptions, encryptionKeyID };
	}

	/**
	 * Retrieve the protocol public parameters used for cryptographic operations.
	 * These parameters are cached by encryption key ID and only refetched when the epoch or decryption key changes.
	 *
	 * @param dWallet - The DWallet to get the protocol public parameters for
	 * @param curve - The curve to use for key generation
	 * @returns Promise resolving to the protocol public parameters as bytes
	 * @throws {ObjectNotFoundError} If the public parameters cannot be found
	 * @throws {NetworkError} If the network request fails
	 */
	async getProtocolPublicParameters(dWallet?: DWallet, curve?: Curve): Promise<Uint8Array> {
		await this.#fetchEncryptionKeysFromNetwork();

		let networkEncryptionKey: NetworkEncryptionKey;

		if (dWallet) {
			networkEncryptionKey = await this.getDWalletNetworkEncryptionKey(dWallet.id.id);
		} else {
			// Use client's configured encryption key options
			networkEncryptionKey = await this.getConfiguredNetworkEncryptionKey();
		}

		const encryptionKeyID = networkEncryptionKey.id;
		const networkEncryptionKeyPublicOutputID = networkEncryptionKey.networkDKGOutputID;
		const epoch = networkEncryptionKey.epoch;

		let selectedCurve: Curve;

		if (dWallet) {
			selectedCurve = fromNumberToCurve(dWallet.curve);
		} else {
			selectedCurve = curve !== undefined ? curve : fromNumberToCurve(0);
		}

		// Check if we have cached parameters for this specific encryption key and curve
		const cacheKey = this.#getCacheKey(encryptionKeyID, selectedCurve);
		const cachedParams = this.cachedProtocolPublicParameters.get(cacheKey);
		if (cachedParams) {
			if (
				cachedParams.networkEncryptionKeyPublicOutputID === networkEncryptionKeyPublicOutputID &&
				cachedParams.epoch === epoch &&
				cachedParams.curve === selectedCurve
			) {
				return cachedParams.protocolPublicParameters;
			}
		}

		const protocolPublicParameters = !networkEncryptionKey.reconfigurationOutputID
			? await networkDkgPublicOutputToProtocolPublicParameters(
					selectedCurve,
					await this.readTableVecAsRawBytes(networkEncryptionKeyPublicOutputID),
				)
			: await reconfigurationPublicOutputToProtocolPublicParameters(
					selectedCurve,
					await this.readTableVecAsRawBytes(networkEncryptionKey.reconfigurationOutputID),
					await this.readTableVecAsRawBytes(networkEncryptionKeyPublicOutputID),
				);

		// Cache the parameters by encryption key ID and curve
		this.cachedProtocolPublicParameters.set(cacheKey, {
			networkEncryptionKeyPublicOutputID,
			epoch,
			curve: selectedCurve,
			protocolPublicParameters,
		});

		return protocolPublicParameters;
	}

	/**
	 * Get the active encryption key for a specific address.
	 * This key is used for encrypting user shares and other cryptographic operations.
	 *
	 * @param address - The Sui address to get the encryption key for
	 * @returns Promise resolving to the EncryptionKey object
	 * @throws {InvalidObjectError} If the encryption key object cannot be parsed
	 * @throws {NetworkError} If the network request fails
	 */
	async getActiveEncryptionKey(address: string): Promise<EncryptionKey> {
		await this.ensureInitialized();

		const tx = new Transaction();

		getActiveEncryptionKeyFromCoordinator(
			this.ikaConfig,
			tx.sharedObjectRef({
				objectId: this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion: this.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			}),
			address,
			tx,
		);

		const res = await this.client.devInspectTransactionBlock({
			sender: address,
			transactionBlock: tx,
		});

		const objIDArray = new Uint8Array(res.results?.at(0)?.returnValues?.at(0)?.at(0) as number[]);
		const objID = toHex(objIDArray);

		const obj = await this.client.getObject({
			id: objID,
			options: { showBcs: true },
		});

		return CoordinatorInnerModule.EncryptionKey.fromBase64(objResToBcs(obj));
	}

	/**
	 * Get the current network epoch number.
	 * The epoch is used for versioning and determining when to refresh cached parameters.
	 *
	 * @returns Promise resolving to the current epoch number
	 * @throws {NetworkError} If the network objects cannot be fetched
	 */
	async getEpoch(): Promise<number> {
		const objects = await this.ensureInitialized();
		return Number(objects.coordinatorInner.current_epoch);
	}

	/**
	 * Get the core network objects (coordinator inner and system inner objects).
	 * Uses caching to avoid redundant network requests.
	 *
	 * @returns Promise resolving to the core network objects
	 * @throws {NetworkError} If the network request fails
	 * @private
	 */
	async #getObjects() {
		if (this.cachedObjects) {
			return {
				coordinatorInner: this.cachedObjects.coordinatorInner,
				systemInner: this.cachedObjects.systemInner,
			};
		}

		if (this.objectsPromise) {
			return this.objectsPromise;
		}

		this.objectsPromise = this.#fetchObjectsFromNetwork();

		try {
			const result = await this.objectsPromise;
			this.cachedObjects = {
				coordinatorInner: result.coordinatorInner,
				systemInner: result.systemInner,
			};
			return result;
		} catch (error) {
			this.objectsPromise = undefined;
			throw error;
		}
	}

	/**
	 * Fetch core network objects from the blockchain.
	 * This method retrieves coordinator and system objects along with their dynamic fields.
	 *
	 * @returns Promise resolving to the fetched network objects
	 * @throws {ObjectNotFoundError} If required objects or dynamic fields are not found
	 * @throws {InvalidObjectError} If objects cannot be parsed
	 * @throws {NetworkError} If network requests fail
	 * @private
	 */
	async #fetchObjectsFromNetwork() {
		try {
			const [coordinator, system] = await this.client.multiGetObjects({
				ids: [
					this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
					this.ikaConfig.objects.ikaSystemObject.objectID,
				],
				options: { showBcs: true, showOwner: true },
			});

			const coordinatorParsed = CoordinatorModule.DWalletCoordinator.fromBase64(
				objResToBcs(coordinator),
			);
			const systemParsed = SystemModule.System.fromBase64(objResToBcs(system));

			const [coordinatorDFs, systemDFs] = await Promise.all([
				this.client.getDynamicFields({
					parentId: coordinatorParsed.id.id,
				}),
				this.client.getDynamicFields({
					parentId: systemParsed.id.id,
				}),
			]);

			if (!coordinatorDFs.data?.length || !systemDFs.data?.length) {
				throw new ObjectNotFoundError('Dynamic fields for coordinator or system');
			}

			const coordinatorInnerDF = coordinatorDFs.data[coordinatorDFs.data.length - 1];
			const systemInnerDF = systemDFs.data[systemDFs.data.length - 1];

			const [coordinatorInner, systemInner] = await this.client.multiGetObjects({
				ids: [coordinatorInnerDF.objectId, systemInnerDF.objectId],
				options: { showBcs: true },
			});

			const coordinatorInnerParsed = CoordinatorInnerDynamicField.fromBase64(
				objResToBcs(coordinatorInner),
			).value;

			const systemInnerParsed = SystemInnerDynamicField.fromBase64(objResToBcs(systemInner)).value;

			this.ikaConfig.packages.ikaSystemPackage = systemParsed.package_id;
			this.ikaConfig.packages.ikaDwallet2pcMpcPackage = coordinatorParsed.package_id;

			this.ikaConfig.objects.ikaSystemObject.initialSharedVersion =
				(system.data?.owner as unknown as SharedObjectOwner)?.Shared?.initial_shared_version ?? 0;
			this.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion =
				(coordinator.data?.owner as unknown as SharedObjectOwner)?.Shared?.initial_shared_version ??
				0;

			return {
				coordinatorInner: coordinatorInnerParsed,
				systemInner: systemInnerParsed,
			};
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch objects', error as Error);
		}
	}

	/**
	 * Fetch encryption keys from the network and parse them.
	 *
	 * @returns Promise resolving to the fetched encryption keys
	 * @private
	 */
	async #fetchEncryptionKeys(): Promise<NetworkEncryptionKey[]> {
		if (this.encryptionKeysPromise) {
			return this.encryptionKeysPromise;
		}

		this.encryptionKeysPromise = this.#fetchEncryptionKeysFromNetwork();

		try {
			const result = await this.encryptionKeysPromise;
			return result;
		} catch (error) {
			this.encryptionKeysPromise = undefined;
			throw error;
		}
	}

	/**
	 * Fetch encryption keys from the network and parse them.
	 *
	 * @returns Promise resolving to the fetched encryption keys
	 * @private
	 */
	async #fetchEncryptionKeysFromNetwork(): Promise<NetworkEncryptionKey[]> {
		try {
			const objects = await this.ensureInitialized();
			const keysDFs = await this.client.getDynamicFields({
				parentId: objects.coordinatorInner.dwallet_network_encryption_keys.id.id,
			});

			if (!keysDFs.data?.length) {
				throw new ObjectNotFoundError('Network encryption keys');
			}

			const encryptionKeys: NetworkEncryptionKey[] = [];

			for (const keyDF of keysDFs.data) {
				const keyName = keyDF.name.value as string;
				const keyObject = await this.client.getObject({
					id: keyDF.objectId,
					options: { showBcs: true },
				});

				const keyParsed = CoordinatorInnerModule.DWalletNetworkEncryptionKey.fromBase64(
					objResToBcs(keyObject),
				);

				const reconfigOutputsDFs = await fetchAllDynamicFields(
					this.client,
					keyParsed.reconfiguration_public_outputs.id.id,
				);

				const lastReconfigOutput = (
					await Promise.all(
						reconfigOutputsDFs.map(async (df) => {
							const name = df.name.value as string;
							const reconfigObject = await this.client.getObject({
								id: df.objectId,
								options: { showBcs: true },
							});

							const parsedValue = DynamicField(TableVec).fromBase64(objResToBcs(reconfigObject));

							return {
								name,
								parsedValue,
							};
						}),
					)
				)
					.sort((a, b) => Number(a.name) - Number(b.name))
					// The last reconfiguration has not necessarily been completed, so we take the second to last
					.at(-2);

				const encryptionKey: NetworkEncryptionKey = {
					id: keyName,
					epoch: Number(keyParsed.dkg_at_epoch),
					networkDKGOutputID: keyParsed.network_dkg_public_output.contents.id.id,
					reconfigurationOutputID: lastReconfigOutput?.parsedValue.value.contents.id.id,
				};

				encryptionKeys.push(encryptionKey);
				this.cachedEncryptionKeys.set(keyName, encryptionKey);
			}

			// Sort by epoch to ensure proper ordering
			encryptionKeys.sort((a, b) => a.epoch - b.epoch);

			return encryptionKeys;
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch encryption keys', error as Error);
		}
	}

	/**
	 * Read a table vector as raw bytes from the blockchain.
	 * This method handles paginated dynamic field retrieval and assembles the data in order.
	 *
	 * @param tableID - The ID of the table object to read
	 * @returns Promise resolving to the concatenated raw bytes from the table
	 * @throws {ObjectNotFoundError} If the table or its dynamic fields are not found
	 * @throws {InvalidObjectError} If table indices are invalid
	 * @throws {NetworkError} If network requests fail
	 * @private
	 */
	async readTableVecAsRawBytes(tableID: string): Promise<Uint8Array> {
		try {
			let cursor: string | null = null;
			const allTableRows: { objectId: string }[] = [];

			do {
				const dynamicFieldPage = await this.client.getDynamicFields({
					parentId: tableID,
					cursor,
				});

				if (!dynamicFieldPage?.data?.length) {
					if (allTableRows.length === 0) {
						throw new ObjectNotFoundError('Dynamic fields', tableID);
					}
					break;
				}

				allTableRows.push(...dynamicFieldPage.data);
				cursor = dynamicFieldPage.nextCursor;

				if (!dynamicFieldPage.hasNextPage) {
					break;
				}
			} while (cursor);

			const dataMap = new Map<number, Uint8Array>();

			const objectIds = new Set(allTableRows.map((tableRowResult) => tableRowResult.objectId));

			await this.#processBatchedObjects([...objectIds], ({ objectId, fields }) => {
				const tableIndex = parseInt(fields.name);

				if (isNaN(tableIndex)) {
					throw new InvalidObjectError('Table index (expected numeric name)', objectId);
				}

				dataMap.set(tableIndex, fields.value);
			});

			const indices = Array.from(dataMap.keys()).sort((a, b) => a - b);

			if (indices.length === 0) {
				throw new ObjectNotFoundError('No table chunks found', tableID);
			}

			const orderedChunks: Uint8Array[] = indices
				.map((idx) => dataMap.get(idx)!)
				.filter((chunk): chunk is Uint8Array => !!chunk);

			const totalLength = orderedChunks.reduce((acc, arr) => acc + arr.length, 0);
			const result = new Uint8Array(totalLength);
			let offset = 0;

			for (const chunk of orderedChunks) {
				result.set(chunk, offset);
				offset += chunk.length;
			}

			return result;
		} catch (error) {
			if (
				error instanceof InvalidObjectError ||
				error instanceof ObjectNotFoundError ||
				error instanceof NetworkError
			) {
				throw error;
			}
			throw new NetworkError(
				`Failed to read table vector as raw bytes: ${tableID}`,
				error as Error,
			);
		}
	}

	/**
	 * Process multiple objects in batches to avoid overwhelming the network.
	 * This method fetches objects in configurable batch sizes and applies a processor function to each.
	 *
	 * @param objectIds - Array of object IDs to fetch and process
	 * @param processor - Function to apply to each fetched object
	 * @returns Promise that resolves when all objects are processed
	 * @throws {NetworkError} If any network request fails or object fetching fails
	 * @throws {InvalidObjectError} If any object processing fails
	 * @private
	 */
	async #processBatchedObjects<TReturn = void>(
		objectIds: string[],
		processor: (input: {
			objectId: string;
			fields: { name: string; value: Uint8Array };
		}) => TReturn,
	): Promise<TReturn[]> {
		const batchSize = 50;

		try {
			const results: TReturn[] = [];
			for (let i = 0; i < objectIds.length; i += batchSize) {
				const batchIds = objectIds.slice(i, i + batchSize);

				const dynFields = await this.client.multiGetObjects({
					ids: batchIds,
					options: { showContent: true },
				});

				for (const dynField of dynFields) {
					if (dynField.error) {
						const errorInfo =
							'object_id' in dynField.error
								? `object ${dynField.error.object_id}`
								: 'unknown object';
						throw new NetworkError(`Failed to fetch ${errorInfo}: ${dynField.error.code}`);
					}

					const objectIdForError = dynField.data?.objectId;
					const content = dynField.data?.content;
					if (!content || content.dataType !== 'moveObject') {
						throw new InvalidObjectError('Object content (expected moveObject)', objectIdForError);
					}
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					const fields = (content as any).fields as { name?: unknown; value?: unknown } | undefined;
					if (!fields) {
						throw new InvalidObjectError('Object content.fields missing', objectIdForError);
					}
					const name = typeof fields.name === 'string' ? fields.name : String(fields.name);
					const value =
						fields.value instanceof Uint8Array
							? fields.value
							: new Uint8Array(fields.value as ArrayLike<number>);

					results.push(
						processor({
							objectId: objectIdForError ?? 'unknown',
							fields: { name, value },
						}),
					);
				}
			}
			return results;
		} catch (error) {
			if (error instanceof NetworkError || error instanceof InvalidObjectError) {
				throw error;
			}
			throw new NetworkError('Failed to process batched objects', error as Error);
		}
	}

	/**
	 * Generate a cache key for protocol public parameters based on encryption key ID and curve.
	 *
	 * @param encryptionKeyID - The encryption key ID
	 * @param curve - The curve
	 * @returns A unique cache key string
	 * @private
	 */
	#getCacheKey(encryptionKeyID: string, curve: Curve): string {
		return `${encryptionKeyID}-${curve}`;
	}

	#getDWalletKind(dWallet: DWalletInternal): DWalletKind {
		if (dWallet.is_imported_key_dwallet && dWallet.public_user_secret_key_share) {
			return 'imported-key-shared';
		}

		if (dWallet.is_imported_key_dwallet) {
			return 'imported-key';
		}

		if (dWallet.public_user_secret_key_share) {
			return 'shared';
		}

		return 'zero-trust';
	}

	/**
	 * Generic polling method that waits for an object to meet a specific condition.
	 * Implements exponential backoff and abort signal support.
	 *
	 * @param fetcher - Function that fetches the object
	 * @param condition - Function that checks if the object meets the desired condition
	 * @param errorContext - Context string for error messages (e.g., "DWallet X to reach state Y")
	 * @param options - Optional configuration for polling behavior
	 * @returns Promise resolving to the object when the condition is met
	 * @throws {Error} If timeout is reached before condition is met or operation is aborted
	 * @private
	 */
	async #pollUntilCondition<T>(
		fetcher: () => Promise<T>,
		condition: (obj: T) => boolean,
		errorContext: string,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<T> {
		await this.ensureInitialized();

		const {
			timeout = 30000,
			interval = 1000,
			maxInterval = 5000,
			backoffMultiplier = 1.5,
			signal,
		} = options;

		if (signal?.aborted) {
			throw new Error('Operation aborted');
		}

		const startTime = Date.now();
		let currentInterval = interval;
		let lastError: Error | undefined;

		while (Date.now() - startTime < timeout) {
			if (signal?.aborted) {
				throw new Error('Operation aborted');
			}

			try {
				const obj = await fetcher();

				if (condition(obj)) {
					return obj;
				}
			} catch (error) {
				lastError = error as Error;
			}

			const waitTime = currentInterval;
			await new Promise((resolve, reject) => {
				const timeoutId = setTimeout(resolve, waitTime);
				signal?.addEventListener('abort', () => {
					clearTimeout(timeoutId);
					reject(new Error('Operation aborted'));
				});
			});

			currentInterval = Math.min(currentInterval * backoffMultiplier, maxInterval);
		}

		const errorMessage = lastError
			? `Timeout waiting for ${errorContext}. Last error: ${lastError.message}`
			: `Timeout waiting for ${errorContext}`;

		throw new Error(errorMessage);
	}

	/**
	 * Specialized polling method that waits for an object to reach a specific state.
	 * This is a convenience wrapper around #pollUntilCondition for the common case of checking state.$kind.
	 *
	 * @param fetcher - Function that fetches the object
	 * @param state - The state to wait for (compared with obj.state.$kind)
	 * @param errorContext - Context string for error messages (e.g., "DWallet X to reach state Y")
	 * @param options - Optional configuration for polling behavior
	 * @returns Promise resolving to the object when it reaches the desired state
	 * @throws {Error} If timeout is reached before state is achieved or operation is aborted
	 * @private
	 */
	async #pollUntilState<T extends { state: { $kind: string } }>(
		fetcher: () => Promise<T>,
		state: string,
		errorContext: string,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<T> {
		return this.#pollUntilCondition(
			fetcher,
			(obj) => obj.state.$kind === state,
			errorContext,
			options,
		);
	}
}
