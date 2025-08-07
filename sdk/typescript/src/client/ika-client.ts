import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/dist/cjs/transactions';
import { toHex } from '@mysten/sui/dist/cjs/utils';

import * as CoordinatorModule from '../generated/ika_dwallet_2pc_mpc/coordinator';
import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner';
import * as SystemModule from '../generated/ika_system/system';
import * as SystemInnerModule from '../generated/ika_system/system_inner';
import { getActiveEncryptionKey as getActiveEncryptionKeyFromCoordinator } from '../tx/coordinator';
import { InvalidObjectError, NetworkError, ObjectNotFoundError } from './errors';
import {
	CoordinatorInner,
	DWallet,
	DWalletCap,
	EncryptedUserSecretKeyShare,
	EncryptionKey,
	IkaClientOptions,
	IkaConfig,
	PartialUserSignature,
	Presign,
	SharedObjectOwner,
	SystemInner,
} from './types';
import { objResToBcs } from './utils';

/**
 * IkaClient provides a high-level interface for interacting with the Ika network.
 * It handles network configuration, object fetching, caching, and provides methods
 * for retrieving DWallets, presigns, and other network objects.
 */
export class IkaClient {
	/** The Ika network configuration including package IDs and object references */
	public ikaConfig: IkaConfig;

	/** The underlying Sui client for blockchain interactions */
	private client: SuiClient;
	/** Whether to enable caching of network objects and parameters */
	private cache: boolean;
	/** Cached network public parameters to avoid repeated fetching */
	private cachedPublicParameters?: {
		decryptionKeyPublicOutputID: string;
		epoch: number;
		publicParameters: Uint8Array;
	};
	/** Cached network objects (coordinator and system inner objects) */
	private cachedObjects?: {
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
		decryptionKeyID: string;
	};
	/** Promise for ongoing object fetching to prevent duplicate requests */
	private objectsPromise?: Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
		decryptionKeyID: string;
	}>;

	/**
	 * Creates a new IkaClient instance
	 *
	 * @param options - Configuration options for the client
	 * @param options.suiClient - The Sui client instance to use for blockchain interactions
	 * @param options.config - The Ika network configuration
	 * @param options.publicParameters - Optional cached public parameters
	 * @param options.cache - Whether to enable caching (default: true)
	 */
	constructor({ suiClient, config, publicParameters, cache = true }: IkaClientOptions) {
		this.client = suiClient;
		this.ikaConfig = config;
		this.cachedPublicParameters = publicParameters;
		this.cache = cache;
	}

	/**
	 * Invalidate all cached data including objects and public parameters.
	 * This forces the client to refetch data on the next request.
	 */
	invalidateCache(): void {
		this.cachedObjects = undefined;
		this.cachedPublicParameters = undefined;
		this.objectsPromise = undefined;
	}

	/**
	 * Invalidate only the cached objects (coordinator and system inner objects).
	 * Public parameters cache is preserved.
	 */
	invalidateObjectCache(): void {
		this.cachedObjects = undefined;
		this.objectsPromise = undefined;
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
	private async ensureInitialized(): Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
		decryptionKeyID: string;
	}> {
		if (!this.cache) {
			return this.getObjects();
		}

		if (this.cachedObjects) {
			return this.cachedObjects;
		}

		if (this.objectsPromise) {
			await this.objectsPromise;
			return this.cachedObjects!;
		}

		await this.getObjects();
		return this.cachedObjects!;
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
				return CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj));
			});
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
				return objs.map((obj) => CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj)));
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
				StructType: `${this.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator_inner::DWalletCap`,
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
	 * Retrieve the network's public parameters used for cryptographic operations.
	 * These parameters are cached and only refetched when the epoch or decryption key changes.
	 *
	 * @returns Promise resolving to the network public parameters as bytes
	 * @throws {ObjectNotFoundError} If the public parameters cannot be found
	 * @throws {NetworkError} If the network request fails
	 */
	async getNetworkPublicParameters(): Promise<Uint8Array> {
		await this.ensureInitialized();

		const decryptionKeyPublicOutputID = await this.getDecryptionKeyPublicOutputID();
		const epoch = await this.getEpoch();

		if (this.cachedPublicParameters) {
			if (
				this.cachedPublicParameters.decryptionKeyPublicOutputID === decryptionKeyPublicOutputID &&
				this.cachedPublicParameters.epoch === epoch
			) {
				return this.cachedPublicParameters.publicParameters;
			}
		}

		const publicParameters = await this.readTableVecAsRawBytes(decryptionKeyPublicOutputID);

		this.cachedPublicParameters = {
			decryptionKeyPublicOutputID,
			epoch,
			publicParameters,
		};

		return publicParameters;
	}

	/**
	 * Get the current network decryption key ID.
	 *
	 * @returns Promise resolving to the decryption key ID
	 * @throws {NetworkError} If the network objects cannot be fetched
	 */
	async getDecryptionKeyID(): Promise<string> {
		const objects = await this.ensureInitialized();
		return objects.decryptionKeyID;
	}

	/**
	 * Get the public output ID for the current network decryption key.
	 * This ID is used to fetch the network's public parameters.
	 *
	 * @returns Promise resolving to the decryption key public output ID
	 * @throws {InvalidObjectError} If the decryption key object cannot be parsed
	 * @throws {NetworkError} If the network request fails
	 */
	async getDecryptionKeyPublicOutputID(): Promise<string> {
		const objects = await this.ensureInitialized();

		try {
			const decryptionKeyID = objects.decryptionKeyID;

			const decryptionKey = await this.client.getObject({
				id: decryptionKeyID,
				options: { showBcs: true },
			});

			const decryptionKeyParsed = CoordinatorInnerModule.DWalletNetworkEncryptionKey.fromBase64(
				objResToBcs(decryptionKey),
			);

			return decryptionKeyParsed.network_dkg_public_output.contents.id.id;
		} catch (error) {
			if (error instanceof InvalidObjectError) {
				throw error;
			}

			throw new NetworkError('Failed to get decryption key public output ID', error as Error);
		}
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
		getActiveEncryptionKeyFromCoordinator(this.ikaConfig, address, tx);

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
		return +objects.coordinatorInner.current_epoch;
	}

	/**
	 * Get the core network objects (coordinator inner, system inner, and decryption key ID).
	 * Uses caching to avoid redundant network requests.
	 *
	 * @returns Promise resolving to the core network objects
	 * @throws {NetworkError} If the network request fails
	 * @private
	 */
	private async getObjects() {
		if (this.cachedObjects) {
			return {
				coordinatorInner: this.cachedObjects.coordinatorInner,
				systemInner: this.cachedObjects.systemInner,
				decryptionKeyID: this.cachedObjects.decryptionKeyID,
			};
		}

		if (this.objectsPromise) {
			return this.objectsPromise;
		}

		this.objectsPromise = this.fetchObjectsFromNetwork();

		try {
			const result = await this.objectsPromise;
			this.cachedObjects = {
				coordinatorInner: result.coordinatorInner,
				systemInner: result.systemInner,
				decryptionKeyID: result.decryptionKeyID,
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
	private async fetchObjectsFromNetwork() {
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

			const systemInnerID = systemDFs.data[systemDFs.data.length - 1].name.value as string;
			const coordinatorInnerID = coordinatorDFs.data[+coordinatorParsed.version].name
				.value as string;

			const [systemInner, coordinatorInner] = await this.client.multiGetObjects({
				ids: [systemInnerID, coordinatorInnerID],
				options: { showContent: true },
			});

			const systemInnerParsed = SystemInnerModule.SystemInner.fromBase64(objResToBcs(systemInner));
			const coordinatorInnerParsed = CoordinatorInnerModule.DWalletCoordinatorInner.fromBase64(
				objResToBcs(coordinatorInner),
			);

			const keysDFs = await this.client.getDynamicFields({
				parentId: coordinatorInnerParsed.dwallet_network_encryption_keys.id.id,
			});

			if (!keysDFs.data?.length) {
				throw new ObjectNotFoundError('Network encryption keys');
			}

			const decryptionKeyID = keysDFs.data[keysDFs.data.length - 1].name.value as string;

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
				decryptionKeyID,
			};
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch objects', error as Error);
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
	private async readTableVecAsRawBytes(tableID: string): Promise<Uint8Array> {
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
			} while (cursor);

			const data: Uint8Array[] = [];

			const objectIds = allTableRows.map((tableRowResult) => tableRowResult.objectId);

			await this.processBatchedObjects(objectIds, (dynField) => {
				// TODO(fesal): Find a way to get DF type
				// @ts-expect-error Find a way to get DF type
				const tableIndex = parseInt(dynamicFieldData.fields.name);
				if (isNaN(tableIndex)) {
					throw new InvalidObjectError(
						'Table index (expected numeric name)',
						dynField.data?.objectId,
					);
				}

				// TODO(fesal): Find a way to get DF type
				// @ts-expect-error Find a way to get DF type
				data[tableIndex] = dynamicFieldData.fields.value;
			});

			return new Uint8Array(data.flatMap((arr) => Array.from(arr)));
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
	private async processBatchedObjects(
		objectIds: string[],
		processor: (dynField: any) => void,
	): Promise<void> {
		const batchSize = 50;

		try {
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
					processor(dynField);
				}
			}
		} catch (error) {
			if (error instanceof NetworkError || error instanceof InvalidObjectError) {
				throw error;
			}
			throw new NetworkError('Failed to process batched objects', error as Error);
		}
	}
}
