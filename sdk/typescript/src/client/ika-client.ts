import { SuiClient } from '@mysten/sui/client';

import { InvalidObjectError, NetworkError, ObjectNotFoundError } from './errors';
import {
	isCoordinator,
	isCoordinatorInner,
	isDWalletNetworkDecryptionKey,
	isMoveDynamicField,
	isMoveObject,
	isSystem,
	isSystemInner,
	validateObject,
} from './type-guards';
import { CoordinatorInner, IkaClientOptions, IkaConfig, SystemInner } from './types';

export class IkaClient {
	public ikaConfig: IkaConfig;

	private client: SuiClient;
	private cache: boolean;
	private cachedPublicParameters?: {
		decryptionKeyPublicOutputID: string;
		epoch: number;
		publicParameters: Uint8Array;
	};
	private cachedObjects?: {
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
		decryptionKeyID: string;
	};
	private objectsPromise?: Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
		decryptionKeyID: string;
	}>;

	constructor({ suiClient, config, publicParameters, cache = true }: IkaClientOptions) {
		this.client = suiClient;
		this.ikaConfig = config;
		this.cachedPublicParameters = publicParameters;
		this.cache = cache;
	}

	invalidateCache(): void {
		this.cachedObjects = undefined;
		this.cachedPublicParameters = undefined;
		this.objectsPromise = undefined;
	}

	invalidateObjectCache(): void {
		this.cachedObjects = undefined;
		this.objectsPromise = undefined;
	}

	async initialize(): Promise<void> {
		await this.ensureInitialized();
	}

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

	async getDecryptionKeyID(): Promise<string> {
		const objects = await this.ensureInitialized();
		return objects.decryptionKeyID;
	}

	async getDecryptionKeyPublicOutputID(): Promise<string> {
		const objects = await this.ensureInitialized();

		try {
			const decryptionKeyID = objects.decryptionKeyID;

			const decryptionKey = await this.client.getObject({
				id: decryptionKeyID,
				options: { showContent: true },
			});

			if (!decryptionKey || !isMoveObject(decryptionKey?.data?.content)) {
				throw new InvalidObjectError('DWallet Network Decryption Key', decryptionKeyID);
			}

			const decryptionKeyData = validateObject(
				decryptionKey.data.content,
				isDWalletNetworkDecryptionKey,
				'DWallet Network Decryption Key',
				decryptionKeyID,
			);

			if (!isMoveObject(decryptionKeyData.fields.network_dkg_public_output)) {
				throw new InvalidObjectError('Network DKG Public Output', decryptionKeyID);
			}

			return decryptionKeyData.fields.network_dkg_public_output.fields.contents.fields.id
				.id as string;
		} catch (error) {
			if (error instanceof InvalidObjectError) {
				throw error;
			}

			throw new NetworkError('Failed to get decryption key public output ID', error as Error);
		}
	}

	async getEpoch(): Promise<number> {
		const objects = await this.ensureInitialized();
		return objects.coordinatorInner.fields.value.fields.current_epoch;
	}

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

	private async fetchObjectsFromNetwork() {
		try {
			const [coordinator, system] = await this.client.multiGetObjects({
				ids: [
					this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
					this.ikaConfig.objects.ikaSystemObject.objectID,
				],
				options: { showContent: true },
			});

			const coordinatorData = validateObject(
				coordinator.data?.content,
				isCoordinator,
				'Coordinator',
				this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
			);

			const systemData = validateObject(
				system.data?.content,
				isSystem,
				'System',
				this.ikaConfig.objects.ikaSystemObject.objectID,
			);

			const [coordinatorDFs, systemDFs] = await Promise.all([
				this.client.getDynamicFields({
					parentId: coordinatorData.fields.id.id,
				}),
				this.client.getDynamicFields({
					parentId: systemData.fields.id.id,
				}),
			]);

			if (!coordinatorDFs.data?.length || !systemDFs.data?.length) {
				throw new ObjectNotFoundError('Dynamic fields for coordinator or system');
			}

			const systemInnerID = systemDFs.data[systemDFs.data.length - 1].name.value as string;
			const coordinatorInnerID = coordinatorDFs.data[+coordinatorData.fields.version].name
				.value as string;

			const [systemInner, coordinatorInner] = await this.client.multiGetObjects({
				ids: [systemInnerID, coordinatorInnerID],
				options: { showContent: true },
			});

			const systemInnerData = validateObject(
				systemInner.data?.content,
				isSystemInner,
				'SystemInner',
				systemInnerID,
			);

			const coordinatorInnerData = validateObject(
				coordinatorInner.data?.content,
				isCoordinatorInner,
				'CoordinatorInner',
				coordinatorInnerID,
			);

			const keysDFs = await this.client.getDynamicFields({
				parentId:
					coordinatorInnerData.fields.value.fields.dwallet_network_encryption_keys.fields.id.id,
			});

			if (!keysDFs.data?.length) {
				throw new ObjectNotFoundError('Network encryption keys');
			}

			const decryptionKeyID = keysDFs.data[keysDFs.data.length - 1].name.value as string;

			this.ikaConfig.packages.ikaSystemPackage = systemData.fields.package_id;
			this.ikaConfig.packages.ikaDwallet2pcMpcPackage = coordinatorData.fields.package_id;

			return {
				coordinatorInner: coordinatorInnerData,
				systemInner: systemInnerData,
				decryptionKeyID,
			};
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch objects', error as Error);
		}
	}

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
				if (!isMoveObject(dynField.data?.content)) {
					throw new InvalidObjectError('Move object', dynField.data?.objectId);
				}

				const dynamicFieldData = validateObject(
					dynField.data.content,
					isMoveDynamicField,
					'Move dynamic field',
					dynField.data?.objectId,
				);

				const tableIndex = parseInt(dynamicFieldData.fields.name);
				if (isNaN(tableIndex)) {
					throw new InvalidObjectError(
						'Table index (expected numeric name)',
						dynField.data?.objectId,
					);
				}

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
