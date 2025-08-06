import { SuiClient } from '@mysten/sui/client';

import * as CoordinatorModule from '../generated/ika_dwallet_2pc_mpc/coordinator';
import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner';
import * as SystemModule from '../generated/ika_system/system';
import * as SystemInnerModule from '../generated/ika_system/system_inner';
import { InvalidObjectError, NetworkError, ObjectNotFoundError } from './errors';
import {
	CoordinatorInner,
	DWallet,
	DWalletCap,
	EncryptedUserSecretKeyShare,
	IkaClientOptions,
	IkaConfig,
	PartialUserSignature,
	Presign,
	SystemInner,
} from './types';
import { objResToBcs } from './utils';

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

	async getDWallet(dwalletID: string): Promise<DWallet> {
		return this.client
			.getObject({
				id: dwalletID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj));
			});
	}

	async getPresign(presignID: string): Promise<Presign> {
		return this.client
			.getObject({
				id: presignID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PresignSession.fromBase64(objResToBcs(obj));
			});
	}

	async getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareID: string,
	): Promise<EncryptedUserSecretKeyShare> {
		return this.client
			.getObject({
				id: encryptedUserSecretKeyShareID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.EncryptedUserSecretKeyShare.fromBase64(objResToBcs(obj));
			});
	}

	async getPartialUserSignature(
		partialCentralizedSignedMessageID: string,
	): Promise<PartialUserSignature> {
		return this.client
			.getObject({
				id: partialCentralizedSignedMessageID,
				options: { showBcs: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PartialUserSignature.fromBase64(objResToBcs(obj));
			});
	}

	async getMultipleDWallets(dwalletIDs: string[]): Promise<DWallet[]> {
		return this.client
			.multiGetObjects({
				ids: dwalletIDs,
				options: { showBcs: true },
			})
			.then((objs) => {
				return objs.map((obj) => CoordinatorInnerModule.DWallet.fromBase64(objResToBcs(obj)));
			});
	}

	async getOwnedDWalletCaps(
		address: string,
		cursor?: string,
		limit?: number,
	): Promise<{
		dWalletCaps: DWalletCap[];
		cursor: string | null | undefined;
		hasNextPage: boolean;
	}> {
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

	async getEpoch(): Promise<number> {
		const objects = await this.ensureInitialized();
		return +objects.coordinatorInner.current_epoch;
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
				options: { showBcs: true },
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
