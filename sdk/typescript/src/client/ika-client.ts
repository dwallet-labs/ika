import { SuiClient } from '@mysten/sui/client';

import { DEFAULT_TIMEOUT } from './constants';
import {
	CoordinatorInner,
	DWalletNetworkDecryptionKey,
	IkaClientOptions,
	IkaConfig,
	MoveDynamicField,
	MoveObject,
} from './types';

export class IkaClient {
	private client: SuiClient;
	private ikaConfig: IkaConfig;
	private timeout: number;
	private cachedPublicParameters?: {
		decryptionKeyPublicOutputID: string;
		epoch: number;
		publicParameters: Uint8Array;
	};

	constructor({
		suiClient,
		config,
		timeout = DEFAULT_TIMEOUT,
		publicParameters,
	}: IkaClientOptions) {
		this.client = suiClient;
		this.ikaConfig = config;
		this.timeout = timeout;
		this.cachedPublicParameters = publicParameters;
	}

	async getNetworkPublicParameters(): Promise<Uint8Array> {
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
		return this.client
			.getDynamicFields({
				parentId: this.ikaConfig.objects.ikaDWalletCoordinatorInnerKeys.objectID,
			})
			.then((res) => {
				const keysDynamicFields = res.data;
				const decryptionKeyID = keysDynamicFields[keysDynamicFields.length - 1].name
					.value as string;
				if (!decryptionKeyID) {
					throw new Error('No network decryption key found');
				}
				return decryptionKeyID;
			});
	}

	async getDecryptionKeyPublicOutputID(decryptionKeyID?: string): Promise<string> {
		decryptionKeyID = decryptionKeyID ?? (await this.getDecryptionKeyID());

		const decryptionKey = await this.client.getObject({
			id: decryptionKeyID,
			options: { showContent: true },
		});

		if (
			!decryptionKey ||
			!this.isMoveObject(decryptionKey?.data?.content) ||
			!this.isDWalletNetworkDecryptionKey(decryptionKey.data.content) ||
			!this.isMoveObject(decryptionKey.data.content.fields.network_dkg_public_output)
		) {
			throw new Error(`Invalid network decryption key object: ${decryptionKeyID}`);
		}

		return decryptionKey.data.content.fields.network_dkg_public_output.fields.contents.fields.id
			.id as string;
	}

	async getEpoch(): Promise<number> {
		const coordinatorInner = await this.getCoordinatorInner();
		return coordinatorInner.fields.value.fields.current_epoch;
	}

	private async getCoordinatorInner(): Promise<CoordinatorInner> {
		const coordinatorInner = await this.client.getObject({
			id: this.ikaConfig.objects.ikaDWalletCoordinatorInner.objectID,
			options: {
				showContent: true,
			},
		});

		if (!this.isCoordinatorInner(coordinatorInner.data?.content)) {
			throw new Error('Coordinator inner not found');
		}

		return coordinatorInner.data.content;
	}

	private isCoordinatorInner(obj: any): obj is CoordinatorInner {
		return (
			obj?.fields?.value?.fields?.dwallet_network_encryption_keys !== undefined &&
			obj?.fields?.value?.fields?.current_epoch !== undefined
		);
	}

	private isDWalletNetworkDecryptionKey(obj: any): obj is DWalletNetworkDecryptionKey {
		return (
			obj?.fields?.network_dkg_public_output?.fields?.contents?.fields?.id?.id !== undefined &&
			obj?.fields?.network_dkg_public_output?.fields?.contents?.fields?.id?.id !== null
		);
	}

	private isMoveObject<TFields>(obj: any): obj is MoveObject<TFields> {
		return obj?.fields !== undefined;
	}

	private async readTableVecAsRawBytes(tableID: string): Promise<Uint8Array> {
		let cursor: string | null = null;
		const allTableRows: { objectId: string }[] = [];

		// Fetch all dynamic fields using pagination with cursor
		do {
			const dynamicFieldPage = await this.client.getDynamicFields({
				parentId: tableID,
				cursor,
			});

			if (!dynamicFieldPage?.data?.length) {
				if (allTableRows.length === 0) {
					throw new Error('no dynamic fields found');
				}
				break;
			}

			allTableRows.push(...dynamicFieldPage.data);
			cursor = dynamicFieldPage.nextCursor;
		} while (cursor);

		const data: Uint8Array[] = [];

		// Extract object IDs for multiGetObjects
		const objectIds = allTableRows.map((tableRowResult) => tableRowResult.objectId);

		// Fetch all objects in batches
		await this.processBatchedObjects(objectIds, (dynField) => {
			if (
				!this.isMoveObject(dynField.data?.content) ||
				!this.isMoveDynamicField(dynField.data?.content)
			) {
				throw new Error('invalid dynamic field object');
			}

			const tableIndex = parseInt(dynField.data.content.fields.name);
			data[tableIndex] = dynField.data.content.fields.value;
		});

		return new Uint8Array(data.flatMap((arr) => Array.from(arr)));
	}

	private async processBatchedObjects(
		objectIds: string[],
		processor: (dynField: any) => void,
	): Promise<void> {
		const batchSize = 50; // Reasonable batch size for RPC calls

		for (let i = 0; i < objectIds.length; i += batchSize) {
			const batchIds = objectIds.slice(i, i + batchSize);

			// Fetch batch of objects
			const dynFields = await this.client.multiGetObjects({
				ids: batchIds,
				options: { showContent: true },
			});

			for (const dynField of dynFields) {
				processor(dynField);
			}
		}
	}

	private isMoveDynamicField(obj: any): obj is MoveDynamicField {
		return obj?.fields.name !== undefined || obj?.fields.value !== undefined;
	}
}
