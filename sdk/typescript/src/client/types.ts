import { SuiClient } from '@mysten/sui/client';

import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner';
import * as SystemInnerModule from '../generated/ika_system/system_inner';

export interface IkaPackageConfig {
	ikaPackage: string;
	ikaCommonPackage: string;
	ikaDwallet2pcMpcPackage: string;
	ikaSystemPackage: string;
}

export interface IkaObjectsConfig {
	ikaSystemObject: {
		objectID: string;
		initialSharedVersion: number;
	};
	ikaDWalletCoordinator: {
		objectID: string;
		initialSharedVersion: number;
	};
}

export interface IkaConfig {
	packages: IkaPackageConfig;
	objects: IkaObjectsConfig;
}

export interface IkaClientOptions {
	config: IkaConfig;
	suiClient: SuiClient;
	timeout?: number;
	publicParameters?: {
		decryptionKeyPublicOutputID: string;
		epoch: number;
		publicParameters: Uint8Array;
	};
	cache?: boolean;
}

export interface Coordinator {
	fields: {
		id: {
			id: string;
		};
		migration_epoch: null;
		new_package_id: null;
		package_id: string;
		version: string;
	};
}

export interface System extends Coordinator {}

export interface DWalletNetworkDecryptionKey {
	fields: {
		id: { id: string };
		network_dkg_public_output: MoveObject<{
			contents: {
				fields: {
					id: { id: string };
				};
			};
		}>;
	};
}

export interface MoveObject<TFields> {
	fields: TFields;
}

export interface MoveDynamicField {
	fields: {
		name: string;
		value: Uint8Array;
	};
}

export interface StartDKGFirstRoundEvent {
	event_data: {
		dwallet_id: string;
		dwallet_cap_id: string;
		dwallet_network_encryption_key_id: string;
	};
	session_identifier_preimage: Uint8Array;
}

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;
export type DWallet = typeof CoordinatorInnerModule.DWallet.$inferType;
export type DWalletCap = typeof CoordinatorInnerModule.DWalletCap.$inferType;
