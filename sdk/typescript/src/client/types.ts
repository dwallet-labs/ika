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

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;
export type DWallet = typeof CoordinatorInnerModule.DWallet.$inferType;
export type DWalletCap = typeof CoordinatorInnerModule.DWalletCap.$inferType;
