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

export type Network = 'localnet' | 'testnet' | 'mainnet';

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
	network: Network;
}

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;
export type DWallet = typeof CoordinatorInnerModule.DWallet.$inferType;
export type DWalletCap = typeof CoordinatorInnerModule.DWalletCap.$inferType;
export type Presign = typeof CoordinatorInnerModule.PresignSession.$inferType;
export type EncryptedUserSecretKeyShare =
	typeof CoordinatorInnerModule.EncryptedUserSecretKeyShare.$inferType;
export type PartialUserSignature = typeof CoordinatorInnerModule.PartialUserSignature.$inferType;

export const Hash = {
	KECCAK256: 0,
	SHA256: 1,
} as const;

export type Hash = (typeof Hash)[keyof typeof Hash];

export const Curve = {
	SECP256K1: 0,
} as const;

export type Curve = (typeof Curve)[keyof typeof Curve];

export const SignatureAlgorithm = {
	ECDSA: 0,
} as const;

export type SignatureAlgorithm = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];
