// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { BcsType } from '@mysten/sui/bcs';
import { bcs, BcsStruct } from '@mysten/sui/bcs';
import type { SuiClient } from '@mysten/sui/client';

import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SystemInnerModule from '../generated/ika_system/system_inner.js';

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

/**
 * Represents a network encryption key with its metadata
 */
export interface NetworkEncryptionKey {
	/** The unique identifier of the encryption key */
	id: string;
	/** The epoch when this encryption key was created */
	epoch: number;
	/** The public output ID for this encryption key */
	publicOutputID: string;
}

/**
 * Options for encryption key selection in protocol public parameters
 */
export interface EncryptionKeyOptions {
	/** Specific encryption key ID to use */
	encryptionKeyID?: string;
	/** Whether to automatically detect the encryption key from the dWallet */
	autoDetect?: boolean;
}

export interface IkaClientOptions {
	config: IkaConfig;
	suiClient: SuiClient;
	timeout?: number;
	protocolPublicParameters?: {
		networkEncryptionKeyPublicOutputID: string;
		epoch: number;
		protocolPublicParameters: Uint8Array;
	};
	cache?: boolean;
	network: Network;
	/** Default encryption key options for the client */
	encryptionKeyOptions?: EncryptionKeyOptions;
}

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;

export const DWalletKind = {
	ZeroTrust: 'zero-trust',
	Imported: 'imported',
	ImportedShared: 'imported-shared',
	Shared: 'shared',
} as const;

export type DWalletKind = (typeof DWalletKind)[keyof typeof DWalletKind];

export type DWalletInternal = typeof CoordinatorInnerModule.DWallet.$inferType;

export type ZeroTrustDWallet = DWalletInternal & {
	kind: 'zero-trust';
};

export type ImportedDWallet = DWalletInternal & {
	kind: 'imported';
};

export type ImportedSharedDWallet = DWalletInternal & {
	kind: 'imported-shared';
};

export type SharedDWallet = DWalletInternal & {
	kind: 'shared';
};

export type DWallet = ZeroTrustDWallet | ImportedDWallet | ImportedSharedDWallet | SharedDWallet;

export type DWalletCap = typeof CoordinatorInnerModule.DWalletCap.$inferType;
export type Presign = typeof CoordinatorInnerModule.PresignSession.$inferType;
export type EncryptedUserSecretKeyShare =
	typeof CoordinatorInnerModule.EncryptedUserSecretKeyShare.$inferType;
export type PartialUserSignature = typeof CoordinatorInnerModule.PartialUserSignature.$inferType;
export type EncryptionKey = typeof CoordinatorInnerModule.EncryptionKey.$inferType;
export type DWalletState = typeof CoordinatorInnerModule.DWalletState.$inferType.$kind;
export type PresignState = typeof CoordinatorInnerModule.PresignState.$inferType.$kind;
export type PartialUserSignatureState =
	typeof CoordinatorInnerModule.PartialUserSignatureState.$inferType.$kind;
export type EncryptedUserSecretKeyShareState =
	typeof CoordinatorInnerModule.EncryptedUserSecretKeyShareState.$inferType.$kind;

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

export interface SharedObjectOwner {
	Shared: {
		initial_shared_version: number;
	};
}

export function DynamicField<E extends BcsType<any>>(...typeParameters: [E]) {
	return new BcsStruct({
		name: `dynamic_field::Field<u64, ${typeParameters[0].name as E['name']}>`,
		fields: {
			id: bcs.Address,
			name: bcs.u64(),
			value: typeParameters[0],
		},
	});
}

export const CoordinatorInnerDynamicField = DynamicField(
	CoordinatorInnerModule.DWalletCoordinatorInner,
);

export const SystemInnerDynamicField = DynamicField(SystemInnerModule.SystemInner);

export type UserSignatureInputs = {
	activeDWallet: DWallet;
	publicOutput?: Uint8Array;
	secretShare?: Uint8Array;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	presign: Presign;
	message: Uint8Array;
	hash: Hash;
};
