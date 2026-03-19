// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { BcsType } from '@mysten/sui/bcs';
import { bcs, BcsStruct } from '@mysten/sui/bcs';
import type { ClientWithCoreApi } from '@mysten/sui/client';

import type { Curve, DWalletKind, EncryptionKeyOptions, Hash, SignatureAlgorithm } from '@ika.xyz/core';

import * as CoordinatorInnerModule from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as SystemInnerModule from '../generated/ika_system/system_inner.js';

export interface IkaPackageConfig {
	ikaPackage: string;
	ikaCommonPackage: string;
	ikaSystemOriginalPackage: string;
	ikaDwallet2pcMpcOriginalPackage: string;
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

export type Network = 'testnet' | 'mainnet';

export interface IkaClientOptions {
	config: IkaConfig;
	suiClient: ClientWithCoreApi;
	timeout?: number;
	protocolPublicParameters?: {
		networkEncryptionKeyPublicOutputID: string;
		epoch: number;
		protocolPublicParameters: Uint8Array;
	};
	cache?: boolean;
	/** Default encryption key options for the client */
	encryptionKeyOptions?: EncryptionKeyOptions;
}

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;

export type DWalletInternal = typeof CoordinatorInnerModule.DWallet.$inferType;

export type ZeroTrustDWallet = DWalletInternal & {
	kind: 'zero-trust';
};

export type ImportedKeyDWallet = DWalletInternal & {
	kind: 'imported-key';
};

export type ImportedSharedDWallet = DWalletInternal & {
	kind: 'imported-key-shared';
};

export type SharedDWallet = DWalletInternal & {
	kind: 'shared';
};

export type DWallet = ZeroTrustDWallet | ImportedKeyDWallet | ImportedSharedDWallet | SharedDWallet;

export type DWalletCap = typeof CoordinatorInnerModule.DWalletCap.$inferType;
export type Presign = typeof CoordinatorInnerModule.PresignSession.$inferType;
export type EncryptedUserSecretKeyShare =
	typeof CoordinatorInnerModule.EncryptedUserSecretKeyShare.$inferType;
export type PartialUserSignature = typeof CoordinatorInnerModule.PartialUserSignature.$inferType;
export type Sign = typeof CoordinatorInnerModule.SignSession.$inferType;
export type EncryptionKey = typeof CoordinatorInnerModule.EncryptionKey.$inferType;
export type DWalletState = typeof CoordinatorInnerModule.DWalletState.$inferType.$kind;
export type PresignState = typeof CoordinatorInnerModule.PresignState.$inferType.$kind;
export type PartialUserSignatureState =
	typeof CoordinatorInnerModule.PartialUserSignatureState.$inferType.$kind;
export type EncryptedUserSecretKeyShareState =
	typeof CoordinatorInnerModule.EncryptedUserSecretKeyShareState.$inferType.$kind;
export type SignState = typeof CoordinatorInnerModule.SignState.$inferType.$kind;

/** Narrow DWallet to a specific state */
export type DWalletWithState<S extends DWalletState> = Omit<DWalletInternal, 'state' | 'kind'> & {
	state: Extract<typeof CoordinatorInnerModule.DWalletState.$inferType, { $kind: S }>;
	kind: DWalletKind;
};

/** Narrow Presign to a specific state */
export type PresignWithState<S extends PresignState> = Omit<Presign, 'state'> & {
	state: Extract<typeof CoordinatorInnerModule.PresignState.$inferType, { $kind: S }>;
};

/** Narrow EncryptedUserSecretKeyShare to a specific state */
export type EncryptedUserSecretKeyShareWithState<S extends EncryptedUserSecretKeyShareState> = Omit<
	EncryptedUserSecretKeyShare,
	'state'
> & {
	state: Extract<
		typeof CoordinatorInnerModule.EncryptedUserSecretKeyShareState.$inferType,
		{ $kind: S }
	>;
};

/** Narrow PartialUserSignature to a specific state */
export type PartialUserSignatureWithState<S extends PartialUserSignatureState> = Omit<
	PartialUserSignature,
	'state'
> & {
	state: Extract<typeof CoordinatorInnerModule.PartialUserSignatureState.$inferType, { $kind: S }>;
};

/** Narrow Sign to a specific state */
export type SignWithState<S extends SignState> = Omit<Sign, 'state'> & {
	state: Extract<typeof CoordinatorInnerModule.SignState.$inferType, { $kind: S }>;
};

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
	activeDWallet?: DWallet;
	publicOutput?: Uint8Array;
	secretShare?: Uint8Array;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	presign: Presign;
	message: Uint8Array;
	hash: Hash;
	signatureScheme: SignatureAlgorithm;
	curve: Curve;
	createWithCentralizedOutput?: boolean;
};
