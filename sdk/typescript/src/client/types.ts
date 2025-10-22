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

export type Network = 'testnet' | 'mainnet';

/**
 * Represents a network encryption key with its metadata
 */
export interface NetworkEncryptionKey {
	/** The unique identifier of the encryption key */
	id: string;
	/** The epoch when this encryption key was created */
	epoch: number;
	/** The public output ID for this encryption key */
	networkDKGOutputID: string;
	/** The reconfiguration output ID associated with this encryption key */
	reconfigurationOutputID: string | undefined;
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
	/** Default encryption key options for the client */
	encryptionKeyOptions?: EncryptionKeyOptions;
}

export type CoordinatorInner = typeof CoordinatorInnerModule.DWalletCoordinatorInner.$inferType;
export type SystemInner = typeof SystemInnerModule.SystemInner.$inferType;

export const DWalletKind = {
	ZeroTrust: 'zero-trust',
	ImportedKey: 'imported-key',
	ImportedKeyShared: 'imported-key-shared',
	Shared: 'shared',
} as const;

export type DWalletKind = (typeof DWalletKind)[keyof typeof DWalletKind];

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

/**
 * Hash algorithms supported by the Ika network.
 *
 * **Valid Combinations:**
 * - `KECCAK256`, `SHA256`, `DoubleSHA256`: Compatible with ECDSASecp256k1
 * - `SHA256`: Compatible with Taproot
 * - `SHA256`, `DoubleSHA256`: Compatible with ECDSASecp256r1
 * - `SHA512`: Compatible with EdDSA
 * - `Merlin`: Compatible with SchnorrkelSubstrate
 */
export const Hash = {
	/** KECCAK256 (SHA3) - Compatible with: ECDSASecp256k1 */
	KECCAK256: 0,
	/** SHA256 - Compatible with: ECDSASecp256k1, Taproot, ECDSASecp256r1 */
	SHA256: 1,
	/** Double SHA256: h(x) = sha256(sha256(x)) - Compatible with: ECDSASecp256k1, ECDSASecp256r1 */
	DoubleSHA256: 2,
	/** SHA512 - Compatible with: EdDSA only */
	SHA512: 3,
	/** Merlin (STROBE-based transcript construction) - Compatible with: SchnorrkelSubstrate only */
	Merlin: 4,
} as const;

export type Hash = (typeof Hash)[keyof typeof Hash];

/**
 * Elliptic curves supported by the Ika network.
 * Each curve is associated with specific signature algorithms.
 */
export const Curve = {
	/** secp256k1 - Used by: ECDSASecp256k1, Taproot */
	SECP256K1: 0,
	/** Ristretto - Used by: SchnorrkelSubstrate */
	RISTRETTO: 1,
	/** Ed25519 - Used by: EdDSA */
	ED25519: 2,
	/** secp256r1 (P-256) - Used by: ECDSASecp256r1 */
	SECP256R1: 3,
} as const;

export type Curve = (typeof Curve)[keyof typeof Curve];

/**
 * Signature algorithms supported by the Ika network.
 *
 * **Valid Hash Combinations:**
 * - `ECDSASecp256k1`: KECCAK256, SHA256, DoubleSHA256
 * - `Taproot`: SHA256 only
 * - `ECDSASecp256r1`: SHA256, DoubleSHA256
 * - `EdDSA`: SHA512 only
 * - `SchnorrkelSubstrate`: Merlin only
 */
export const SignatureAlgorithm = {
	/** ECDSA with secp256k1 curve - Valid hashes: KECCAK256, SHA256, DoubleSHA256 */
	ECDSASecp256k1: 0,
	/** Taproot (Bitcoin) - Valid hash: SHA256 only */
	Taproot: 1,
	/** ECDSA with secp256r1 (P-256) curve - Valid hashes: SHA256, DoubleSHA256 */
	ECDSASecp256r1: 2,
	/** EdDSA (Ed25519) - Valid hash: SHA512 only */
	EdDSA: 3,
	/** Schnorrkel/Ristretto (Substrate) - Valid hash: Merlin only */
	SchnorrkelSubstrate: 4,
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
	activeDWallet?: DWallet;
	publicOutput?: Uint8Array;
	secretShare?: Uint8Array;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	presign: Presign;
	message: Uint8Array;
	hash: Hash;
	signatureScheme: SignatureAlgorithm;
	curve?: Curve;
};

export const PublicKeyBCS = bcs.vector(bcs.u8());

export const SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES = {
	Secp256k1: {
		value: 0,
		signatureAlgorithms: {
			ECDSA: {
				value: 0,
				hashSchemes: {
					Keccak256: { value: 0 },
					SHA256: { value: 1 },
					DoubleSHA256: { value: 2 },
				},
			},
			Taproot: {
				value: 1,
				hashSchemes: {
					SHA256: { value: 0 },
				},
			},
		},
	},

	Secp256r1: {
		value: 1,
		signatureAlgorithms: {
			ECDSA: {
				value: 0,
				hashSchemes: {
					SHA256: { value: 0 },
					DoubleSHA256: { value: 1 },
				},
			},
		},
	},

	Curve25519: {
		value: 2,
		signatureAlgorithms: {
			EdDSA: {
				value: 0,
				hashSchemes: {
					SHA512: { value: 0 },
				},
			},
		},
	},

	Ristretto: {
		value: 3,
		signatureAlgorithms: {
			SchnorrkelSubstrate: {
				value: 0,
				hashSchemes: {
					Merlin: { value: 0 },
				},
			},
		},
	},
} as const;
