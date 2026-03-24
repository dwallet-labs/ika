// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * CAIP-2 chain ID to Ika curve/algorithm mapping.
 *
 * Maps OWS-supported chains to the correct Ika cryptographic parameters
 * for dWallet MPC signing.
 *
 * @see https://docs.openwallet.sh/
 * @see https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
 */

import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';

import { OWSError, OWSErrorCode } from './errors.js';
import type { ChainId } from './types.js';

/** Resolved signing parameters for a given chain. */
export interface ChainSigningParams {
	/** The CAIP-2 namespace (e.g., "eip155", "solana"). */
	namespace: string;
	/** Ika cryptographic curve. */
	curve: Curve;
	/** Default signature algorithm for this chain. */
	signatureAlgorithm: SignatureAlgorithm;
	/** Default hash algorithm for this chain. */
	hash: Hash;
	/** Human-readable chain family name. */
	chainFamily: string;
}

/**
 * Chain family definitions mapping CAIP-2 namespaces to Ika signing parameters.
 *
 * | Chain     | CAIP-2 Namespace | Curve      | Signature Algorithm | Hash         |
 * |-----------|-----------------|------------|--------------------:|-------------|
 * | EVM       | eip155          | secp256k1  | ECDSASecp256k1      | KECCAK256    |
 * | Bitcoin   | bip122          | secp256k1  | ECDSASecp256k1      | DoubleSHA256 |
 * | Solana    | solana          | ed25519    | EdDSA               | SHA512       |
 * | Sui       | sui             | ed25519    | EdDSA               | SHA512       |
 * | Cosmos    | cosmos          | secp256k1  | ECDSASecp256k1      | SHA256       |
 * | Tron      | tron            | secp256k1  | ECDSASecp256k1      | KECCAK256    |
 * | TON       | ton             | ed25519    | EdDSA               | SHA512       |
 * | Filecoin  | fil             | secp256k1  | ECDSASecp256k1      | SHA256       |
 */
const CHAIN_FAMILIES: Record<string, Omit<ChainSigningParams, 'namespace'>> = {
	eip155: {
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.KECCAK256,
		chainFamily: 'EVM',
	},
	bip122: {
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.DoubleSHA256,
		chainFamily: 'Bitcoin',
	},
	solana: {
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
		chainFamily: 'Solana',
	},
	sui: {
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
		chainFamily: 'Sui',
	},
	cosmos: {
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.SHA256,
		chainFamily: 'Cosmos',
	},
	tron: {
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.KECCAK256,
		chainFamily: 'Tron',
	},
	ton: {
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
		chainFamily: 'TON',
	},
	fil: {
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.SHA256,
		chainFamily: 'Filecoin',
	},
};

/** All supported CAIP-2 namespaces. */
export const SUPPORTED_NAMESPACES = Object.keys(CHAIN_FAMILIES);

/**
 * Parse a CAIP-2 chain ID into namespace and reference.
 * @example parseChainId("eip155:1") → { namespace: "eip155", reference: "1" }
 */
export function parseChainId(chainId: ChainId): { namespace: string; reference: string } {
	const colonIndex = chainId.indexOf(':');
	if (colonIndex === -1 || colonIndex === 0 || colonIndex === chainId.length - 1) {
		throw new OWSError(OWSErrorCode.CAIP_PARSE_ERROR, `Invalid CAIP-2 chain ID: ${chainId}`);
	}
	return {
		namespace: chainId.substring(0, colonIndex),
		reference: chainId.substring(colonIndex + 1),
	};
}

/**
 * Resolve signing parameters for a CAIP-2 chain ID.
 * @throws {OWSError} CAIP_PARSE_ERROR if chainId is malformed.
 * @throws {OWSError} CHAIN_NOT_SUPPORTED if namespace is unknown.
 */
export function resolveChainParams(chainId: ChainId): ChainSigningParams {
	const { namespace } = parseChainId(chainId);
	const family = CHAIN_FAMILIES[namespace];
	if (!family) {
		throw new OWSError(
			OWSErrorCode.CHAIN_NOT_SUPPORTED,
			`Unsupported chain: ${chainId}. Supported namespaces: ${SUPPORTED_NAMESPACES.join(', ')}`,
		);
	}
	return { namespace, ...family };
}

/** Check if a CAIP-2 chain is supported. */
export function isChainSupported(chainId: ChainId): boolean {
	try {
		resolveChainParams(chainId);
		return true;
	} catch {
		return false;
	}
}

/** Get all supported chains with their signing parameters. */
export function getSupportedChains(): ChainSigningParams[] {
	return Object.entries(CHAIN_FAMILIES).map(([namespace, params]) => ({
		namespace,
		...params,
	}));
}

/**
 * Get all chain namespaces that use a given curve.
 * A single dWallet on a given curve can sign for all chains using that curve.
 */
export function namespacesForCurve(curve: Curve): string[] {
	return Object.entries(CHAIN_FAMILIES)
		.filter(([_, params]) => params.curve === curve)
		.map(([namespace]) => namespace);
}
