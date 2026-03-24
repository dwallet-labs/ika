// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * BIP-39 mnemonic utilities. Replaces @open-wallet-standard/core's
 * generateMnemonic and deriveAddress.
 */

import { generateMnemonic as bip39Generate, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { Curve } from '@ika.xyz/sdk';

import { deriveAddress } from './address.js';
import { derivePrivateKeyFromMnemonic } from './crypto.js';
import { OWSError, OWSErrorCode } from './errors.js';
import { resolveChainParams } from './chains.js';

/**
 * Generate a BIP-39 mnemonic phrase.
 * @param words — 12 or 24 (default: 12)
 */
export function generateMnemonic(words?: number | null): string {
	const strength = (words ?? 12) === 24 ? 256 : 128;
	return bip39Generate(wordlist, strength);
}

/**
 * Validate a BIP-39 mnemonic.
 */
export function isValidMnemonic(mnemonic: string): boolean {
	return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derive a chain-native address from a mnemonic.
 *
 * @param mnemonic — BIP-39 mnemonic
 * @param chain — Chain family name (e.g., "evm", "solana", "bitcoin", "sui", "cosmos")
 *                or CAIP-2 namespace
 * @param index — BIP-44 account index (default: 0)
 */
export function deriveAddressFromMnemonic(
	mnemonic: string,
	chain: string,
	index?: number | null,
): string {
	if (!isValidMnemonic(mnemonic)) {
		throw new OWSError(OWSErrorCode.INVALID_INPUT, 'Invalid BIP-39 mnemonic');
	}

	// Resolve chain name to CAIP-2 namespace.
	const namespace = resolveChainNameToNamespace(chain);
	const chainParams = resolveChainParams(`${namespace}:_`);
	const curve = chainParams.curve;

	const privateKey = derivePrivateKeyFromMnemonic(mnemonic, curve, index ?? 0);
	const publicKey = derivePublicKeyFromPrivate(privateKey, curve);

	// Use a canonical chain ID for address derivation.
	const canonicalChainId = getCanonicalChainId(namespace);
	return deriveAddress(publicKey, curve, canonicalChainId);
}

/** Map friendly chain names to CAIP-2 namespaces. */
function resolveChainNameToNamespace(chain: string): string {
	const nameMap: Record<string, string> = {
		evm: 'eip155',
		ethereum: 'eip155',
		bitcoin: 'bip122',
		btc: 'bip122',
		solana: 'solana',
		sol: 'solana',
		sui: 'sui',
		cosmos: 'cosmos',
		tron: 'tron',
		ton: 'ton',
		filecoin: 'fil',
		fil: 'fil',
	};

	// If it's already a namespace or CAIP-2 ID, extract namespace.
	if (chain.includes(':')) {
		return chain.split(':')[0]!;
	}

	return nameMap[chain.toLowerCase()] ?? chain;
}

/** Get a canonical CAIP-2 chain ID for a namespace (for address derivation). */
function getCanonicalChainId(namespace: string): string {
	const canonicalMap: Record<string, string> = {
		eip155: 'eip155:1',
		bip122: 'bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
		solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
		sui: 'sui:mainnet',
		cosmos: 'cosmos:cosmoshub-4',
		tron: 'tron:0x2b6653dc',
		ton: 'ton:mainnet',
		fil: 'fil:f',
	};
	return canonicalMap[namespace] ?? `${namespace}:mainnet`;
}

/**
 * Derive public key from private key for a given curve.
 * Uses @noble/curves for the actual derivation.
 */
function derivePublicKeyFromPrivate(privateKey: Uint8Array, curve: Curve): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1: {
			const { secp256k1 } = require('@noble/curves/secp256k1');
			return secp256k1.getPublicKey(privateKey, true); // compressed
		}
		case Curve.ED25519: {
			const { ed25519 } = require('@noble/curves/ed25519');
			return ed25519.getPublicKey(privateKey);
		}
		case Curve.SECP256R1: {
			const { p256 } = require('@noble/curves/p256');
			return p256.getPublicKey(privateKey, true); // compressed
		}
		default:
			throw new OWSError(OWSErrorCode.INVALID_INPUT, `Unsupported curve for key derivation: ${curve}`);
	}
}
