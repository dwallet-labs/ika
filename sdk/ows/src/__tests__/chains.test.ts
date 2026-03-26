// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	resolveChainParams,
	parseChainId,
	isChainSupported,
	getSupportedChains,
	namespacesForCurve,
	SUPPORTED_NAMESPACES,
} from '../chain/chains.js';

describe('parseChainId', () => {
	it('parses valid CAIP-2 chain IDs', () => {
		expect(parseChainId('eip155:1')).toEqual({ namespace: 'eip155', reference: '1' });
		expect(parseChainId('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')).toEqual({
			namespace: 'solana',
			reference: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
		});
	});

	it('throws on malformed chain IDs', () => {
		expect(() => parseChainId('eip155')).toThrow('CAIP_PARSE_ERROR');
		expect(() => parseChainId(':1')).toThrow('CAIP_PARSE_ERROR');
		expect(() => parseChainId('eip155:')).toThrow('CAIP_PARSE_ERROR');
		expect(() => parseChainId('')).toThrow('CAIP_PARSE_ERROR');
	});
});

describe('resolveChainParams', () => {
	it('resolves EVM chains', () => {
		const params = resolveChainParams('eip155:1');
		expect(params.namespace).toBe('eip155');
		expect(params.chainFamily).toBe('EVM');
		expect(params.curve).toBe('SECP256K1');
	});

	it('resolves Solana', () => {
		const params = resolveChainParams('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
		expect(params.curve).toBe('ED25519');
		expect(params.chainFamily).toBe('Solana');
	});

	it('throws on unsupported namespace', () => {
		expect(() => resolveChainParams('unsupported:123')).toThrow('CHAIN_NOT_SUPPORTED');
	});
});

describe('isChainSupported', () => {
	it('returns true for supported chains', () => {
		expect(isChainSupported('eip155:1')).toBe(true);
		expect(isChainSupported('bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')).toBe(true);
		expect(isChainSupported('solana:mainnet')).toBe(true);
	});

	it('returns false for unsupported chains', () => {
		expect(isChainSupported('unsupported:1')).toBe(false);
	});
});

describe('getSupportedChains', () => {
	it('returns all 8 chain families', () => {
		const chains = getSupportedChains();
		expect(chains.length).toBe(8);
		expect(chains.map((c) => c.namespace).sort()).toEqual(
			['bip122', 'cosmos', 'eip155', 'fil', 'solana', 'sui', 'ton', 'tron'],
		);
	});
});

describe('namespacesForCurve', () => {
	it('returns secp256k1 namespaces', () => {
		const ns = namespacesForCurve('SECP256K1' as any);
		expect(ns).toContain('eip155');
		expect(ns).toContain('bip122');
		expect(ns).toContain('cosmos');
		expect(ns).not.toContain('solana');
	});

	it('returns ed25519 namespaces', () => {
		const ns = namespacesForCurve('ED25519' as any);
		expect(ns).toContain('solana');
		expect(ns).toContain('sui');
		expect(ns).not.toContain('eip155');
	});
});

describe('SUPPORTED_NAMESPACES', () => {
	it('has 8 entries', () => {
		expect(SUPPORTED_NAMESPACES.length).toBe(8);
	});
});
