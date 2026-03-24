// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { deriveAddress, deriveAccountsForCurve } from '../chain/address.js';

// A deterministic compressed secp256k1 public key (33 bytes).
const SECP256K1_PUBKEY = new Uint8Array([
	0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40,
	0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c,
	0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
]);

// A deterministic ed25519 public key (32 bytes).
const ED25519_PUBKEY = new Uint8Array([
	0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0,
	0x2a, 0x6f, 0x0d, 0x73, 0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6,
	0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59, 0xda, 0x29,
]);

describe('deriveAddress', () => {
	it('derives EVM address (0x-prefixed, 42 chars)', () => {
		const addr = deriveAddress(SECP256K1_PUBKEY, 'SECP256K1' as any, 'eip155:1');
		expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});

	it('derives Solana address (base58)', () => {
		const addr = deriveAddress(ED25519_PUBKEY, 'ED25519' as any, 'solana:mainnet');
		expect(addr.length).toBeGreaterThan(30);
		expect(addr).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
	});

	it('derives Sui address (0x-prefixed, 66 chars)', () => {
		const addr = deriveAddress(ED25519_PUBKEY, 'ED25519' as any, 'sui:mainnet');
		expect(addr).toMatch(/^0x[0-9a-f]{64}$/);
	});

	it('derives Cosmos bech32 address', () => {
		const addr = deriveAddress(SECP256K1_PUBKEY, 'SECP256K1' as any, 'cosmos:cosmoshub-4');
		expect(addr).toMatch(/^cosmos1/);
	});

	it('derives Bitcoin bech32 address', () => {
		const addr = deriveAddress(
			SECP256K1_PUBKEY,
			'SECP256K1' as any,
			'bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
		);
		expect(addr).toMatch(/^bc1/);
	});

	it('falls back to hex for unknown namespace', () => {
		const addr = deriveAddress(SECP256K1_PUBKEY, 'SECP256K1' as any, 'unknown:123');
		expect(addr).toMatch(/^0x/);
	});
});

describe('deriveAccountsForCurve', () => {
	it('derives secp256k1 accounts for EVM, BTC, Cosmos, Tron, Filecoin', () => {
		const accounts = deriveAccountsForCurve(SECP256K1_PUBKEY, 'SECP256K1' as any);
		expect(accounts.length).toBe(5);
		const chainIds = accounts.map((a) => a.chainId.split(':')[0]);
		expect(chainIds).toContain('eip155');
		expect(chainIds).toContain('bip122');
		expect(chainIds).toContain('cosmos');
		expect(chainIds).toContain('tron');
		expect(chainIds).toContain('fil');
	});

	it('derives ed25519 accounts for Solana, Sui, TON', () => {
		const accounts = deriveAccountsForCurve(ED25519_PUBKEY, 'ED25519' as any);
		expect(accounts.length).toBe(3);
		const chainIds = accounts.map((a) => a.chainId.split(':')[0]);
		expect(chainIds).toContain('solana');
		expect(chainIds).toContain('sui');
		expect(chainIds).toContain('ton');
	});

	it('all accounts have non-empty addresses', () => {
		const accounts = deriveAccountsForCurve(SECP256K1_PUBKEY, 'SECP256K1' as any);
		for (const account of accounts) {
			expect(account.address.length).toBeGreaterThan(0);
		}
	});
});
