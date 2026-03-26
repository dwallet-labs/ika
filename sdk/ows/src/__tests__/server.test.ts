// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { handleRequest } from '../server/index.js';
import type { OWSRequest } from '../server/index.js';

// Minimal mock provider for testing auth and routing.
const mockProvider = {
	isInitialized: true,
	getSuiAddress: () => '0xmock',
	listWallets: () => [],
} as any;

const apiKey = 'test-secret';

function req(overrides: Partial<OWSRequest>): OWSRequest {
	return {
		method: 'GET',
		path: '/health',
		body: {},
		headers: {},
		...overrides,
	};
}

describe('handleRequest', () => {
	it('health check works without auth', async () => {
		const res = await handleRequest(mockProvider, apiKey, req({ path: '/health' }));
		expect(res.status).toBe(200);
		expect((res.body as any).status).toBe('ok');
	});

	it('rejects missing auth', async () => {
		const res = await handleRequest(mockProvider, apiKey, req({ path: '/wallets' }));
		expect(res.status).toBe(401);
	});

	it('rejects wrong auth', async () => {
		const res = await handleRequest(mockProvider, apiKey, req({
			path: '/wallets',
			headers: { authorization: 'Bearer wrong' },
		}));
		expect(res.status).toBe(401);
	});

	it('accepts correct auth', async () => {
		const res = await handleRequest(mockProvider, apiKey, req({
			path: '/wallets',
			headers: { authorization: `Bearer ${apiKey}` },
		}));
		expect(res.status).toBe(200);
		expect(res.body).toEqual([]);
	});

	it('returns 404 for unknown routes', async () => {
		const res = await handleRequest(mockProvider, apiKey, req({
			path: '/nonexistent',
			headers: { authorization: `Bearer ${apiKey}` },
		}));
		expect(res.status).toBe(404);
	});

	it('returns error status for provider errors', async () => {
		const badProvider = {
			...mockProvider,
			listWallets: () => { throw new Error('something broke'); },
		} as any;
		const res = await handleRequest(badProvider, apiKey, req({
			path: '/wallets',
			headers: { authorization: `Bearer ${apiKey}` },
		}));
		expect(res.status).toBe(500);
		expect((res.body as any).error).toContain('something broke');
	});
});
