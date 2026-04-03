// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { PolicyEngine } from '../policy/index.js';

describe('PolicyEngine', () => {
	describe('declarative policies', () => {
		it('allows when no policies registered', async () => {
			const engine = new PolicyEngine();
			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'eip155:1',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).resolves.toBeUndefined();
		});

		it('blocks chains not in allowlist', async () => {
			const engine = new PolicyEngine();
			engine.createPolicy('evm-only', { allowed_chains: ['eip155'] });

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'solana:mainnet',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).rejects.toThrow('POLICY_DENIED');
		});

		it('allows chains in allowlist', async () => {
			const engine = new PolicyEngine();
			engine.createPolicy('evm-only', { allowed_chains: ['eip155'] });

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'eip155:1',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).resolves.toBeUndefined();
		});

		it('blocks chains in blocklist', async () => {
			const engine = new PolicyEngine();
			engine.createPolicy('no-solana', { blocked_chains: ['solana'] });

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'solana:mainnet',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).rejects.toThrow('POLICY_DENIED');
		});

		it('blocks expired policies', async () => {
			const engine = new PolicyEngine();
			engine.createPolicy('expired', { expires_at: '2020-01-01T00:00:00Z' });

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'eip155:1',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).rejects.toThrow('POLICY_DENIED');
		});

		it('enforces daily transaction limit', async () => {
			const engine = new PolicyEngine();
			engine.createPolicy('daily-limit', { max_daily_transactions: 2 });
			const now = new Date().toISOString();
			const ctx = {
				walletId: 'w1',
				walletName: 'test',
				chain: 'eip155:1' as const,
				operation: 'sign_transaction' as const,
				messageHex: 'aabb',
				timestamp: now,
			};

			await engine.evaluate(ctx);
			await engine.evaluate(ctx);
			await expect(engine.evaluate(ctx)).rejects.toThrow('POLICY_DENIED');
		});
	});

	describe('custom policy functions', () => {
		it('blocks when custom function returns deny', async () => {
			const engine = new PolicyEngine();
			engine.addPolicyFunction({
				name: 'always-deny',
				evaluate: () => ({ allow: false, reason: 'nope' }),
			});

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'eip155:1',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).rejects.toThrow('nope');
		});

		it('allows when custom function returns allow', async () => {
			const engine = new PolicyEngine();
			engine.addPolicyFunction({
				name: 'always-allow',
				evaluate: () => ({ allow: true }),
			});

			await expect(
				engine.evaluate({
					walletId: 'w1',
					walletName: 'test',
					chain: 'eip155:1',
					operation: 'sign_transaction',
					messageHex: 'aabb',
					timestamp: new Date().toISOString(),
				}),
			).resolves.toBeUndefined();
		});

		it('removes policy function by name', () => {
			const engine = new PolicyEngine();
			engine.addPolicyFunction({
				name: 'test',
				evaluate: () => ({ allow: true }),
			});
			expect(engine.listPolicyFunctions()).toContain('test');
			engine.removePolicyFunction('test');
			expect(engine.listPolicyFunctions()).not.toContain('test');
		});
	});

	describe('policy CRUD', () => {
		it('creates, lists, gets, deletes', () => {
			const engine = new PolicyEngine();
			const policy = engine.createPolicy('test', { allowed_chains: ['eip155'] });
			expect(engine.listPolicies()).toHaveLength(1);
			expect(engine.getPolicy(policy.id).name).toBe('test');
			engine.deletePolicy(policy.id);
			expect(engine.listPolicies()).toHaveLength(0);
		});
	});
});
