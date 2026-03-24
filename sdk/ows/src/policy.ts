// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Policy engine — two-layer enforcement for SAWS.
 *
 * ## Layer 1: Local Policies (agent-side)
 *
 * Evaluated in-process before signing requests reach the network.
 * Two types:
 *
 * ### Declarative Rules
 * JSON-based rules (allowed_chains, rate_limit, max_value, etc.)
 * evaluated automatically.
 *
 * ### Custom Policy Functions
 * User-defined TypeScript functions registered with the provider.
 * Called with the full signing context — can implement any logic.
 *
 * ```typescript
 * provider.addPolicy({
 *   name: 'spending-limit',
 *   evaluate: async (ctx) => {
 *     const dailySpent = await getDailySpending(ctx.wallet);
 *     if (dailySpent + ctx.estimatedValue > MAX_DAILY) {
 *       return { allow: false, reason: 'Daily spending limit exceeded' };
 *     }
 *     return { allow: true };
 *   },
 * });
 * ```
 *
 * ## Layer 2: On-Chain Policies (network-side)
 *
 * Enforced at the Sui Move smart contract level. The agent cannot bypass these.
 *
 * On-chain policies are Move modules that wrap `approve_message` and add
 * validation before producing a `MessageApproval`. Users deploy their own
 * policy modules. The SDK supports passing custom Move calls instead of
 * the default `approve_message`.
 *
 * Example Move policy:
 * ```move
 * module my_policy::allowlist {
 *     use ika_dwallet_2pc_mpc::coordinator;
 *
 *     struct ChainAllowlist has key {
 *         allowed_signature_algorithms: vector<u32>,
 *     }
 *
 *     public fun approve_with_allowlist(
 *         coordinator: &mut coordinator::DWalletCoordinator,
 *         cap: &coordinator_inner::DWalletCap,
 *         allowlist: &ChainAllowlist,
 *         signature_algorithm: u32,
 *         hash_scheme: u32,
 *         message: vector<u8>,
 *     ): coordinator_inner::MessageApproval {
 *         assert!(vector::contains(&allowlist.allowed_signature_algorithms, &signature_algorithm));
 *         coordinator::approve_message(coordinator, cap, signature_algorithm, hash_scheme, message)
 *     }
 * }
 * ```
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import { OWSError, OWSErrorCode } from './errors.js';
import type { ChainId } from './types.js';

// ─── Types ───────────────────────────────────────────────────────────────

/** Context passed to policy evaluation. */
export interface PolicyContext {
	/** Wallet name or ID. */
	walletId: string;
	/** Wallet name. */
	walletName: string;
	/** CAIP-2 chain being signed for. */
	chain: ChainId;
	/** Operation type. */
	operation: 'sign_transaction' | 'sign_message' | 'sign_typed_data' | 'pay_request';
	/** Hex-encoded message/transaction being signed. */
	messageHex: string;
	/** ISO 8601 timestamp. */
	timestamp: string;
}

/** Result from a policy evaluation. */
export interface PolicyResult {
	allow: boolean;
	reason?: string;
}

/** A user-defined policy function. */
export interface PolicyFunction {
	/** Policy name (for logging/debugging). */
	name: string;
	/** Evaluation function. Return { allow: false, reason } to deny. */
	evaluate: (ctx: PolicyContext) => PolicyResult | Promise<PolicyResult>;
}

/** Declarative policy rules (JSON-serializable). */
export interface DeclarativePolicyRules {
	/** Whitelist of allowed CAIP-2 chain IDs or namespaces. */
	allowed_chains?: string[];
	/** Blacklist of blocked CAIP-2 chain IDs or namespaces. */
	blocked_chains?: string[];
	/** ISO 8601 policy expiration. */
	expires_at?: string;
	/** Max transactions per UTC day. */
	max_daily_transactions?: number;
	/** Sliding window rate limit. */
	rate_limit?: { max_requests: number; window_seconds: number };
	/** Allowed operation types. */
	allowed_operations?: string[];
}

/** A stored declarative policy. */
export interface DeclarativePolicy {
	id: string;
	name: string;
	type: 'declarative';
	rules: DeclarativePolicyRules;
	createdAt: string;
}

/** On-chain policy configuration. */
export interface OnChainPolicy {
	/** Policy name. */
	name: string;
	/**
	 * The Move function to call instead of the default `approve_message`.
	 * Format: `<package>::<module>::<function>`
	 * The function MUST return a MessageApproval or ImportedKeyMessageApproval.
	 */
	approveFunction: string;
	/**
	 * Additional object arguments to pass to the approve function.
	 * These are Sui object IDs that will be passed as references.
	 */
	objectArgs: string[];
}

// ─── Policy Engine ───────────────────────────────────────────────────────

export class PolicyEngine {
	/** Registered custom policy functions. */
	readonly #functions: PolicyFunction[] = [];
	/** Loaded declarative policies. */
	readonly #declarative: DeclarativePolicy[] = [];
	/** On-chain policies. */
	readonly #onChain: OnChainPolicy[] = [];
	/** Rate limit state: key → timestamps[] */
	readonly #rateLimitState = new Map<string, number[]>();
	/** Daily transaction counts: "walletId:YYYY-MM-DD" → count */
	readonly #dailyCounts = new Map<string, number>();
	/** Vault path for persisted policies. */
	readonly #vaultPath: string | undefined;

	constructor(vaultPath?: string) {
		this.#vaultPath = vaultPath;
		this.#loadPersistedPolicies();
	}

	// ─── Custom Policy Functions ──────────────────────────────────────

	/** Register a custom policy function. Evaluated for every sign request. */
	addPolicyFunction(fn: PolicyFunction): void {
		this.#functions.push(fn);
	}

	/** Remove a custom policy function by name. */
	removePolicyFunction(name: string): void {
		const idx = this.#functions.findIndex((f) => f.name === name);
		if (idx !== -1) this.#functions.splice(idx, 1);
	}

	/** List registered policy function names. */
	listPolicyFunctions(): string[] {
		return this.#functions.map((f) => f.name);
	}

	// ─── Declarative Policies ─────────────────────────────────────────

	/** Create a declarative policy. Persisted to vault. */
	createPolicy(name: string, rules: DeclarativePolicyRules): DeclarativePolicy {
		const policy: DeclarativePolicy = {
			id: crypto.randomUUID(),
			name,
			type: 'declarative',
			rules,
			createdAt: new Date().toISOString(),
		};
		this.#declarative.push(policy);
		this.#persistPolicy(policy);
		return policy;
	}

	/** List all declarative policies. */
	listPolicies(): DeclarativePolicy[] {
		return [...this.#declarative];
	}

	/** Get a declarative policy by ID. */
	getPolicy(id: string): DeclarativePolicy {
		const policy = this.#declarative.find((p) => p.id === id);
		if (!policy) throw new OWSError(OWSErrorCode.INVALID_INPUT, `Policy not found: ${id}`);
		return policy;
	}

	/** Delete a declarative policy. */
	deletePolicy(id: string): void {
		const idx = this.#declarative.findIndex((p) => p.id === id);
		if (idx === -1) throw new OWSError(OWSErrorCode.INVALID_INPUT, `Policy not found: ${id}`);
		this.#declarative.splice(idx, 1);
		this.#removePersistedPolicy(id);
	}

	// ─── On-Chain Policies ────────────────────────────────────────────

	/** Register an on-chain policy. Applied during message approval. */
	addOnChainPolicy(policy: OnChainPolicy): void {
		this.#onChain.push(policy);
	}

	/** Remove an on-chain policy by name. */
	removeOnChainPolicy(name: string): void {
		const idx = this.#onChain.findIndex((p) => p.name === name);
		if (idx !== -1) this.#onChain.splice(idx, 1);
	}

	/** List on-chain policies. */
	listOnChainPolicies(): OnChainPolicy[] {
		return [...this.#onChain];
	}

	/** Get on-chain policies (used by provider during signing). */
	getOnChainPolicies(): OnChainPolicy[] {
		return this.#onChain;
	}

	// ─── Evaluation ───────────────────────────────────────────────────

	/**
	 * Evaluate all local policies (Layer 1) against a signing context.
	 * @throws {OWSError} POLICY_DENIED if any policy rejects.
	 */
	async evaluate(ctx: PolicyContext): Promise<void> {
		// 1. Declarative rules.
		for (const policy of this.#declarative) {
			const result = this.#evaluateDeclarative(policy, ctx);
			if (!result.allow) {
				throw new OWSError(
					OWSErrorCode.POLICY_DENIED,
					`Policy "${policy.name}" denied: ${result.reason}`,
				);
			}
		}

		// 2. Custom policy functions.
		for (const fn of this.#functions) {
			const result = await fn.evaluate(ctx);
			if (!result.allow) {
				throw new OWSError(
					OWSErrorCode.POLICY_DENIED,
					`Policy "${fn.name}" denied: ${result.reason}`,
				);
			}
		}

		// 3. Update rate limit / daily count state.
		this.#recordRequest(ctx);
	}

	// ─── Internal: Declarative Evaluation ─────────────────────────────

	#evaluateDeclarative(policy: DeclarativePolicy, ctx: PolicyContext): PolicyResult {
		const { rules } = policy;

		// Expiration.
		if (rules.expires_at) {
			if (new Date(ctx.timestamp) > new Date(rules.expires_at)) {
				return { allow: false, reason: `Policy expired at ${rules.expires_at}` };
			}
		}

		// Allowed chains.
		if (rules.allowed_chains && rules.allowed_chains.length > 0) {
			const namespace = ctx.chain.split(':')[0]!;
			const match = rules.allowed_chains.some(
				(c) => c === ctx.chain || c === namespace,
			);
			if (!match) {
				return { allow: false, reason: `Chain ${ctx.chain} not in allowed list` };
			}
		}

		// Blocked chains.
		if (rules.blocked_chains && rules.blocked_chains.length > 0) {
			const namespace = ctx.chain.split(':')[0]!;
			const match = rules.blocked_chains.some(
				(c) => c === ctx.chain || c === namespace,
			);
			if (match) {
				return { allow: false, reason: `Chain ${ctx.chain} is blocked` };
			}
		}

		// Allowed operations.
		if (rules.allowed_operations && rules.allowed_operations.length > 0) {
			if (!rules.allowed_operations.includes(ctx.operation)) {
				return { allow: false, reason: `Operation ${ctx.operation} not allowed` };
			}
		}

		// Daily transaction limit.
		if (rules.max_daily_transactions !== undefined) {
			const today = new Date(ctx.timestamp).toISOString().split('T')[0];
			const key = `${ctx.walletId}:${today}`;
			const count = this.#dailyCounts.get(key) ?? 0;
			if (count >= rules.max_daily_transactions) {
				return { allow: false, reason: `Daily transaction limit (${rules.max_daily_transactions}) reached` };
			}
		}

		// Rate limit.
		if (rules.rate_limit) {
			const key = `rate:${ctx.walletId}`;
			const now = Date.now();
			const windowMs = rules.rate_limit.window_seconds * 1000;
			const timestamps = (this.#rateLimitState.get(key) ?? []).filter(
				(t) => now - t < windowMs,
			);
			if (timestamps.length >= rules.rate_limit.max_requests) {
				return { allow: false, reason: `Rate limit (${rules.rate_limit.max_requests}/${rules.rate_limit.window_seconds}s) exceeded` };
			}
		}

		return { allow: true };
	}

	#recordRequest(ctx: PolicyContext): void {
		// Update daily count.
		const today = new Date(ctx.timestamp).toISOString().split('T')[0];
		const dailyKey = `${ctx.walletId}:${today}`;
		this.#dailyCounts.set(dailyKey, (this.#dailyCounts.get(dailyKey) ?? 0) + 1);

		// Update rate limit state.
		const rateKey = `rate:${ctx.walletId}`;
		const timestamps = this.#rateLimitState.get(rateKey) ?? [];
		timestamps.push(Date.now());
		this.#rateLimitState.set(rateKey, timestamps);
	}

	// ─── Internal: Persistence ────────────────────────────────────────

	#policiesDir(): string | null {
		if (!this.#vaultPath) return null;
		const dir = path.join(this.#vaultPath, 'ika', 'policies');
		return dir;
	}

	#persistPolicy(policy: DeclarativePolicy): void {
		const dir = this.#policiesDir();
		if (!dir) return;
		fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
		fs.writeFileSync(
			path.join(dir, `${policy.id}.json`),
			JSON.stringify(policy, null, '\t'),
			{ encoding: 'utf-8', mode: 0o644 },
		);
	}

	#removePersistedPolicy(id: string): void {
		const dir = this.#policiesDir();
		if (!dir) return;
		const filePath = path.join(dir, `${id}.json`);
		if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
	}

	#loadPersistedPolicies(): void {
		const dir = this.#policiesDir();
		if (!dir || !fs.existsSync(dir)) return;
		for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.json'))) {
			try {
				const policy = JSON.parse(
					fs.readFileSync(path.join(dir, file), 'utf-8'),
				) as DeclarativePolicy;
				this.#declarative.push(policy);
			} catch {
				// Skip malformed policy files.
			}
		}
	}
}
