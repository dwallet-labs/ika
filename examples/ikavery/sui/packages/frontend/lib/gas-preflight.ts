/**
 * Pre-flight balance check helpers. The gas-payer wallet is `ctx.sender` and
 * pays both SUI gas and any IKA fees consumed inside the PTB — if it doesn't
 * hold enough of either, the wallet prompt still fires but the tx aborts at
 * fee resolution. Showing an estimate against current balance up-front lets
 * the user fix the wallet selection without burning a wallet prompt to find
 * out.
 */

import type { ClientWithCoreApi } from '@mysten/sui/client';

export interface BalanceSnapshot {
	sui: bigint;
	ika: bigint;
}

export interface CostEstimate {
	/** Required SUI in MIST. Includes a small headroom for gas itself. */
	sui: bigint;
	/** Required IKA in IKA's smallest unit (10^9 == 1 IKA). */
	ika: bigint;
}

/** SUI gas headroom per single PTB. Empirical for our flows (~0.02 SUI). */
const SUI_GAS_HEADROOM = 30_000_000n;

/** Default per-message IKA fee at execute time. Mirrors lib/session.ts. */
const DEFAULT_IKA_PER_MESSAGE = 500_000_000n;

/** Default per-message SUI fee at execute time. Mirrors lib/session.ts. */
const DEFAULT_SUI_PER_MESSAGE = 20_000_000n;

/** Verification IKA fee for `importSolanaKey` and enrollment ops. */
const VERIFY_IKA = 500_000_000n;

/** Verification SUI fee for `importSolanaKey` and enrollment ops. */
const VERIFY_SUI = 50_000_000n;

/**
 * Fee passed to `request_re_encrypt_user_share_for` at enrollment-execute.
 * Mirrors the worker's `executeKeyHolderEnrollment` overrides — over-budget
 * by design since the SDK refunds the leftover IKA + SUI back to the
 * executor at the end of the PTB.
 */
const REENCRYPT_IKA = 2_000_000_000n;
const REENCRYPT_SUI = 200_000_000n;

/**
 * Propose & approve don't lock IKA — the only Sui-side cost is gas. Approve
 * is a single Move call so headroom is enough by itself.
 */
export const ESTIMATE_APPROVE: CostEstimate = {
	sui: SUI_GAS_HEADROOM,
	ika: 0n,
};
export const ESTIMATE_PROPOSE: CostEstimate = {
	sui: SUI_GAS_HEADROOM,
	ika: 0n,
};

/**
 * Execute reserves IKA + SUI fees for each Solana tx in the bundle, then
 * the SDK transfers the change back to the executor — but the wallet still
 * has to *front* the full pre-fee amount, so size the budget for the upper
 * bound.
 */
export function estimateExecute(messageCount: number): CostEstimate {
	const n = BigInt(messageCount);
	return {
		sui: DEFAULT_SUI_PER_MESSAGE * n + SUI_GAS_HEADROOM,
		ika: DEFAULT_IKA_PER_MESSAGE * n,
	};
}

/**
 * importSolanaKey covers DKG (no IKA fee) plus key-import verification
 * (1× verify fee). The provisioning fan-out (re-encrypt + accept) does NOT
 * consume more IKA — only the initial verification does.
 */
export const ESTIMATE_IMPORT: CostEstimate = {
	sui: VERIFY_SUI + SUI_GAS_HEADROOM,
	ika: VERIFY_IKA,
};

/** Enroll-device verification + accept. Same shape as import's verify step. */
export const ESTIMATE_ENROLL: CostEstimate = {
	sui: VERIFY_SUI + SUI_GAS_HEADROOM,
	ika: VERIFY_IKA,
};

/** Key-holder enrollment-execute (re-encrypts the share to the new member). */
export const ESTIMATE_ENROLL_EXECUTE: CostEstimate = {
	sui: REENCRYPT_SUI + SUI_GAS_HEADROOM,
	ika: REENCRYPT_IKA,
};

/**
 * Read the gas-payer's SUI + IKA balance. Returns zeros on RPC failure (so
 * the UI can fail open — show the warning, never crash).
 */
export async function fetchBalances(
	suiClient: ClientWithCoreApi,
	owner: string,
	ikaCoinType: string,
): Promise<BalanceSnapshot> {
	const [suiRes, ikaRes] = await Promise.allSettled([
		suiClient.core.getBalance({ owner }),
		suiClient.core.getBalance({ owner, coinType: ikaCoinType }),
	]);
	return {
		sui: suiRes.status === 'fulfilled' ? BigInt(suiRes.value.balance.balance) : 0n,
		ika: ikaRes.status === 'fulfilled' ? BigInt(ikaRes.value.balance.balance) : 0n,
	};
}

export interface BudgetReadout {
	/** Current balances. */
	have: BalanceSnapshot;
	/** What this action will consume. */
	need: CostEstimate;
	/** True only when both currencies cover the estimate. */
	ok: boolean;
	/** Per-currency status, useful for highlighting the failing one. */
	suiOk: boolean;
	ikaOk: boolean;
}

export function compareBudget(have: BalanceSnapshot, need: CostEstimate): BudgetReadout {
	const suiOk = have.sui >= need.sui;
	const ikaOk = have.ika >= need.ika;
	return { have, need, ok: suiOk && ikaOk, suiOk, ikaOk };
}

export function formatSui(mist: bigint): string {
	return `${(Number(mist) / 1e9).toFixed(3)} SUI`;
}
export function formatIka(units: bigint): string {
	return `${(Number(units) / 1e9).toFixed(3)} IKA`;
}
