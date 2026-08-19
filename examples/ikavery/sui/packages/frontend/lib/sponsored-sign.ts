'use client';

import type { TransactionExecuteResult } from '@fesal-packages/ikavery-sui-sdk';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Transaction } from '@mysten/sui/transactions';

import { dAppKit } from './dapp-kit';
import { env } from './env';

/**
 * The wallet that becomes ctx.sender of the next PTB. It pays for SUI gas
 * AND for any IKA fees referenced inside the PTB — in our flows the IKA
 * coins are sourced from `ctx.sender`'s owned objects, so making the gas
 * payer anything other than the sender breaks fee resolution.
 *
 * Auth (passkey / personal-message / sender_address) is decoupled from this:
 * the credential signer signs a per-operation challenge that Move's
 * `auth::verify` checks against the members set, independently of who paid
 * the gas. The only coupling is when the auth scheme IS sender_address (an
 * approver-only zkLogin member) — there the gas-payer must equal the
 * approver's address, since auth degenerates to `addr == ctx.sender`.
 */
export type GasPayer = {
	wallet: UiWallet;
	account: UiWalletAccount;
	walletName: string;
	walletIcon?: string;
	address: string;
};

/**
 * Build a `signAndExecute` callback for a single gas-payer wallet. That
 * wallet is both the tx signer (ctx.sender) and the gas owner; the IKA fee
 * is implicitly drawn from its owned coins by the SDK flows.
 *
 * If `walletSign` (dapp-kit's `useSignTransaction().mutateAsync`) is provided
 * AND the gas-payer is the dapp-kit "current" wallet, we use it — the
 * tested 1-sig flow. Otherwise we sign via raw wallet-standard against the
 * specified gas-payer account.
 */
export function buildSignAndExecute(opts: {
	gasPayer: GasPayer;
	/**
	 * dapp-kit's `useSignTransaction().mutateAsync`. Used as a happy path when
	 * the gas-payer matches the dapp-kit current wallet.
	 */
	walletSign?: (input: {
		transaction: Transaction;
	}) => Promise<{ bytes: string; signature: string }>;
	/** dapp-kit's "current wallet". Used to decide whether to use `walletSign`. */
	currentWallet: UiWallet | null;
	/** Progress callback for fine-grained UI phases. */
	onPhase?: (phase: string) => void;
	suiClient: ClientWithCoreApi;
	network: string;
}): (transaction: Transaction) => Promise<TransactionExecuteResult> {
	const { gasPayer, walletSign, currentWallet, onPhase, suiClient, network } = opts;
	const chain = `sui:${network}`;
	const phase = (s: string) => {
		onPhase?.(s);
		if (typeof console !== 'undefined') console.log('[tx]', s);
	};

	const useDappKit =
		walletSign &&
		currentWallet?.accounts.some((a) => a.address.toLowerCase() === gasPayer.address.toLowerCase());

	return async (transaction: Transaction) => {
		transaction.setSender(gasPayer.address);
		transaction.setGasOwner(gasPayer.address);

		// Dry-run before bothering the wallet — surfaces Move aborts (already
		// member, threshold not reached, etc.) and gas-budget / IKA-balance
		// problems while the user still has a clear error to act on. Without
		// this, a failing tx silently goes through wallet-sign + RPC submit and
		// shows up as an opaque "FailedTransaction".
		phase('Simulating transaction…');
		await simulateOrThrow(suiClient, transaction);

		let bytes: string;
		let signature: string;
		if (useDappKit && walletSign) {
			phase('Asking connected wallet to sign…');
			const r = await walletSign({ transaction });
			bytes = r.bytes;
			signature = r.signature;
		} else {
			phase(`Asking ${gasPayer.walletName} to sign…`);
			// dApp Kit dispatches sui:signTransaction, falling back to the legacy
			// sui:signTransactionBlock itself, and resolves the transaction through
			// its own (gRPC) client.
			const r = await dAppKit.signTransaction({
				transaction,
				account: gasPayer.account,
			});
			bytes = r.bytes;
			signature = r.signature;
		}
		phase('Wallet signed. Submitting to Sui RPC…');
		const out = await suiClient.core.executeTransaction({
			transaction: base64ToUint8(bytes),
			signatures: [signature],
			include: { events: true, effects: true, objectTypes: true },
		});
		phase('Sui RPC accepted the transaction.');
		return out;
	};
}

// ===== simulate / abort decoding =====

/**
 * Run a read-only simulation against the Sui RPC. Throws an Error with a
 * human-readable message if the tx would fail; returns silently otherwise.
 *
 * Call this before any wallet sign + RPC submit — the simulation is free
 * (no gas, no signature) and surfaces Move aborts and gas-budget problems
 * while the user still has a clear error to act on.
 */
export async function simulateOrThrow(
	suiClient: ClientWithCoreApi,
	transaction: Transaction,
): Promise<void> {
	let r: { $kind: string; FailedTransaction?: { status: unknown } };
	try {
		r = (await suiClient.core.simulateTransaction({
			transaction,
			include: { effects: true },
		})) as { $kind: string; FailedTransaction?: { status: unknown } };
	} catch (e) {
		// RPC-level failure (network, malformed PTB, etc.). Surface as-is.
		const msg = e instanceof Error ? e.message : String(e);
		throw new Error(`Simulation could not run: ${msg}`);
	}
	if (r.$kind === 'Transaction') return;

	const status = r.FailedTransaction?.status;
	const decoded = decodeStatus(status);
	throw new Error(`Transaction would fail: ${decoded}`);
}

/**
 * Decode Sui's `FailedTransaction.status` into something a human can read.
 * Maps `MoveAbort` against the recovery package's abort codes when we can
 * recognize them; falls back to JSON otherwise.
 */
function decodeStatus(status: unknown): string {
	if (!status || typeof status !== 'object') return String(status);
	const s = status as Record<string, unknown>;

	const moveAbort = (s.MoveAbort ?? s.moveAbort) as
		| {
				abortCode?: string | number;
				location?: { module?: { name?: string; address?: string } } | string;
		  }
		| undefined;
	if (moveAbort) {
		const code = Number(moveAbort.abortCode);
		const loc =
			typeof moveAbort.location === 'object' && moveAbort.location?.module
				? moveAbort.location.module
				: null;
		const moduleName = loc?.name ?? '';
		const moduleAddr = loc?.address ?? '';
		const isRecoveryPkg =
			moduleAddr &&
			env.recoveryPackageId &&
			moduleAddr.toLowerCase() === env.recoveryPackageId.toLowerCase();
		if (isRecoveryPkg && moduleName === 'recovery') {
			const friendly = RECOVERY_ABORTS[code];
			if (friendly) return friendly;
		}
		if (isRecoveryPkg && moduleName === 'auth') {
			const friendly = AUTH_ABORTS[code];
			if (friendly) return friendly;
		}
		return `Move abort ${code}${moduleName ? ` in ${moduleName}` : ''}`;
	}

	if (typeof s.InsufficientGas === 'object' || s.kind === 'InsufficientGas') {
		return "Gas-payer wallet doesn't have enough SUI to cover this tx.";
	}

	return JSON.stringify(status);
}

const RECOVERY_ABORTS: Record<number, string> = {
	1: 'Threshold is invalid for the member count.',
	2: 'Need at least one initial member.',
	3: 'Too many members on the roster.',
	4: 'Sweep bundle is too large.',
	5: 'Sweep bundle is empty.',
	6: "Number of message signatures doesn't match the bundle.",
	7: 'This member already voted on this proposal.',
	8: 'Proposal has already been executed.',
	9: 'Approval threshold not reached yet.',
	10: 'This identity is already a member of the vault.',
	11: 'Proposal id not found.',
	12: 'Enrollment id not found.',
	13: 'Not enough presigns in the pool — replenish before proposing.',
	14: "Tx intent doesn't match the proposal it was bound to.",
	15: "Approver-only members can't execute (vote-only role).",
};

const AUTH_ABORTS: Record<number, string> = {
	// Filled out lazily as we encounter them.
};

function base64ToUint8(b64: string): Uint8Array {
	const s = atob(b64);
	const out = new Uint8Array(s.length);
	for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
	return out;
}
