// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { IkaConfig } from '@ika.xyz/sdk';
import { coinWithBalance } from '@mysten/sui/transactions';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { SuiTxExecutionResult } from './types.js';

/**
 * Per-tx fee carrier. Holds the IKA and SUI coin handles plus a `finalize`
 * helper that transfers them (and any caller-supplied extras) back to the
 * signer. Coordinator Move calls take `&mut Coin<...>`, so the handles
 * remain valid after the call and must be transferred (or otherwise
 * consumed) before the PTB completes; dropping them is a PTB error.
 */
export interface PaymentBag {
	readonly ika: TransactionObjectArgument;
	readonly sui: TransactionObjectArgument;
	finalize(...extras: TransactionObjectArgument[]): void;
}

export interface PayOptions {
	readonly ikaFee: bigint;
	readonly suiGas: bigint;
	readonly ikaConfig: IkaConfig;
	readonly signerAddress: string;
}

export function makePay(opts: PayOptions): (tx: Transaction) => PaymentBag {
	const ikaType = `${opts.ikaConfig.packages.ikaPackage}::ika::IKA`;
	return (tx: Transaction): PaymentBag => {
		const ika = tx.add(coinWithBalance({ balance: opts.ikaFee, type: ikaType }));
		const sui = tx.splitCoins(tx.gas, [opts.suiGas]);
		return {
			ika,
			sui,
			finalize: (...extras: TransactionObjectArgument[]): void => {
				tx.transferObjects([...extras, ika, sui], opts.signerAddress);
			},
		};
	};
}

export interface ExecOptions {
	/**
	 * Submits a signed transaction and returns its execution result. Built
	 * once at source-construction time by normalizing the `SuiSigner`
	 * union: keypair signers wrap `suiClient.signAndExecuteTransaction`,
	 * wallet signers delegate to the caller's
	 * `signAndExecuteTransaction`. Either way the result MUST carry
	 * `events`, since downstream code parses Move events to extract
	 * presign / sign / dWallet ids.
	 */
	readonly signAndExecute: (tx: Transaction) => Promise<SuiTxExecutionResult>;
	readonly postTxSleepMs: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Signs and executes a tx, sleeps briefly so RPC indexing catches up, returns the result with events. */
export function makeExec(opts: ExecOptions): (tx: Transaction) => Promise<SuiTxExecutionResult> {
	return async (tx: Transaction) => {
		const result = await opts.signAndExecute(tx);
		await sleep(opts.postTxSleepMs);
		return result;
	};
}
