'use client';

import { moveRecovery, type TransactionExecuteResult } from '@fesal-packages/ikavery-sui-sdk';
import { getNetworkConfig } from '@ika.xyz/sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { isValidSuiAddress, normalizeSuiAddress } from '@mysten/sui/utils';

import { env } from './env';

/**
 * Per-presign Ika fee on testnet. Derived from the testnet validator fee
 * schedule — under-fees fail at session-init with EInsufficientIKAPayment.
 */
export const PRESIGN_IKA_PER_CALL = 500_000_000n;

/**
 * Per-presign SUI fee. Each presign session opens its own slot, so SUI scales
 * linearly with `count`. The 50M figure mirrors the e2e flows.
 */
export const PRESIGN_SUI_PER_CALL = 50_000_000n;

export interface ReplenishParams {
	recoveryId: string;
	count: number;
	/**
	 * Sui address that pays — leftover IKA/SUI from the fee coins flow back
	 * here. The Move call borrows both coins as `&mut`, so we must transfer
	 * them somewhere or the PTB fails with an unused-resource error.
	 */
	payerAddress: string;
	/**
	 * Used to pre-resolve `coinWithBalance` (calls `core.listCoins`). Dapp-kit's
	 * bundled SuiClient is on an older API surface that lacks `listCoins`, so we
	 * resolve here with the recovery client's ClientWithCoreApi and hand the
	 * wallet a fully-built tx.
	 */
	suiClient: ClientWithCoreApi;
	signAndExecute: (tx: Transaction) => Promise<TransactionExecuteResult>;
}

export interface ReplenishResult {
	digest: string;
	count: number;
	/** Total IKA committed (mIKA — divide by 1e9 for IKA). */
	ikaCommitted: bigint;
	suiCommitted: bigint;
}

export async function replenishPresigns(params: ReplenishParams): Promise<ReplenishResult> {
	if (params.count < 1) throw new Error('replenishPresigns: count must be at least 1');

	const recoveryId = ensureSuiAddress('recoveryId', params.recoveryId);
	const payerAddress = ensureSuiAddress('payerAddress', params.payerAddress);

	const config = getNetworkConfig(env.network);
	const coordinatorId = ensureSuiAddress(
		'coordinatorObjectId',
		config.objects.ikaDWalletCoordinator.objectID,
	);
	const packageId = ensureSuiAddress('recoveryPackageId', env.recoveryPackageId);

	const totalIka = PRESIGN_IKA_PER_CALL * BigInt(params.count);
	const totalSui = PRESIGN_SUI_PER_CALL * BigInt(params.count);
	const ikaType = `${config.packages.ikaPackage}::ika::IKA`;

	const tx = new Transaction();
	tx.setSender(payerAddress);
	const ikaCoin = coinWithBalance({ balance: totalIka, type: ikaType });
	const suiCoin = coinWithBalance({ balance: totalSui });
	tx.add(
		moveRecovery.replenishPresigns({
			package: packageId,
			arguments: [recoveryId, coordinatorId, BigInt(params.count), ikaCoin, suiCoin],
		}),
	);
	tx.transferObjects([ikaCoin, suiCoin], payerAddress);

	// Resolve coinWithBalance against our ClientWithCoreApi and reconstruct the
	// tx so the wallet's older client never needs to call core.listCoins.
	const txJson = await tx.toJSON({ client: params.suiClient });
	const resolved = Transaction.from(txJson);

	const result = await params.signAndExecute(resolved);
	if (result.$kind !== 'Transaction') {
		throw new Error(`replenishPresigns failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}
	return {
		digest: result.Transaction.digest,
		count: params.count,
		ikaCommitted: totalIka,
		suiCommitted: totalSui,
	};
}

function ensureSuiAddress(label: string, value: string | undefined): string {
	if (!value) {
		throw new Error(`replenishPresigns: ${label} is missing`);
	}
	const normalized = normalizeSuiAddress(value);
	if (!isValidSuiAddress(normalized)) {
		throw new Error(`replenishPresigns: ${label} is not a valid Sui address: ${value}`);
	}
	return normalized;
}
