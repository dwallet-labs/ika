import { useCurrentAccount, useCurrentClient } from '@mysten/dapp-kit-react';
import { Transaction } from '@mysten/sui/transactions';
import { fromBase64 } from '@mysten/sui/utils';
import { useQueryClient } from '@tanstack/react-query';

import { dAppKit } from '../lib/sui';

export const useExecuteTransaction = () => {
	const suiClient = useCurrentClient();
	const queryClient = useQueryClient();
	const account = useCurrentAccount();

	const executeTransaction = async (tx: Transaction) => {
		// dApp Kit 2.x exposes wallet actions directly rather than through hooks.
		const signedTransaction = await dAppKit.signTransaction({
			transaction: tx,
		});

		// Execute. The Core API takes raw bytes and answers with a discriminated
		// union rather than throwing on an on-chain failure.
		const executed = await suiClient.executeTransaction({
			transaction: fromBase64(signedTransaction.bytes),
			signatures: [signedTransaction.signature],
			include: { effects: true, events: true, balanceChanges: true },
		});

		const executedTransaction = executed.Transaction ?? executed.FailedTransaction;

		// Wait
		const waited = await suiClient.waitForTransaction({
			digest: executedTransaction.digest,
			include: { effects: true, events: true, balanceChanges: true },
		});

		const res2 = waited.Transaction ?? waited.FailedTransaction;

		// Automatically invalidate multisig data and balances after transaction completes
		// This will trigger a refetch of all related queries
		if (account) {
			// Invalidate all queries in parallel for faster UI updates
			await Promise.all([
				// Old combined query (for backwards compatibility)
				queryClient.invalidateQueries({
					queryKey: ['multisigOwnership', account.address],
				}),
				// New granular queries
				queryClient.invalidateQueries({
					queryKey: ['multisigOwnerships', account.address],
				}),
				queryClient.invalidateQueries({
					queryKey: ['multisigs'],
				}),
				queryClient.invalidateQueries({
					queryKey: ['multisigRequests'],
				}),
				queryClient.invalidateQueries({
					queryKey: ['multipleMultisigRequests'],
				}),
				// Balance queries
				queryClient.invalidateQueries({
					queryKey: ['sui-balance', account.address],
				}),
				queryClient.invalidateQueries({
					queryKey: ['ika-balance', account.address],
				}),
				// Invalidate all Bitcoin balance queries since we don't know which addresses are affected
				queryClient.invalidateQueries({
					queryKey: ['btc-balance'],
				}),
			]);
		}

		return res2;
	};

	return { executeTransaction };
};
