import { useCurrentAccount, useSignTransaction, useSuiClient } from '@mysten/dapp-kit';
import { Transaction } from '@mysten/sui/transactions';
import { useQueryClient } from '@tanstack/react-query';

export const useExecuteTransaction = () => {
	const suiClient = useSuiClient();
	const { mutateAsync: signTransaction } = useSignTransaction();
	const queryClient = useQueryClient();
	const account = useCurrentAccount();

	const executeTransaction = async (tx: Transaction) => {
		const signedTransaction = await signTransaction({
			transaction: tx,
		});

		// Execute
		const res1 = await suiClient.executeTransactionBlock({
			transactionBlock: signedTransaction.bytes,
			signature: signedTransaction.signature,
		});

		// Wait
		const res2 = await suiClient.waitForTransaction({
			digest: res1.digest,
			options: {
				showEffects: true,
				showBalanceChanges: true,
				showEvents: true,
			},
		});

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
