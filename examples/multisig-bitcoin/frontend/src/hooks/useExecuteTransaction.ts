import { useSignTransaction, useSuiClient } from '@mysten/dapp-kit';
import { Transaction } from '@mysten/sui/transactions';

export const useExecuteTransaction = () => {
	const suiClient = useSuiClient();
	const { mutateAsync: signTransaction } = useSignTransaction();

	const executeTransaction = async (tx: Transaction) => {
		const signedTransaction = await signTransaction({
			// @todo(fesal): Fix this type error
			// @ts-expect-error - Transaction is not assignable to type 'string | Transaction'
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

		return res2;
	};

	return { executeTransaction };
};
