import { ArrowLeft, Bitcoin, Send, Users } from 'lucide-react';
import React, { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useMultisig } from '@/contract/multisig';
import { validateAddress } from '@/lib/bitcoin-utils';

interface CreateTransactionProps {
	multisigId: string;
	bitcoinAddress: string;
	onClose: () => void;
}

interface TransactionData {
	recipient: string;
	amount: string;
	description: string;
}

export function CreateTransaction({ multisigId, bitcoinAddress, onClose }: CreateTransactionProps) {
	const [transaction, setTransaction] = useState<TransactionData>({
		recipient: '',
		amount: '',
		description: '',
	});
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const { createTransaction } = useMultisig();

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		if (!transaction.recipient || !transaction.amount) {
			setError('Please fill in all required fields');
			return;
		}

		// Validate recipient Bitcoin address
		if (!validateAddress(transaction.recipient)) {
			setError('Invalid recipient Bitcoin address');
			return;
		}

		const amount = parseFloat(transaction.amount);
		if (isNaN(amount) || amount <= 0) {
			setError('Please enter a valid positive amount');
			return;
		}

		try {
			setIsSubmitting(true);
			setError(null);

			// Create the actual Bitcoin transaction
			const result = await createTransaction(
				multisigId,
				amount,
				transaction.recipient,
				bitcoinAddress, // Use multisig bitcoin address as change address
				bitcoinAddress, // Use multisig bitcoin address as wallet address
			);

			console.log('Transaction created:', result);
			onClose();
		} catch (err) {
			console.error('Failed to create transaction:', err);
			setError(err instanceof Error ? err.message : 'Failed to create transaction');
		} finally {
			setIsSubmitting(false);
		}
	};

	const handleInputChange = (field: keyof TransactionData, value: string) => {
		setTransaction((prev) => ({
			...prev,
			[field]: value,
		}));
		if (error) setError(null);
	};

	return (
		<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
			<Card className="w-full max-w-md">
				<CardHeader>
					<div className="flex items-center gap-2">
						<Button variant="ghost" size="sm" onClick={onClose}>
							<ArrowLeft className="w-4 h-4" />
						</Button>
						<div>
							<CardTitle className="flex items-center gap-2">
								<Bitcoin className="w-5 h-5" />
								Create Bitcoin Transaction
							</CardTitle>
							<CardDescription>Send Bitcoin from your multisig wallet</CardDescription>
						</div>
					</div>
				</CardHeader>
				<CardContent>
					<div className="mb-6 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
						<h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
							Multisig Wallet Address
						</h3>
						<p className="text-sm text-gray-700 dark:text-gray-300 font-mono break-all">
							{bitcoinAddress}
						</p>
						<p className="text-xs text-gray-500 mt-2">
							Funds will be sent from this address, and any change will return to this address.
						</p>
					</div>

					<form onSubmit={handleSubmit} className="space-y-4">
						<div>
							<Label htmlFor="recipient">Recipient Bitcoin Address</Label>
							<Input
								id="recipient"
								type="text"
								placeholder="Enter Bitcoin address (testnet)"
								value={transaction.recipient}
								onChange={(e) => handleInputChange('recipient', e.target.value)}
								className="mt-1 font-mono text-sm"
							/>
							<p className="text-xs text-gray-500 mt-1">
								Testnet addresses start with 'tb1', 'm', or 'n'
							</p>
						</div>

						<div>
							<Label htmlFor="amount">Amount (BTC)</Label>
							<Input
								id="amount"
								type="number"
								step="0.00000001"
								min="0"
								placeholder="0.00000000"
								value={transaction.amount}
								onChange={(e) => handleInputChange('amount', e.target.value)}
								className="mt-1"
							/>
						</div>

						<div>
							<Label htmlFor="description">Description (Optional)</Label>
							<Input
								id="description"
								type="text"
								placeholder="What's this transaction for?"
								value={transaction.description}
								onChange={(e) => handleInputChange('description', e.target.value)}
								className="mt-1"
							/>
						</div>

						{error && (
							<div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 p-3 rounded-lg">
								{error}
							</div>
						)}

						<div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg mb-4">
							<div className="flex items-center gap-2 mb-2">
								<Bitcoin className="w-4 h-4 text-orange-600 dark:text-orange-400" />
								<span className="text-sm font-medium text-orange-900 dark:text-orange-100">
									Bitcoin Testnet
								</span>
							</div>
							<div className="text-sm text-orange-700 dark:text-orange-300">
								This transaction will be created on Bitcoin testnet. Use testnet addresses only.
							</div>
						</div>

						<div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
							<div className="flex items-center gap-2 mb-2">
								<Users className="w-4 h-4 text-blue-600 dark:text-blue-400" />
								<span className="text-sm font-medium text-blue-900 dark:text-blue-100">
									Multisig Requirements
								</span>
							</div>
							<div className="text-sm text-blue-700 dark:text-blue-300">
								This Bitcoin transaction requires 2 out of 3 signatures to execute
							</div>
						</div>

						<div className="flex gap-2">
							<Button type="button" variant="outline" onClick={onClose} className="flex-1">
								Cancel
							</Button>
							<Button type="submit" disabled={isSubmitting} className="flex-1">
								{isSubmitting ? (
									<>
										<div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
										Creating Bitcoin Transaction...
									</>
								) : (
									<>
										<Bitcoin className="w-4 h-4 mr-2" />
										Create Bitcoin Transaction
									</>
								)}
							</Button>
						</div>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
