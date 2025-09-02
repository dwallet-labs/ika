import { ArrowLeft, Send, Users } from 'lucide-react';
import React, { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface CreateTransactionProps {
	multisigId: string;
	onClose: () => void;
}

interface TransactionData {
	recipient: string;
	amount: string;
	description: string;
}

export function CreateTransaction({ multisigId, onClose }: CreateTransactionProps) {
	const [transaction, setTransaction] = useState<TransactionData>({
		recipient: '',
		amount: '',
		description: '',
	});
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		if (!transaction.recipient || !transaction.amount) {
			setError('Please fill in all required fields');
			return;
		}

		try {
			setIsSubmitting(true);
			setError(null);

			// Here you would integrate with the actual transaction creation logic
			// For now, we'll just simulate the process
			await new Promise((resolve) => setTimeout(resolve, 2000));

			console.log('Creating transaction:', {
				multisigId,
				...transaction,
			});

			// In a real implementation, this would:
			// 1. Create the transaction using the multisig contract
			// 2. Submit it for approval from other signers
			// 3. Wait for confirmations

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
								<Send className="w-5 h-5" />
								Create Transaction
							</CardTitle>
							<CardDescription>Send funds from your multisig wallet</CardDescription>
						</div>
					</div>
				</CardHeader>
				<CardContent>
					<form onSubmit={handleSubmit} className="space-y-4">
						<div>
							<Label htmlFor="recipient">Recipient Address</Label>
							<Input
								id="recipient"
								type="text"
								placeholder="Enter recipient address"
								value={transaction.recipient}
								onChange={(e) => handleInputChange('recipient', e.target.value)}
								className="mt-1"
							/>
						</div>

						<div>
							<Label htmlFor="amount">Amount (SUI)</Label>
							<Input
								id="amount"
								type="number"
								step="0.000000001"
								placeholder="0.00"
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

						<div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
							<div className="flex items-center gap-2 mb-2">
								<Users className="w-4 h-4 text-blue-600 dark:text-blue-400" />
								<span className="text-sm font-medium text-blue-900 dark:text-blue-100">
									Multisig Requirements
								</span>
							</div>
							<div className="text-sm text-blue-700 dark:text-blue-300">
								This transaction requires 2 out of 3 signatures to execute
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
										Creating...
									</>
								) : (
									<>
										<Send className="w-4 h-4 mr-2" />
										Create Transaction
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
