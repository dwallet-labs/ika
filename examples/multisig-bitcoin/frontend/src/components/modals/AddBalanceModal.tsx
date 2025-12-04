'use client';

import { useState } from 'react';

import { Button } from '../ui/button';
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { RadioGroup, RadioGroupItem } from '../ui/radio-group';

interface AddBalanceModalProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onAddIka: (amount: bigint) => Promise<void>;
	onAddSui: (amount: bigint) => Promise<void>;
}

export function AddBalanceModal({ open, onOpenChange, onAddIka, onAddSui }: AddBalanceModalProps) {
	const [tokenType, setTokenType] = useState<'ika' | 'sui'>('ika');
	const [amount, setAmount] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);

	const handleSubmit = async () => {
		const numAmount = parseFloat(amount);
		if (isNaN(numAmount) || numAmount <= 0) {
			return;
		}

		setIsSubmitting(true);
		try {
			// Convert to MIST (9 decimals for both IKA and SUI)
			const amountInMist = BigInt(Math.floor(numAmount * 1_000_000_000));

			if (tokenType === 'ika') {
				await onAddIka(amountInMist);
			} else {
				await onAddSui(amountInMist);
			}

			// Reset form
			setAmount('');
			setTokenType('ika');
			onOpenChange(false);
		} catch (error) {
			// Error handling is done by the parent component
		} finally {
			setIsSubmitting(false);
		}
	};

	const isValid = amount && parseFloat(amount) > 0;

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Add Balance</DialogTitle>
					<DialogDescription>
						Add IKA or SUI tokens to the multisig for protocol fees and gas
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-4 py-4">
					<div className="space-y-2">
						<Label>Token Type</Label>
						<RadioGroup value={tokenType} onValueChange={(v) => setTokenType(v as 'ika' | 'sui')}>
							<div className="flex items-center space-x-2">
								<RadioGroupItem value="ika" id="ika" />
								<Label htmlFor="ika" className="font-normal cursor-pointer">
									IKA (for presign operations)
								</Label>
							</div>
							<div className="flex items-center space-x-2">
								<RadioGroupItem value="sui" id="sui" />
								<Label htmlFor="sui" className="font-normal cursor-pointer">
									SUI (for gas fees)
								</Label>
							</div>
						</RadioGroup>
					</div>

					<div className="space-y-2">
						<Label htmlFor="amount">Amount</Label>
						<Input
							id="amount"
							type="number"
							step="0.01"
							min="0"
							placeholder={`Enter ${tokenType.toUpperCase()} amount`}
							value={amount}
							onChange={(e) => setAmount(e.target.value)}
						/>
						<p className="text-xs text-muted-foreground">
							{tokenType === 'ika'
								? 'IKA tokens are used for presign operations and protocol fees'
								: 'SUI tokens are used for transaction gas fees'}
						</p>
					</div>
				</div>

				<DialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
						Cancel
					</Button>
					<Button onClick={handleSubmit} disabled={!isValid || isSubmitting}>
						{isSubmitting ? 'Adding...' : `Add ${tokenType.toUpperCase()}`}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}

