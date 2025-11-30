'use client';

import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';
import { formatSats, isValidBitcoinAddress, shorten } from '@/lib/formatting';
import type { MultisigBitcoinWallet, UTXO } from '@/multisig/bitcoin';

import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Skeleton } from '../ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';

interface SendTransactionModalProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	multisig: MultisigBitcoinWallet;
	onSubmit: (params: {
		toAddress: string;
		amount: bigint;
		feeRate: number;
		utxo: UTXO;
	}) => Promise<void>;
}

export function SendTransactionModal({
	open,
	onOpenChange,
	multisig,
	onSubmit,
}: SendTransactionModalProps) {
	const [step, setStep] = useState(1);
	const [toAddress, setToAddress] = useState('');
	const [amountSats, setAmountSats] = useState('');
	const [feeRate, setFeeRate] = useState('10');
	const [isSubmitting, setIsSubmitting] = useState(false);

	const {
		data: utxos,
		isLoading: isLoadingUtxos,
		refetch: refetchUtxos,
	} = useQuery({
		queryKey: ['btc-utxos', multisig.getAddress(), open],
		queryFn: async () => multisig.getUTXOs(),
		enabled: open && step >= 2,
	});

	const selectedUtxo = useMemo(() => {
		if (!utxos || !amountSats) return null;
		const amount = BigInt(amountSats || '0');
		return multisig.findSuitableUTXO(utxos, amount, Number(feeRate));
	}, [utxos, amountSats, feeRate, multisig]);

	const resetForm = () => {
		setStep(1);
		setToAddress('');
		setAmountSats('');
		setFeeRate('10');
		setIsSubmitting(false);
	};

	const handleNext = () => {
		if (step === 1) {
			if (!isValidBitcoinAddress(toAddress)) {
				showErrorToast('Invalid Bitcoin address');
				return;
			}
			if (!amountSats || Number(amountSats) <= 0) {
				showErrorToast('Invalid amount');
				return;
			}
			setStep(2);
		} else if (step === 2) {
			setStep(3);
		}
	};

	const handleSubmit = async () => {
		if (!selectedUtxo) {
			showErrorToast('No suitable UTXO found');
			return;
		}

		setIsSubmitting(true);
		try {
			await onSubmit({
				toAddress,
				amount: BigInt(amountSats),
				feeRate: Number(feeRate),
				utxo: selectedUtxo,
			});

			showSuccessToast('Transaction request created!');
			resetForm();
			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to create transaction request');
		} finally {
			setIsSubmitting(false);
		}
	};

	const handleOpenChange = (open: boolean) => {
		if (!open) {
			resetForm();
		}
		onOpenChange(open);
	};

	return (
		<Dialog open={open} onOpenChange={handleOpenChange}>
			<DialogContent className="max-w-2xl">
				<DialogHeader>
					<DialogTitle>Send Bitcoin</DialogTitle>
					<DialogDescription>
						Create a transaction request to send BTC from this multisig wallet
					</DialogDescription>
				</DialogHeader>

				{/* Step Indicator */}
				<div className="flex items-center justify-center gap-2 py-2">
					{[1, 2, 3].map((s) => (
						<div key={s} className="flex items-center">
							<div
								className={`h-8 w-8 rounded-full flex items-center justify-center text-sm font-medium ${
									s === step
										? 'bg-primary text-primary-foreground'
										: s < step
											? 'bg-primary/20 text-primary'
											: 'bg-muted text-muted-foreground'
								}`}
							>
								{s}
							</div>
							{s < 3 && (
								<div className={`h-0.5 w-12 mx-1 ${s < step ? 'bg-primary' : 'bg-muted'}`} />
							)}
						</div>
					))}
				</div>

				<div className="space-y-4">
					{/* Step 1: Enter Details */}
					{step === 1 && (
						<div className="space-y-4">
							<div className="space-y-2">
								<Label htmlFor="recipient">
									Recipient Address <span className="text-destructive">*</span>
								</Label>
								<Input
									id="recipient"
									placeholder="tb1... or bc1..."
									value={toAddress}
									onChange={(e) => setToAddress(e.target.value)}
									className={
										toAddress.trim()
											? isValidBitcoinAddress(toAddress)
												? 'border-green-500 dark:border-green-600'
												: 'border-red-500 dark:border-red-600'
											: ''
									}
								/>
								{toAddress.trim() && !isValidBitcoinAddress(toAddress) && (
									<p className="text-xs text-red-500">Invalid Bitcoin address</p>
								)}
								{isValidBitcoinAddress(toAddress) && (
									<p className="text-xs text-green-600 dark:text-green-500">
										Valid Bitcoin address
									</p>
								)}
							</div>

							<div className="grid grid-cols-2 gap-4">
								<div className="space-y-2">
									<Label htmlFor="amount">
										Amount (sats) <span className="text-destructive">*</span>
									</Label>
									<Input
										id="amount"
										type="number"
										min={1}
										placeholder="10000"
										value={amountSats}
										onChange={(e) => setAmountSats(e.target.value)}
									/>
									{amountSats && Number(amountSats) > 0 ? (
										<p className="text-xs text-muted-foreground">
											≈ {(Number(amountSats) / 100_000_000).toFixed(8)} BTC
										</p>
									) : (
										<p className="text-xs text-muted-foreground">Enter amount in satoshis</p>
									)}
								</div>

								<div className="space-y-2">
									<Label htmlFor="feeRate">
										Fee Rate (sat/vB) <span className="text-destructive">*</span>
									</Label>
									<Input
										id="feeRate"
										type="number"
										min={1}
										placeholder="10"
										value={feeRate}
										onChange={(e) => setFeeRate(e.target.value)}
									/>
									<p className="text-xs text-muted-foreground">Higher = faster confirmation</p>
								</div>
							</div>

							<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
								<p className="text-sm text-blue-900 dark:text-blue-100">
									💡 The transaction will automatically select the best UTXO to use based on the
									amount and fee rate.
								</p>
							</div>
						</div>
					)}

					{/* Step 2: Select UTXO */}
					{step === 2 && (
						<div className="space-y-4">
							<div className="flex items-center justify-between">
								<h4 className="text-sm font-medium">Available UTXOs</h4>
								<Button
									variant="outline"
									size="sm"
									onClick={() => refetchUtxos()}
									disabled={isLoadingUtxos}
								>
									{isLoadingUtxos ? 'Loading...' : 'Refresh'}
								</Button>
							</div>

							{isLoadingUtxos ? (
								<div className="space-y-2">
									<Skeleton className="h-12 w-full" />
									<Skeleton className="h-12 w-full" />
								</div>
							) : utxos && utxos.length > 0 ? (
								<div className="border rounded-md">
									<Table>
										<TableHeader>
											<TableRow>
												<TableHead>TXID</TableHead>
												<TableHead>Vout</TableHead>
												<TableHead>Value</TableHead>
												<TableHead>Status</TableHead>
											</TableRow>
										</TableHeader>
										<TableBody>
											{utxos.map((utxo) => {
												const isSelected =
													selectedUtxo &&
													utxo.txid === selectedUtxo.txid &&
													utxo.vout === selectedUtxo.vout;
												return (
													<TableRow key={`${utxo.txid}:${utxo.vout}`}>
														<TableCell className="font-mono text-xs">
															{shorten(utxo.txid, 8)}
														</TableCell>
														<TableCell>{utxo.vout}</TableCell>
														<TableCell>{formatSats(utxo.value)}</TableCell>
														<TableCell>
															{isSelected ? (
																<Badge>Selected</Badge>
															) : (
																<Badge variant="outline">Available</Badge>
															)}
														</TableCell>
													</TableRow>
												);
											})}
										</TableBody>
									</Table>
								</div>
							) : (
								<div className="text-center py-8 text-muted-foreground">No UTXOs available</div>
							)}

							{selectedUtxo && (
								<div className="bg-muted rounded-md p-3 text-sm">
									<p className="font-medium mb-1">Auto-selected UTXO:</p>
									<p className="text-muted-foreground">
										{shorten(selectedUtxo.txid, 8)}:{selectedUtxo.vout} •{' '}
										{formatSats(selectedUtxo.value)}
									</p>
								</div>
							)}
						</div>
					)}

					{/* Step 3: Review */}
					{step === 3 && (
						<div className="space-y-4">
							<div className="bg-muted rounded-md p-4 space-y-3">
								<div className="flex justify-between">
									<span className="text-sm text-muted-foreground">Recipient</span>
									<span className="text-sm font-mono">{shorten(toAddress, 12)}</span>
								</div>
								<div className="flex justify-between">
									<span className="text-sm text-muted-foreground">Amount</span>
									<span className="text-sm font-medium">{formatSats(amountSats)}</span>
								</div>
								<div className="flex justify-between">
									<span className="text-sm text-muted-foreground">Fee Rate</span>
									<span className="text-sm">{feeRate} sat/vB</span>
								</div>
								{selectedUtxo && (
									<div className="flex justify-between">
										<span className="text-sm text-muted-foreground">Using UTXO</span>
										<span className="text-sm font-mono">
											{shorten(selectedUtxo.txid, 8)}:{selectedUtxo.vout}
										</span>
									</div>
								)}
							</div>

							<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
								<p className="text-sm text-blue-900 dark:text-blue-100">
									This will create a transaction request that requires approval from other multisig
									members.
								</p>
							</div>
						</div>
					)}
				</div>

				<div className="flex justify-between">
					{step > 1 ? (
						<Button variant="outline" onClick={() => setStep(step - 1)} disabled={isSubmitting}>
							Back
						</Button>
					) : (
						<Button variant="outline" onClick={() => handleOpenChange(false)}>
							Cancel
						</Button>
					)}

					{step < 3 ? (
						<Button onClick={handleNext} disabled={step === 2 && !selectedUtxo}>
							Next
						</Button>
					) : (
						<Button onClick={handleSubmit} disabled={!selectedUtxo || isSubmitting}>
							{isSubmitting ? 'Creating...' : 'Create Request'}
						</Button>
					)}
				</div>
			</DialogContent>
		</Dialog>
	);
}
