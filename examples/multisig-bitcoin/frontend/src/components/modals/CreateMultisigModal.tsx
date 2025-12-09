'use client';

import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Check, Coins, Plus, Trash2, Wallet, X } from 'lucide-react';
import { useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';
import { isValidSuiAddress, shorten } from '@/lib/formatting';

import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Skeleton } from '../ui/skeleton';

interface CreateMultisigModalProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onSubmit: (params: {
		members: string[];
		approvalThreshold: number;
		rejectionThreshold: number;
		expirationDuration: number;
	}) => Promise<void>;
	isCreating?: boolean;
	ikaPackageId?: string;
}

// Costs in base units (10^9 decimals)
const CREATION_COST_IKA = BigInt(10_000_000_000); // 10 IKA
const CREATION_COST_SUI = BigInt(1_000_000_000); // 1 SUI

const EXPIRATION_PRESETS = {
	'1d': { label: '1 Day', value: 86400 },
	'7d': { label: '7 Days', value: 604800 },
	'30d': { label: '30 Days', value: 2592000 },
	custom: { label: 'Custom', value: 0 },
};

export function CreateMultisigModal({
	open,
	onOpenChange,
	onSubmit,
	isCreating = false,
	ikaPackageId,
}: CreateMultisigModalProps) {
	const account = useCurrentAccount();
	const suiClient = useSuiClient();
	const [members, setMembers] = useState<string[]>([]);
	const [newMemberInput, setNewMemberInput] = useState('');
	const [approvalThreshold, setApprovalThreshold] = useState('2');
	const [rejectionThreshold, setRejectionThreshold] = useState('1');
	const [expirationPreset, setExpirationPreset] = useState('7d');
	const [customExpiration, setCustomExpiration] = useState('');

	// Fetch balances
	const { data: suiBalance, isLoading: isLoadingSui } = useQuery({
		queryKey: ['sui-balance', account?.address, open],
		queryFn: async () => {
			if (!account?.address) return null;
			const balance = await suiClient.getBalance({
				owner: account.address,
			});
			return balance;
		},
		enabled: !!account?.address && open,
	});

	const { data: ikaBalance, isLoading: isLoadingIka } = useQuery({
		queryKey: ['ika-balance', account?.address, ikaPackageId, open],
		queryFn: async () => {
			if (!account?.address || !ikaPackageId) return null;
			const balance = await suiClient.getBalance({
				owner: account.address,
				coinType: `${ikaPackageId}::ika::IKA`,
			});
			return balance;
		},
		enabled: !!account?.address && !!ikaPackageId && open,
	});

	const isNewMemberValid = newMemberInput.trim() && isValidSuiAddress(newMemberInput.trim());
	const isDuplicate = members.includes(newMemberInput.trim());

	// Check if user has sufficient balance
	const hasEnoughIka = ikaBalance ? BigInt(ikaBalance.totalBalance) >= CREATION_COST_IKA : false;
	const hasEnoughSui = suiBalance ? BigInt(suiBalance.totalBalance) >= CREATION_COST_SUI : false;
	const hasEnoughBalance = hasEnoughIka && hasEnoughSui;
	const isLoadingBalances = isLoadingSui || isLoadingIka;

	const isValid =
		members.length >= 2 &&
		members.every(isValidSuiAddress) &&
		Number(approvalThreshold) > 0 &&
		Number(approvalThreshold) <= members.length &&
		Number(rejectionThreshold) >= 0 &&
		Number(rejectionThreshold) < members.length &&
		hasEnoughBalance;

	const getExpirationValue = () => {
		if (expirationPreset === 'custom') {
			return Number(customExpiration) || 0;
		}
		return EXPIRATION_PRESETS[expirationPreset as keyof typeof EXPIRATION_PRESETS]?.value || 0;
	};

	const handleAddMember = () => {
		const address = newMemberInput.trim();
		if (!isValidSuiAddress(address)) {
			showErrorToast('Invalid Sui address');
			return;
		}
		if (members.includes(address)) {
			showErrorToast('This address is already added');
			return;
		}
		setMembers([...members, address]);
		setNewMemberInput('');
	};

	const handleRemoveMember = (address: string) => {
		setMembers(members.filter((m) => m !== address));
	};

	const handleKeyPress = (e: React.KeyboardEvent) => {
		if (e.key === 'Enter' && isNewMemberValid && !isDuplicate) {
			e.preventDefault();
			handleAddMember();
		}
	};

	const resetForm = () => {
		setMembers([]);
		setNewMemberInput('');
		setApprovalThreshold('2');
		setRejectionThreshold('1');
		setExpirationPreset('7d');
		setCustomExpiration('');
	};

	const handleSubmit = async () => {
		if (!hasEnoughBalance) {
			showErrorToast(
				'Insufficient balance',
				'You need at least 10 IKA and 1 SUI to create a multisig',
			);
			return;
		}

		if (!isValid) {
			showErrorToast('Please fill all fields correctly');
			return;
		}

		try {
			await onSubmit({
				members,
				approvalThreshold: Number(approvalThreshold),
				rejectionThreshold: Number(rejectionThreshold),
				expirationDuration: getExpirationValue(),
			});

			// Success - reset and close
			resetForm();
			onOpenChange(false);
		} catch (error) {
			// Error handling is done by parent, just rethrow
			throw error;
		}
	};

	const handleOpenChange = (newOpen: boolean) => {
		if (!newOpen && !isCreating) {
			resetForm();
		}
		onOpenChange(newOpen);
	};

	return (
		<Dialog open={open} onOpenChange={handleOpenChange}>
			<DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle>Create New Multisig</DialogTitle>
					<DialogDescription>
						Create a new Bitcoin multisig wallet controlled on Sui. Define members and approval
						thresholds.
					</DialogDescription>
				</DialogHeader>

				{/* Cost Display */}
				<div
					className={`rounded-lg border p-4 ${
						isLoadingBalances
							? 'bg-muted/50'
							: !hasEnoughBalance
								? 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800'
								: 'bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800'
					}`}
				>
					<div className="flex items-start gap-3">
						{isLoadingBalances ? (
							<Skeleton className="h-5 w-5 rounded" />
						) : !hasEnoughBalance ? (
							<AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
						) : (
							<Coins className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
						)}
						<div className="flex-1 space-y-2">
							<p
								className={`text-sm font-medium ${
									isLoadingBalances
										? 'text-muted-foreground'
										: !hasEnoughBalance
											? 'text-red-900 dark:text-red-100'
											: 'text-blue-900 dark:text-blue-100'
								}`}
							>
								{isLoadingBalances
									? 'Checking balance...'
									: !hasEnoughBalance
										? '⚠️ Insufficient Balance'
										: '💰 Creation Cost'}
							</p>
							<div className="grid grid-cols-2 gap-3 text-sm">
								<div className="flex items-center gap-2">
									<Coins className="h-4 w-4 text-primary" />
									<div>
										{isLoadingBalances ? (
											<Skeleton className="h-4 w-20" />
										) : (
											<>
												<span className="font-semibold">10 IKA</span>
												{ikaBalance && (
													<span
														className={`ml-2 text-xs ${
															hasEnoughIka
																? 'text-green-600 dark:text-green-500'
																: 'text-red-600 dark:text-red-500'
														}`}
													>
														(have: {(Number(ikaBalance.totalBalance) / 1_000_000_000).toFixed(2)})
													</span>
												)}
											</>
										)}
									</div>
								</div>
								<div className="flex items-center gap-2">
									<Wallet className="h-4 w-4 text-blue-500" />
									<div>
										{isLoadingBalances ? (
											<Skeleton className="h-4 w-20" />
										) : (
											<>
												<span className="font-semibold">1 SUI</span>
												{suiBalance && (
													<span
														className={`ml-2 text-xs ${
															hasEnoughSui
																? 'text-green-600 dark:text-green-500'
																: 'text-red-600 dark:text-red-500'
														}`}
													>
														(have: {(Number(suiBalance.totalBalance) / 1_000_000_000).toFixed(2)})
													</span>
												)}
											</>
										)}
									</div>
								</div>
							</div>
							{!isLoadingBalances && !hasEnoughBalance && (
								<p className="text-xs text-red-900/80 dark:text-red-100/80 mt-2">
									You need {!hasEnoughIka && '10 IKA'}
									{!hasEnoughIka && !hasEnoughSui && ' and '}
									{!hasEnoughSui && '1 SUI'} to create a multisig wallet.
								</p>
							)}
						</div>
					</div>
				</div>

				<div className="space-y-6 py-4">
					{/* Members Section */}
					<div className="space-y-3">
						<div className="flex items-center justify-between">
							<Label>
								Multisig Members <span className="text-destructive">*</span>
							</Label>
							<Badge variant={members.length >= 2 ? 'default' : 'secondary'}>
								{members.length} {members.length === 1 ? 'member' : 'members'}
							</Badge>
						</div>

						{/* Add Member Input */}
						<div className="flex gap-2">
							<div className="flex-1 relative">
								<Input
									placeholder="Enter Sui address (0x...)"
									value={newMemberInput}
									onChange={(e) => setNewMemberInput(e.target.value)}
									onKeyPress={handleKeyPress}
									className={
										newMemberInput.trim()
											? isNewMemberValid && !isDuplicate
												? 'border-green-500 dark:border-green-600'
												: 'border-red-500 dark:border-red-600'
											: ''
									}
								/>
								{newMemberInput.trim() && (
									<div className="absolute right-3 top-1/2 -translate-y-1/2">
										{isNewMemberValid && !isDuplicate ? (
											<Check className="h-4 w-4 text-green-500" />
										) : (
											<X className="h-4 w-4 text-red-500" />
										)}
									</div>
								)}
							</div>
							<Button
								type="button"
								onClick={handleAddMember}
								disabled={!isNewMemberValid || isDuplicate}
								size="sm"
							>
								<Plus className="h-4 w-4 mr-1" />
								Add
							</Button>
						</div>

						{newMemberInput.trim() && !isNewMemberValid && (
							<p className="text-xs text-red-500">Invalid Sui address format</p>
						)}
						{isDuplicate && <p className="text-xs text-red-500">This address is already added</p>}

						{members.length < 2 && (
							<Alert>
								<AlertDescription className="text-xs">
									Add at least 2 members to create a multisig wallet
								</AlertDescription>
							</Alert>
						)}

						{/* Members List */}
						{members.length > 0 && (
							<div className="border rounded-lg divide-y">
								{members.map((member, index) => (
									<div
										key={member}
										className="flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
									>
										<div className="flex items-center gap-3 flex-1 min-w-0">
											<Badge variant="outline" className="font-mono text-xs">
												#{index + 1}
											</Badge>
											<code className="text-sm flex-1 truncate" title={member}>
												{shorten(member, 16)}
											</code>
										</div>
										<Button
											variant="ghost"
											size="sm"
											onClick={() => handleRemoveMember(member)}
											className="text-destructive hover:text-destructive hover:bg-destructive/10"
										>
											<Trash2 className="h-4 w-4" />
										</Button>
									</div>
								))}
							</div>
						)}
					</div>

					{/* Thresholds */}
					<div className="grid grid-cols-2 gap-4">
						<div className="space-y-2">
							<Label htmlFor="approval">
								Approval Threshold <span className="text-destructive">*</span>
							</Label>
							<Input
								id="approval"
								type="number"
								min={1}
								max={members.length || 99}
								value={approvalThreshold}
								onChange={(e) => setApprovalThreshold(e.target.value)}
								className={
									members.length > 0 && Number(approvalThreshold) > members.length
										? 'border-red-500 dark:border-red-600'
										: members.length > 0 &&
											  Number(approvalThreshold) > 0 &&
											  Number(approvalThreshold) <= members.length
											? 'border-green-500 dark:border-green-600'
											: ''
								}
							/>
							<p className="text-xs text-muted-foreground">
								{members.length > 0
									? `Must be between 1 and ${members.length}`
									: 'Number of approvals needed to execute a request'}
							</p>
							{members.length > 0 && Number(approvalThreshold) > members.length && (
								<p className="text-xs text-red-500">
									Cannot exceed number of members ({members.length})
								</p>
							)}
							{members.length > 0 &&
								Number(approvalThreshold) > 0 &&
								Number(approvalThreshold) <= members.length && (
									<p className="text-xs text-green-600 dark:text-green-500">Valid threshold</p>
								)}
						</div>

						<div className="space-y-2">
							<Label htmlFor="rejection">
								Rejection Threshold <span className="text-destructive">*</span>
							</Label>
							<Input
								id="rejection"
								type="number"
								min={0}
								max={(members.length || 99) - 1}
								value={rejectionThreshold}
								onChange={(e) => setRejectionThreshold(e.target.value)}
								className={
									members.length > 0 && Number(rejectionThreshold) >= members.length
										? 'border-red-500 dark:border-red-600'
										: members.length > 0 &&
											  Number(rejectionThreshold) >= 0 &&
											  Number(rejectionThreshold) < members.length
											? 'border-green-500 dark:border-green-600'
											: ''
								}
							/>
							<p className="text-xs text-muted-foreground">
								{members.length > 0
									? `Must be between 0 and ${members.length - 1}`
									: 'Number of rejections needed to cancel a request'}
							</p>
							{members.length > 0 && Number(rejectionThreshold) >= members.length && (
								<p className="text-xs text-red-500">
									Must be less than number of members ({members.length})
								</p>
							)}
							{members.length > 0 &&
								Number(rejectionThreshold) >= 0 &&
								Number(rejectionThreshold) < members.length && (
									<p className="text-xs text-green-600 dark:text-green-500">Valid threshold</p>
								)}
						</div>
					</div>

					{/* Expiration */}
					<div className="space-y-2">
						<Label htmlFor="expiration">
							Request Expiration <span className="text-destructive">*</span>
						</Label>
						<Select value={expirationPreset} onValueChange={setExpirationPreset}>
							<SelectTrigger>
								<SelectValue />
							</SelectTrigger>
							<SelectContent>
								{Object.entries(EXPIRATION_PRESETS).map(([key, { label }]) => (
									<SelectItem key={key} value={key}>
										{label}
									</SelectItem>
								))}
							</SelectContent>
						</Select>
						{expirationPreset === 'custom' && (
							<Input
								type="number"
								placeholder="Duration in seconds"
								value={customExpiration}
								onChange={(e) => setCustomExpiration(e.target.value)}
								className="mt-2"
							/>
						)}
						<p className="text-xs text-muted-foreground">
							How long requests remain valid before expiring
						</p>
					</div>
				</div>

				<div className="flex justify-end gap-2 pt-4 border-t">
					<Button variant="outline" onClick={() => handleOpenChange(false)} disabled={isCreating}>
						Cancel
					</Button>
					<Button
						onClick={handleSubmit}
						disabled={!isValid || isCreating || isLoadingBalances || !hasEnoughBalance}
					>
						{isCreating ? 'Creating...' : isLoadingBalances ? 'Checking...' : 'Create Multisig'}
					</Button>
				</div>
			</DialogContent>
		</Dialog>
	);
}
