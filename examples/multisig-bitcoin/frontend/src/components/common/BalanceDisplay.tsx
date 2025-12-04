'use client';

import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { useQuery } from '@tanstack/react-query';
import { Coins, Wallet } from 'lucide-react';

import { Badge } from '../ui/badge';
import { Skeleton } from '../ui/skeleton';

interface BalanceDisplayProps {
	ikaPackageId?: string;
}

export function BalanceDisplay({ ikaPackageId }: BalanceDisplayProps) {
	const account = useCurrentAccount();
	const suiClient = useSuiClient();

	const { data: suiBalance, isLoading: isLoadingSui } = useQuery({
		queryKey: ['sui-balance', account?.address],
		queryFn: async () => {
			if (!account?.address) return null;
			const balance = await suiClient.getBalance({
				owner: account.address,
			});
			return balance;
		},
		enabled: !!account?.address,
		refetchInterval: 10000, // Refetch every 10 seconds
	});

	const { data: ikaBalance, isLoading: isLoadingIka } = useQuery({
		queryKey: ['ika-balance', account?.address, ikaPackageId],
		queryFn: async () => {
			if (!account?.address || !ikaPackageId) return null;
			const balance = await suiClient.getBalance({
				owner: account.address,
				coinType: `${ikaPackageId}::ika::IKA`,
			});
			return balance;
		},
		enabled: !!account?.address && !!ikaPackageId,
		refetchInterval: 10000, // Refetch every 10 seconds
	});

	if (!account) {
		return null;
	}

	const formatBalance = (balance: string | undefined, decimals: number = 9) => {
		if (!balance) return '0.00';
		const num = Number(balance) / Math.pow(10, decimals);
		return num.toLocaleString('en-US', {
			minimumFractionDigits: 2,
			maximumFractionDigits: 2,
		});
	};

	return (
		<div className="hidden md:flex items-center gap-2 mr-3">
			{/* IKA Balance */}
			<div className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 rounded-lg border border-primary/20">
				<Coins className="h-4 w-4 text-primary" />
				<div className="flex flex-col">
					{isLoadingIka ? (
						<Skeleton className="h-4 w-16" />
					) : (
						<div className="flex items-baseline gap-1">
							<span className="text-sm font-semibold text-primary">
								{formatBalance(ikaBalance?.totalBalance)}
							</span>
							<span className="text-xs text-muted-foreground">IKA</span>
						</div>
					)}
				</div>
			</div>

			{/* SUI Balance */}
			<div className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-500/10 rounded-lg border border-blue-500/20">
				<Wallet className="h-4 w-4 text-blue-500" />
				<div className="flex flex-col">
					{isLoadingSui ? (
						<Skeleton className="h-4 w-16" />
					) : (
						<div className="flex items-baseline gap-1">
							<span className="text-sm font-semibold text-blue-500">
								{formatBalance(suiBalance?.totalBalance)}
							</span>
							<span className="text-xs text-muted-foreground">SUI</span>
						</div>
					)}
				</div>
			</div>
		</div>
	);
}
