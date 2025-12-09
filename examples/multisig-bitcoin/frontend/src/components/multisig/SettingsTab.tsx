'use client';

import { Coins, Plus, Settings2 } from 'lucide-react';

import { formatDuration, formatNumber } from '@/lib/formatting';

import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';

interface SettingsTabProps {
	approvalThreshold: number;
	rejectionThreshold: number;
	expirationDuration: number;
	network: 'mainnet' | 'testnet';
	ikaBalance: bigint;
	suiBalance: bigint;
	onChangeThreshold: () => void;
	onAddBalance: () => void;
}

export function SettingsTab({
	approvalThreshold,
	rejectionThreshold,
	expirationDuration,
	network,
	ikaBalance,
	suiBalance,
	onChangeThreshold,
	onAddBalance,
}: SettingsTabProps) {
	// Convert balances to human-readable format
	// IKA has 9 decimals, SUI has 9 decimals
	const ikaBalanceFormatted = (Number(ikaBalance) / 1_000_000_000).toFixed(2);
	const suiBalanceFormatted = (Number(suiBalance) / 1_000_000_000).toFixed(4);

	return (
		<div className="space-y-6">
			<div>
				<h3 className="text-lg font-semibold mb-1">Multisig Settings</h3>
				<p className="text-sm text-muted-foreground">
					Current configuration and balances for this multisig wallet
				</p>
			</div>

			{/* Protocol Balances Section */}
			<div>
				<div className="flex items-center justify-between mb-3">
					<h4 className="text-sm font-medium flex items-center gap-2">
						<Coins className="h-4 w-4" />
						Protocol Balances
					</h4>
					<Button size="sm" variant="outline" onClick={onAddBalance}>
						<Plus className="h-4 w-4 mr-2" />
						Add Balance
					</Button>
				</div>
				<div className="grid gap-4 md:grid-cols-2">
					<Card>
						<CardHeader>
							<CardTitle className="text-base">IKA Balance</CardTitle>
							<CardDescription>Used for presign operations and protocol fees</CardDescription>
						</CardHeader>
						<CardContent>
							<div className="text-2xl font-semibold">{ikaBalanceFormatted} IKA</div>
							<div className="text-xs text-muted-foreground mt-1">
								{formatNumber(ikaBalance)} MIST
							</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader>
							<CardTitle className="text-base">SUI Balance</CardTitle>
							<CardDescription>Used for transaction gas fees</CardDescription>
						</CardHeader>
						<CardContent>
							<div className="text-2xl font-semibold">{suiBalanceFormatted} SUI</div>
							<div className="text-xs text-muted-foreground mt-1">
								{formatNumber(suiBalance)} MIST
							</div>
						</CardContent>
					</Card>
				</div>
			</div>

			{/* Governance Settings Section */}
			<div>
				<h4 className="text-sm font-medium mb-3 flex items-center gap-2">
					<Settings2 className="h-4 w-4" />
					Governance Settings
				</h4>
				<div className="grid gap-4">
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Network</CardTitle>
							<CardDescription>Bitcoin network this multisig operates on</CardDescription>
						</CardHeader>
						<CardContent>
							<Badge variant={network === 'mainnet' ? 'default' : 'secondary'}>
								{network === 'mainnet' ? 'Mainnet' : 'Testnet'}
							</Badge>
						</CardContent>
					</Card>

					<Card>
						<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
							<div>
								<CardTitle className="text-base">Approval Threshold</CardTitle>
								<CardDescription>Signatures required to approve requests</CardDescription>
							</div>
							<Button size="sm" variant="outline" onClick={onChangeThreshold}>
								<Settings2 className="h-4 w-4 mr-2" />
								Change
							</Button>
						</CardHeader>
						<CardContent>
							<div className="text-2xl font-semibold">{approvalThreshold}</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
							<div>
								<CardTitle className="text-base">Rejection Threshold</CardTitle>
								<CardDescription>Signatures required to reject requests</CardDescription>
							</div>
							<Button size="sm" variant="outline" onClick={onChangeThreshold}>
								<Settings2 className="h-4 w-4 mr-2" />
								Change
							</Button>
						</CardHeader>
						<CardContent>
							<div className="text-2xl font-semibold">{rejectionThreshold}</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
							<div>
								<CardTitle className="text-base">Request Expiration</CardTitle>
								<CardDescription>How long requests remain valid</CardDescription>
							</div>
							<Button size="sm" variant="outline" onClick={onChangeThreshold}>
								<Settings2 className="h-4 w-4 mr-2" />
								Change
							</Button>
						</CardHeader>
						<CardContent>
							<div className="text-2xl font-semibold">{formatDuration(expirationDuration)}</div>
						</CardContent>
					</Card>
				</div>
			</div>
		</div>
	);
}
