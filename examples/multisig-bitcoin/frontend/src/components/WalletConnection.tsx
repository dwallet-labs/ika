import { useCurrentAccount, useDisconnectWallet } from '@mysten/dapp-kit';
import { CheckCircle, Copy, LogOut, Wallet } from 'lucide-react';
import { useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export function WalletConnection() {
	const currentAccount = useCurrentAccount();
	const { mutate: disconnect } = useDisconnectWallet();
	const [copied, setCopied] = useState(false);

	const truncateAddress = (address: string) => {
		return `${address.slice(0, 6)}...${address.slice(-4)}`;
	};

	const copyToClipboard = async (text: string) => {
		try {
			await navigator.clipboard.writeText(text);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	};

	if (!currentAccount) {
		return (
			<Card className="mb-6">
				<CardHeader>
					<CardTitle className="flex items-center gap-2">
						<Wallet className="w-5 h-5" />
						Connect Wallet
					</CardTitle>
					<CardDescription>
						Connect your Sui wallet to create and manage multisignature wallets
					</CardDescription>
				</CardHeader>
				<CardContent>
					<div className="text-center">
						<p className="text-gray-600 dark:text-gray-300 mb-4">
							You need to connect a Sui wallet to use the multisig functionality.
						</p>
						<div className="text-sm text-gray-500 dark:text-gray-400">
							Supported wallets: Sui Wallet, Ethos, etc.
						</div>
					</div>
				</CardContent>
			</Card>
		);
	}

	return (
		<Card className="mb-6">
			<CardHeader>
				<CardTitle className="flex items-center gap-2">
					<Wallet className="w-5 h-5" />
					Connected Wallet
				</CardTitle>
				<CardDescription>Your wallet is connected and ready to use</CardDescription>
			</CardHeader>
			<CardContent>
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<div className="flex items-center gap-2">
							<CheckCircle className="w-4 h-4 text-green-500" />
							<Badge variant="default">Connected</Badge>
						</div>
						<div className="flex items-center gap-2">
							<code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
								{truncateAddress(currentAccount.address)}
							</code>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => copyToClipboard(currentAccount.address)}
							>
								{copied ? <CheckCircle className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
							</Button>
						</div>
					</div>
					<Button variant="outline" size="sm" onClick={() => disconnect()}>
						<LogOut className="w-3 h-3 mr-1" />
						Disconnect
					</Button>
				</div>
			</CardContent>
		</Card>
	);
}
