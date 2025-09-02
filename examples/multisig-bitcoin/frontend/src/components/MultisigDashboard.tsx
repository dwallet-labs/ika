import {
	AlertCircle,
	CheckCircle,
	Copy,
	ExternalLink,
	Plus,
	Send,
	Users,
	Wallet,
} from 'lucide-react';
import React, { useState } from 'react';

import { CreateTransaction } from '@/components/CreateTransaction';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useMultisig } from '@/contract/multisig';

interface MultisigWallet {
	id: string;
	dwalletID: string;
	participants: string[];
	threshold: number;
	totalParticipants: number;
	status: 'creating' | 'active' | 'error';
	createdAt: Date;
}

export function MultisigDashboard() {
	const { createMultisig } = useMultisig();
	const [isCreating, setIsCreating] = useState(false);
	const [multisigWallets, setMultisigWallets] = useState<MultisigWallet[]>([]);
	const [error, setError] = useState<string | null>(null);
	const [showCreateTransaction, setShowCreateTransaction] = useState<string | null>(null);

	const handleCreateMultisig = async () => {
		try {
			setIsCreating(true);
			setError(null);

			const result = await createMultisig();

			const newWallet: MultisigWallet = {
				id: result.multisigID,
				dwalletID: result.dwalletID,
				participants: [
					'0xa5b1611d756c1b2723df1b97782cacfd10c8f94df571935db87b7f54ef653d66',
					'0x0c96b48925580099ddb1e9398ed51f3e8504b7793ffd7cee7b7f5b2c8c0e9271',
					'0x2c1507b83627174a0b561cc3747511a29dcca2d6839897e9ebb3367e9c7699b5',
				],
				threshold: 2,
				totalParticipants: 3,
				status: 'active',
				createdAt: new Date(),
			};

			setMultisigWallets((prev) => [newWallet, ...prev]);
		} catch (err) {
			console.error('Failed to create multisig:', err);
			setError(err instanceof Error ? err.message : 'Failed to create multisig wallet');
		} finally {
			setIsCreating(false);
		}
	};

	const copyToClipboard = (text: string) => {
		navigator.clipboard.writeText(text);
	};

	const truncateAddress = (address: string) => {
		return `${address.slice(0, 6)}...${address.slice(-4)}`;
	};

	return (
		<div className="p-4">
			<div className="max-w-6xl mx-auto">
				{/* Header */}
				<div className="mb-8">
					<h1 className="text-3xl font-bold text-foreground mb-2">
						Multisig Bitcoin Wallet
					</h1>
					<p className="text-muted-foreground">
						Create and manage secure multisignature wallets using IKA protocol
					</p>
				</div>

				{/* Create Multisig Card */}
				<Card className="mb-8">
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<Plus className="w-5 h-5" />
							Create New Multisig Wallet
						</CardTitle>
						<CardDescription>
							Create a new 2-of-3 multisignature wallet with distributed key generation
						</CardDescription>
					</CardHeader>
					<CardContent>
						<div className="flex items-center gap-4 mb-4">
							<div className="flex items-center gap-2">
								<Users className="w-4 h-4 text-muted-foreground" />
								<span className="text-sm text-muted-foreground">2 of 3 required</span>
							</div>
							<div className="flex items-center gap-2">
								<Wallet className="w-4 h-4 text-muted-foreground" />
								<span className="text-sm text-muted-foreground">Distributed keys</span>
							</div>
						</div>

						{error && (
							<div className="flex items-center gap-2 p-3 mb-4 bg-destructive/10 border border-destructive/20 rounded-lg">
								<AlertCircle className="w-4 h-4 text-destructive" />
								<span className="text-sm text-destructive">{error}</span>
							</div>
						)}

						<Button
							onClick={handleCreateMultisig}
							disabled={isCreating}
							className="w-full sm:w-auto"
						>
							{isCreating ? (
								<>
									<div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
									Creating Multisig...
								</>
							) : (
								<>
									<Plus className="w-4 h-4 mr-2" />
									Create Multisig Wallet
								</>
							)}
						</Button>
					</CardContent>
				</Card>

				{/* Multisig Wallets List */}
				<div className="space-y-4">
					<h2 className="text-xl font-semibold text-foreground mb-4">
						Your Multisig Wallets
					</h2>

					{multisigWallets.length === 0 ? (
						<Card>
							<CardContent className="flex flex-col items-center justify-center py-12">
								<Wallet className="w-12 h-12 text-muted-foreground mb-4" />
								<h3 className="text-lg font-medium text-foreground mb-2">
									No multisig wallets yet
								</h3>
								<p className="text-muted-foreground text-center mb-4">
									Create your first multisignature wallet to get started
								</p>
								<Button onClick={handleCreateMultisig} disabled={isCreating}>
									<Plus className="w-4 h-4 mr-2" />
									Create Your First Wallet
								</Button>
							</CardContent>
						</Card>
					) : (
						multisigWallets.map((wallet) => (
							<Card key={wallet.id}>
								<CardHeader>
									<div className="flex items-center justify-between">
										<CardTitle className="flex items-center gap-2">
											<Wallet className="w-5 h-5" />
											Multisig Wallet
										</CardTitle>
										<Badge variant={wallet.status === 'active' ? 'default' : 'secondary'}>
											{wallet.status === 'active' && <CheckCircle className="w-3 h-3 mr-1" />}
											{wallet.status === 'creating' ? 'Creating...' : 'Active'}
										</Badge>
									</div>
									<CardDescription>
										Created on {wallet.createdAt.toLocaleDateString()}
									</CardDescription>
								</CardHeader>
								<CardContent>
									<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
										<div>
											<h4 className="font-medium text-foreground mb-2">Wallet ID</h4>
											<div className="flex items-center gap-2">
												<code className="text-sm bg-muted px-2 py-1 rounded">
													{truncateAddress(wallet.id)}
												</code>
												<Button
													variant="ghost"
													size="sm"
													onClick={() => copyToClipboard(wallet.id)}
												>
													<Copy className="w-3 h-3" />
												</Button>
											</div>
										</div>

										<div>
											<h4 className="font-medium text-foreground mb-2">DWallet ID</h4>
											<div className="flex items-center gap-2">
												<code className="text-sm bg-muted px-2 py-1 rounded">
													{truncateAddress(wallet.dwalletID)}
												</code>
												<Button
													variant="ghost"
													size="sm"
													onClick={() => copyToClipboard(wallet.dwalletID)}
												>
													<Copy className="w-3 h-3" />
												</Button>
											</div>
										</div>
									</div>

									<div className="mt-4">
										<h4 className="font-medium text-gray-900 dark:text-white mb-2">
											Participants ({wallet.threshold} of {wallet.totalParticipants} required)
										</h4>
										<div className="space-y-2">
											{wallet.participants.map((participant, index) => (
												<div key={index} className="flex items-center gap-2">
													<div className="w-2 h-2 bg-blue-500 rounded-full"></div>
													<code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
														{truncateAddress(participant)}
													</code>
													<Button
														variant="ghost"
														size="sm"
														onClick={() => copyToClipboard(participant)}
													>
														<Copy className="w-3 h-3" />
													</Button>
												</div>
											))}
										</div>
									</div>

									<div className="mt-4 flex gap-2">
										<Button variant="outline" size="sm">
											<ExternalLink className="w-3 h-3 mr-1" />
											View on Explorer
										</Button>
										<Button
											variant="outline"
											size="sm"
											onClick={() => setShowCreateTransaction(wallet.id)}
										>
											<Send className="w-3 h-3 mr-1" />
											Create Transaction
										</Button>
									</div>
								</CardContent>
							</Card>
						))
					)}
				</div>
			</div>

			{/* Transaction Creation Modal */}
			{showCreateTransaction && (
				<CreateTransaction
					multisigId={showCreateTransaction}
					onClose={() => setShowCreateTransaction(null)}
				/>
			)}
		</div>
	);
}
