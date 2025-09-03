import { AlertCircle, Bitcoin, CheckCircle, ExternalLink, RefreshCw } from 'lucide-react';
import React, { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { BITCOIN_CONFIG, BitcoinAPI, BitcoinFaucet as FaucetAPI } from '@/lib/bitcoin-config';
import { validateAddress } from '@/lib/bitcoin-utils';

interface BitcoinFaucetProps {
	onClose?: () => void;
}

interface FaucetState {
	isRequesting: boolean;
	balance: number | null;
	lastRequest: string | null;
	error: string | null;
	success: string | null;
}

export function BitcoinFaucet({ onClose }: BitcoinFaucetProps) {
	const [address, setAddress] = useState('');
	const [state, setState] = useState<FaucetState>({
		isRequesting: false,
		balance: null,
		lastRequest: null,
		error: null,
		success: null,
	});

	const checkBalance = async () => {
		if (!address || !validateAddress(address)) {
			setState((prev) => ({ ...prev, error: 'Please enter a valid Bitcoin testnet address' }));
			return;
		}

		try {
			setState((prev) => ({ ...prev, error: null }));
			const balance = await BitcoinAPI.getBalance(address);
			setState((prev) => ({ ...prev, balance: balance / 100000000 })); // Convert to BTC
		} catch (error) {
			console.error('Error checking balance:', error);
			setState((prev) => ({ ...prev, error: 'Failed to check balance. Please try again.' }));
		}
	};

	const requestFunds = async () => {
		if (!address || !validateAddress(address)) {
			setState((prev) => ({ ...prev, error: 'Please enter a valid Bitcoin testnet address' }));
			return;
		}

		try {
			setState((prev) => ({
				...prev,
				isRequesting: true,
				error: null,
				success: null,
			}));

			const result = await FaucetAPI.requestFunds(address);

			if (result.success) {
				setState((prev) => ({
					...prev,
					isRequesting: false,
					success: result.message,
				}));
			} else {
				setState((prev) => ({
					...prev,
					isRequesting: false,
					error: result.message,
				}));
			}
		} catch (error) {
			console.error('Error requesting funds:', error);
			setState((prev) => ({
				...prev,
				isRequesting: false,
				error: 'Failed to request funds. Please try again.',
			}));
		}
	};

	const openExplorer = () => {
		if (address) {
			window.open(BitcoinAPI.getExplorerUrl(address), '_blank');
		}
	};

	return (
		<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
			<Card className="w-full max-w-md">
				<CardHeader>
					<div className="flex items-center gap-2">
						{onClose && (
							<Button variant="ghost" size="sm" onClick={onClose}>
								×
							</Button>
						)}
						<div>
							<CardTitle className="flex items-center gap-2">
								<Bitcoin className="w-5 h-5 text-orange-500" />
								Bitcoin Testnet Faucet
							</CardTitle>
							<CardDescription>Get free testnet Bitcoin for development</CardDescription>
						</div>
					</div>
				</CardHeader>
				<CardContent className="space-y-4">
					<div>
						<Label htmlFor="address">Bitcoin Testnet Address</Label>
						<Input
							id="address"
							type="text"
							placeholder="Enter your testnet address"
							value={address}
							onChange={(e) => setAddress(e.target.value)}
							className="mt-1 font-mono text-sm"
						/>
						<p className="text-xs text-gray-500 mt-1">
							Testnet addresses start with 'tb1', 'm', or 'n'
						</p>
					</div>

					{state.balance !== null && (
						<div className="bg-green-50 dark:bg-green-900/20 p-3 rounded-lg">
							<div className="flex items-center gap-2">
								<CheckCircle className="w-4 h-4 text-green-600" />
								<span className="text-sm font-medium text-green-900 dark:text-green-100">
									Balance: {state.balance.toFixed(8)} BTC
								</span>
							</div>
						</div>
					)}

					{state.error && (
						<div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-lg">
							<div className="flex items-center gap-2">
								<AlertCircle className="w-4 h-4 text-red-600" />
								<span className="text-sm text-red-900 dark:text-red-100">{state.error}</span>
							</div>
						</div>
					)}

					{state.success && (
						<div className="bg-green-50 dark:bg-green-900/20 p-3 rounded-lg">
							<div className="flex items-center gap-2">
								<CheckCircle className="w-4 h-4 text-green-600" />
								<span className="text-sm text-green-900 dark:text-green-100">{state.success}</span>
							</div>
						</div>
					)}

					<div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
						<h4 className="text-sm font-medium text-blue-900 dark:text-blue-100 mb-2">
							Available Testnet Faucets:
						</h4>
						<div className="space-y-3">
							<div className="flex items-start gap-2">
								<ExternalLink className="w-3 h-3 text-blue-600 dark:text-blue-400 mt-0.5" />
								<div>
									<a
										href="https://bitcoinfaucet.uo1.net"
										target="_blank"
										rel="noopener noreferrer"
										className="text-sm text-blue-700 dark:text-blue-300 hover:underline font-medium"
									>
										Bitcoin Testnet Faucet
									</a>
									<p className="text-xs text-blue-600 dark:text-blue-400">
										Free testnet Bitcoin with captcha verification
									</p>
								</div>
							</div>
							<div className="flex items-start gap-2">
								<ExternalLink className="w-3 h-3 text-blue-600 dark:text-blue-400 mt-0.5" />
								<div>
									<a
										href="https://testnet-faucet.com"
										target="_blank"
										rel="noopener noreferrer"
										className="text-sm text-blue-700 dark:text-blue-300 hover:underline font-medium"
									>
										Testnet Faucet
									</a>
									<p className="text-xs text-blue-600 dark:text-blue-400">
										Simple faucet for development
									</p>
								</div>
							</div>
							<div className="flex items-start gap-2">
								<ExternalLink className="w-3 h-3 text-blue-600 dark:text-blue-400 mt-0.5" />
								<div>
									<a
										href="https://faucet.testnet.bitcoincloud.net"
										target="_blank"
										rel="noopener noreferrer"
										className="text-sm text-blue-700 dark:text-blue-300 hover:underline font-medium"
									>
										Bitcoin Cloud Testnet Faucet
									</a>
									<p className="text-xs text-blue-600 dark:text-blue-400">
										Cloud-based testnet faucet service
									</p>
								</div>
							</div>
						</div>
					</div>

					<div className="flex gap-2">
						<Button
							type="button"
							variant="outline"
							onClick={checkBalance}
							className="flex-1"
							disabled={!address}
						>
							<RefreshCw className="w-4 h-4 mr-2" />
							Check Balance
						</Button>
						<Button type="button" variant="outline" onClick={openExplorer} disabled={!address}>
							<ExternalLink className="w-4 h-4" />
						</Button>
					</div>

					<Button
						onClick={() => navigator.clipboard.writeText(address)}
						disabled={!address}
						className="w-full"
					>
						<Bitcoin className="w-4 h-4 mr-2" />
						Copy Address for Faucet
					</Button>

					{onClose && (
						<Button variant="outline" onClick={onClose} className="w-full">
							Close
						</Button>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
