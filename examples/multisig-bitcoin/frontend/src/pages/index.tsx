import { ConnectButton } from '@mysten/dapp-kit';

import { MultisigDashboard } from '@/components/MultisigDashboard';
import { NetworkStatus } from '@/components/NetworkStatus';
import { WalletConnection } from '@/components/WalletConnection';

export default function Home() {
	return (
		<div className="min-h-screen bg-background">
			{/* Header */}
			<header className="bg-card border-b border-border">
				<div className="max-w-6xl mx-auto px-4 py-4">
					<div className="flex items-center justify-between">
						<div className="flex items-center gap-4">
							<h1 className="text-2xl font-bold text-foreground">IKA</h1>
							<div className="text-sm text-muted-foreground">Bitcoin Multisig Wallet</div>
						</div>
						<ConnectButton />
					</div>
				</div>
			</header>

			{/* Main Content */}
			<main className="max-w-6xl mx-auto px-4 py-8">
				<WalletConnection />
				<NetworkStatus />
				<MultisigDashboard />
			</main>

			{/* Footer */}
			<footer className="bg-card border-t border-border mt-16">
				<div className="max-w-6xl mx-auto px-4 py-6">
					<div className="text-center text-sm text-muted-foreground">
						<p>Powered by IKA Protocol</p>
					</div>
				</div>
			</footer>
		</div>
	);
}
