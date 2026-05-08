import Image from 'next/image';
import { ArrowRight } from 'lucide-react';

export function SolanaBanner() {
	return (
		<div className="solana-banner relative overflow-hidden border-b border-purple-300/30 dark:border-purple-700/30 bg-gradient-to-r from-purple-600 via-fuchsia-500 to-pink-500">
			<div className="absolute inset-0 bg-[linear-gradient(110deg,transparent_25%,rgba(255,255,255,0.1)_50%,transparent_75%)] animate-shimmer" />
			<div className="relative mx-auto max-w-6xl px-6 py-3 flex items-center justify-center gap-3 text-white text-sm font-medium">
				<Image src="/solana-logo.svg" alt="Solana" width={16} height={16} className="brightness-0 invert" />
				<span>
					Solana support coming soon. dWallets are expanding to Solana for native
					cross-chain signing.
				</span>
				<ArrowRight className="h-4 w-4" />
			</div>
		</div>
	);
}
