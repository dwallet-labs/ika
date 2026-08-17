'use client';

import { Button } from '@fesal-packages/ikavery-frontend-ui';
import { Wallet } from 'lucide-react';
import dynamic from 'next/dynamic';

function Placeholder() {
	return (
		<Button size="sm" variant="secondary" disabled>
			<Wallet className="h-3.5 w-3.5" />
			Connect wallet
		</Button>
	);
}

// dapp-kit's hooks (useWallets, useCurrentAccount) only resolve in the
// browser, so the component is client-only by nature. next/dynamic with
// ssr:false skips server rendering entirely — no manual `mounted` state,
// no hydration mismatch.
export const WalletConnect = dynamic<{ align?: 'start' | 'end' }>(
	() => import('./wallet-connect-impl'),
	{ ssr: false, loading: () => <Placeholder /> },
);
