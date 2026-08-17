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

// Dynamic's widget reads from window-only globals (PRF, navigator, the
// embedded-wallet popup channel) and crashes during SSR. next/dynamic with
// ssr:false skips server rendering entirely — no manual `mounted` state,
// no hydration mismatch.
export const WalletConnect = dynamic(() => import('./wallet-connect-impl'), {
	ssr: false,
	loading: () => <Placeholder />,
});
