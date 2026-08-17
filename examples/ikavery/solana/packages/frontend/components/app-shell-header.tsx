import { Button, ShellHeader, type ShellHeaderProps } from '@fesal-packages/ikavery-frontend-ui';

import { WalletConnect } from '@/components/wallet-connect';

export function AppShellHeader(props: Omit<ShellHeaderProps, 'walletSlot' | 'ctaSlot'>) {
	return (
		<ShellHeader
			version="v0.1"
			{...props}
			walletSlot={<WalletConnect />}
			ctaSlot={
				<Button variant="primary" size="sm" asChild className="hidden sm:inline-flex">
					<a href="/setup/connect">Build a vault</a>
				</Button>
			}
		/>
	);
}
