'use client';

import type { MultisigOwnership } from '@/hooks/useMultisigData';
import { formatSats, shorten } from '@/lib/formatting';

import { Badge } from '../ui/badge';

interface MultisigListItemProps {
	multisig: MultisigOwnership;
	isActive: boolean;
	onClick: () => void;
}

export function MultisigListItem({ multisig, isActive, onClick }: MultisigListItemProps) {
	const btcAddress = multisig.class.getAddress();
	const pendingCount = multisig.requests.filter((r) => {
		const statusObj = r.status as any;
		return (
			statusObj &&
			typeof statusObj === 'object' &&
			(statusObj.$kind === 'Pending' || ('Pending' in statusObj && statusObj.Pending))
		);
	}).length;

	return (
		<button
			onClick={onClick}
			className={`w-full text-left px-3 py-2.5 rounded-lg transition-colors ${
				isActive ? 'bg-sidebar-accent text-sidebar-accent-foreground' : 'hover:bg-sidebar-accent/50'
			}`}
		>
			<div className="flex items-start justify-between gap-2">
				<div className="flex-1 min-w-0">
					<div className="font-mono text-sm font-medium truncate">{shorten(btcAddress, 8)}</div>
					<div className="text-xs text-muted-foreground mt-0.5">
						{multisig.multisig.members.length} member
						{multisig.multisig.members.length !== 1 ? 's' : ''}
					</div>
				</div>
				{pendingCount > 0 && (
					<Badge variant="secondary" className="shrink-0">
						{pendingCount}
					</Badge>
				)}
			</div>
		</button>
	);
}
