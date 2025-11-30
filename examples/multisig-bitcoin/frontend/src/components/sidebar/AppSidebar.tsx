'use client';

import { RefreshCw } from 'lucide-react';
import { useState } from 'react';

import { useMultisigContext } from '@/contexts/MultisigContext';
import { useMultisigOwnership } from '@/hooks/useMultisigData';

import { LoadingSidebar } from '../common/LoadingState';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';
import { Separator } from '../ui/separator';
import { MultisigListItem } from './MultisigListItem';

interface AppSidebarProps {
	onCreateNew: () => void;
}

export function AppSidebar({ onCreateNew }: AppSidebarProps) {
	const { data: ownerships, isLoading, error, refetch, isFetching } = useMultisigOwnership();
	const { selectedMultisigId, selectMultisig } = useMultisigContext();
	const [isRefreshing, setIsRefreshing] = useState(false);

	const handleRefresh = async () => {
		setIsRefreshing(true);
		try {
			await refetch();
		} finally {
			// Keep the spinning animation visible for at least 500ms for better UX
			setTimeout(() => setIsRefreshing(false), 500);
		}
	};

	return (
		<div className="flex h-full flex-col bg-sidebar border-r border-sidebar-border">
			{/* Header */}
			<div className="p-4">
				<div className="flex items-center gap-2 mb-4">
					<div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
					<h2 className="font-semibold text-base tracking-tight">bitisi</h2>
					<Button
						variant="ghost"
						size="icon"
						className="ml-auto h-7 w-7"
						onClick={handleRefresh}
						disabled={isRefreshing || isFetching}
						title="Refresh multisigs"
					>
						<RefreshCw className={`h-4 w-4 ${isRefreshing || isFetching ? 'animate-spin' : ''}`} />
					</Button>
				</div>
				<Button onClick={onCreateNew} className="w-full" size="sm">
					Create New Multisig
				</Button>
			</div>

			<Separator />

			{/* Multisig List */}
			<div className="flex-1 overflow-hidden">
				<ScrollArea className="h-full">
					<div className="p-4 space-y-1">
						<div className="text-xs font-medium text-muted-foreground mb-2 px-3">
							YOUR MULTISIGS
						</div>

						{isLoading && <LoadingSidebar />}

						{error && (
							<div className="text-sm text-destructive px-3 py-2">Failed to load multisigs</div>
						)}

						{!isLoading && !error && ownerships && ownerships.length === 0 && (
							<div className="text-sm text-muted-foreground px-3 py-4 text-center">
								No multisigs yet.
								<br />
								Create your first one!
							</div>
						)}

						{ownerships?.map((ownership) => (
							<MultisigListItem
								key={ownership.id}
								multisig={ownership}
								isActive={selectedMultisigId === ownership.id}
								onClick={() => selectMultisig(ownership)}
							/>
						))}
					</div>
				</ScrollArea>
			</div>

			{/* Footer */}
			<Separator />
			<div className="p-4">
				<div className="text-xs text-muted-foreground text-center">
					bitcoin multisig • powered by ika
				</div>
			</div>
		</div>
	);
}
