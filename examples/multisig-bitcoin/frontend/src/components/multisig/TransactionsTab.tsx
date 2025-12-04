'use client';

import { ChevronDown } from 'lucide-react';
import { useState } from 'react';

import type { RequestWithVote } from '@/hooks/useMultisigData';
import type { MultisigBitcoinWallet } from '@/multisig/bitcoin';

import { EmptyState } from '../common/EmptyState';
import { Button } from '../ui/button';
import { RequestCard } from './RequestCard';

interface TransactionsTabProps {
	requests: RequestWithVote[];
	multisig: {
		approval_threshold: bigint | number;
		rejection_threshold: bigint | number;
	};
	wallet: MultisigBitcoinWallet;
	onVote: (requestId: number, approve: boolean) => void;
	onExecute: (requestId: number) => void;
	onBroadcast: (requestId: number) => void;
}

export function TransactionsTab({
	requests,
	multisig,
	wallet,
	onVote,
	onExecute,
	onBroadcast,
}: TransactionsTabProps) {
	const [isActiveExpanded, setIsActiveExpanded] = useState(true);
	const [isApprovedExpanded, setIsApprovedExpanded] = useState(true);
	const [isRejectedExpanded, setIsRejectedExpanded] = useState(false);

	// Categorize requests
	const categorized = requests.reduce(
		(acc, r) => {
			const statusObj = r.status as any;
			const isPending =
				statusObj &&
				typeof statusObj === 'object' &&
				(statusObj.$kind === 'Pending' || ('Pending' in statusObj && statusObj.Pending));
			const isApproved =
				statusObj &&
				typeof statusObj === 'object' &&
				(statusObj.$kind === 'Approved' || ('Approved' in statusObj && statusObj.Approved));
			const isRejected =
				statusObj &&
				typeof statusObj === 'object' &&
				(statusObj.$kind === 'Rejected' || ('Rejected' in statusObj && statusObj.Rejected));

			if (isPending) acc.active.push(r);
			else if (isApproved) acc.approved.push(r);
			else if (isRejected) acc.rejected.push(r);

			return acc;
		},
		{
			active: [] as RequestWithVote[],
			approved: [] as RequestWithVote[],
			rejected: [] as RequestWithVote[],
		},
	);

	// Sort by request ID descending
	const sortByRequestId = (a: RequestWithVote, b: RequestWithVote) =>
		Number(b.requestId) - Number(a.requestId);
	categorized.active.sort(sortByRequestId);
	categorized.approved.sort(sortByRequestId);
	categorized.rejected.sort(sortByRequestId);

	if (requests.length === 0) {
		return (
			<EmptyState
				title="No requests yet"
				description="Transaction requests will appear here once created."
			/>
		);
	}

	return (
		<div className="space-y-6">
			{/* Active Requests */}
			{categorized.active.length > 0 && (
				<div className="space-y-3">
					<Button
						variant="ghost"
						className="w-full justify-between p-0 h-auto hover:bg-transparent"
						onClick={() => setIsActiveExpanded(!isActiveExpanded)}
					>
						<h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
							Active ({categorized.active.length})
						</h3>
						<ChevronDown
							className={`h-4 w-4 transition-transform ${isActiveExpanded ? 'rotate-180' : ''}`}
						/>
					</Button>
					{isActiveExpanded && (
						<div className="space-y-3">
							{categorized.active.map((request) => (
								<RequestCard
									key={request.requestId}
									request={request}
									multisig={multisig}
									wallet={wallet}
									onVote={onVote}
									onExecute={onExecute}
									onBroadcast={onBroadcast}
								/>
							))}
						</div>
					)}
				</div>
			)}

			{/* Approved Requests */}
			{categorized.approved.length > 0 && (
				<div className="space-y-3">
					<Button
						variant="ghost"
						className="w-full justify-between p-0 h-auto hover:bg-transparent"
						onClick={() => setIsApprovedExpanded(!isApprovedExpanded)}
					>
						<h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
							Approved ({categorized.approved.length})
						</h3>
						<ChevronDown
							className={`h-4 w-4 transition-transform ${isApprovedExpanded ? 'rotate-180' : ''}`}
						/>
					</Button>
					{isApprovedExpanded && (
						<div className="space-y-3">
							{categorized.approved.map((request) => (
								<RequestCard
									key={request.requestId}
									request={request}
									multisig={multisig}
									wallet={wallet}
									onBroadcast={onBroadcast}
								/>
							))}
						</div>
					)}
				</div>
			)}

			{/* Rejected Requests */}
			{categorized.rejected.length > 0 && (
				<div className="space-y-3">
					<Button
						variant="ghost"
						className="w-full justify-between p-0 h-auto hover:bg-transparent"
						onClick={() => setIsRejectedExpanded(!isRejectedExpanded)}
					>
						<h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
							Rejected ({categorized.rejected.length})
						</h3>
						<ChevronDown
							className={`h-4 w-4 transition-transform ${isRejectedExpanded ? 'rotate-180' : ''}`}
						/>
					</Button>
					{isRejectedExpanded && (
						<div className="space-y-3">
							{categorized.rejected.map((request) => (
								<RequestCard
									key={request.requestId}
									request={request}
									multisig={multisig}
									wallet={wallet}
								/>
							))}
						</div>
					)}
				</div>
			)}
		</div>
	);
}
