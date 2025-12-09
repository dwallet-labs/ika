'use client';

import { useQuery } from '@tanstack/react-query';
import { Copy, ExternalLink, Loader2 } from 'lucide-react';
import { useState } from 'react';

import type { MultisigOwnership } from '@/hooks/useMultisigData';
import { showInfoToast, showSuccessToast } from '@/lib/error-handling';
import { formatSats, shorten } from '@/lib/formatting';

import { AddBalanceModal } from '../modals/AddBalanceModal';
import { BroadcastConfirmationDialog } from '../modals/BroadcastConfirmationDialog';
import { ChangeThresholdModal } from '../modals/ChangeThresholdModal';
import { ExecuteConfirmationDialog } from '../modals/ExecuteConfirmationDialog';
import { ManageMembersModal } from '../modals/ManageMembersModal';
import { SendTransactionModal } from '../modals/SendTransactionModal';
import { VoteConfirmationDialog } from '../modals/VoteConfirmationDialog';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Skeleton } from '../ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { MembersTab } from './MembersTab';
import { SettingsTab } from './SettingsTab';
import { TransactionsTab } from './TransactionsTab';

interface MultisigDetailsViewProps {
	multisig: MultisigOwnership;
	onCreateTx: (params: any) => Promise<void>;
	onVote: (requestId: number, vote: boolean) => Promise<void>;
	onExecute: (requestId: number) => Promise<any>;
	onBroadcast: (requestId: number) => Promise<any>;
	onAddMember: (address: string) => Promise<void>;
	onRemoveMember: (address: string) => Promise<void>;
	onChangeApprovalThreshold: (threshold: number) => Promise<void>;
	onChangeRejectionThreshold: (threshold: number) => Promise<void>;
	onChangeExpirationDuration: (durationSeconds: number) => Promise<void>;
	onAddIkaBalance: (amount: bigint) => Promise<void>;
	onAddSuiBalance: (amount: bigint) => Promise<void>;
}

export function MultisigDetailsView({
	multisig,
	onCreateTx,
	onVote,
	onExecute,
	onBroadcast,
	onAddMember,
	onRemoveMember,
	onChangeApprovalThreshold,
	onChangeRejectionThreshold,
	onChangeExpirationDuration,
	onAddIkaBalance,
	onAddSuiBalance,
}: MultisigDetailsViewProps) {
	const [sendTxOpen, setSendTxOpen] = useState(false);
	const [manageMembersOpen, setManageMembersOpen] = useState(false);
	const [changeThresholdOpen, setChangeThresholdOpen] = useState(false);
	const [addBalanceOpen, setAddBalanceOpen] = useState(false);
	const [voteDialog, setVoteDialog] = useState<{
		open: boolean;
		requestId: number;
		approve: boolean;
		description: string;
	}>({ open: false, requestId: 0, approve: true, description: '' });
	const [executeDialog, setExecuteDialog] = useState<{
		open: boolean;
		requestId: number;
		description: string;
	}>({ open: false, requestId: 0, description: '' });
	const [broadcastDialog, setBroadcastDialog] = useState<{
		open: boolean;
		requestId: number;
		description: string;
	}>({ open: false, requestId: 0, description: '' });

	const btcAddress = multisig.class.getAddress();
	const network = multisig.class.getNetwork();
	const isTestnet = network === 'testnet';
	const btcExplorerUrl = isTestnet
		? `https://blockstream.info/testnet/address/${btcAddress}`
		: `https://blockstream.info/address/${btcAddress}`;

	const {
		data: balance,
		isLoading: isLoadingBalance,
		isFetching: isFetchingBalance,
	} = useQuery({
		queryKey: ['btc-balance', btcAddress],
		queryFn: async () => multisig.class.getBalanceWithUnconfirmed(),
		refetchInterval: 15000, // Refetch every 15 seconds for better responsiveness
		staleTime: 10000, // Consider data stale after 10 seconds
	});

	const isBalanceLoading = isLoadingBalance || isFetchingBalance;

	const copyAddress = async () => {
		try {
			await navigator.clipboard.writeText(btcAddress);
			showSuccessToast('Address copied to clipboard');
		} catch (err) {
			console.error('Failed to copy address:', err);
		}
	};

	const handleVote = (requestId: number, approve: boolean) => {
		const request = multisig.requests.find((r) => r.requestId === requestId);
		if (!request) return;

		// Get description
		let description = 'Unknown request';
		const reqType = request.request_type as any;
		if (reqType?.Transaction) description = 'Bitcoin Transaction';
		else if (reqType?.AddMember) description = `Add Member: ${shorten(String(reqType.AddMember))}`;
		else if (reqType?.RemoveMember)
			description = `Remove Member: ${shorten(String(reqType.RemoveMember))}`;

		setVoteDialog({ open: true, requestId, approve, description });
	};

	const handleExecute = (requestId: number) => {
		const request = multisig.requests.find((r) => r.requestId === requestId);
		if (!request) return;

		let description = 'Unknown request';
		const reqType = request.request_type as any;
		if (reqType?.Transaction) description = 'Bitcoin Transaction';

		setExecuteDialog({ open: true, requestId, description });
	};

	const handleBroadcast = (requestId: number) => {
		const request = multisig.requests.find((r) => r.requestId === requestId);
		if (!request) return;

		let description = 'Bitcoin Transaction';
		setBroadcastDialog({ open: true, requestId, description });
	};

	const pendingCount = multisig.requests.filter((r) => {
		const statusObj = r.status as any;
		return (
			statusObj &&
			typeof statusObj === 'object' &&
			(statusObj.$kind === 'Pending' || ('Pending' in statusObj && statusObj.Pending))
		);
	}).length;

	return (
		<div className="space-y-6">
			{/* Header Card */}
			<Card>
				<CardHeader>
					<div className="flex items-start justify-between">
						<div className="flex-1">
							<CardTitle className="text-2xl mb-2">Bitcoin Multisig Wallet</CardTitle>
							<div className="flex items-center gap-2 mb-3">
								<code className="text-sm bg-muted px-2 py-1 rounded">
									{shorten(btcAddress, 12)}
								</code>
								<Button variant="ghost" size="icon" onClick={copyAddress}>
									<Copy className="h-4 w-4" />
								</Button>
								<Button variant="ghost" size="icon" asChild>
									<a href={btcExplorerUrl} target="_blank" rel="noopener noreferrer">
										<ExternalLink className="h-4 w-4" />
									</a>
								</Button>
							</div>
							<div className="flex items-center gap-3">
								<Badge variant="secondary">{isTestnet ? 'Testnet' : 'Mainnet'}</Badge>
								<Badge variant="outline">
									{multisig.multisig.members.length} member
									{multisig.multisig.members.length !== 1 ? 's' : ''}
								</Badge>
								{pendingCount > 0 ? <Badge>{pendingCount} pending</Badge> : null}
							</div>
						</div>
						<div className="text-right">
							<div className="text-sm text-muted-foreground mb-1">Balance</div>
							<div className="text-3xl font-bold min-h-[2.25rem] flex items-center justify-end">
								{isBalanceLoading ? (
									<div className="flex items-center gap-2">
										<Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
										<span className="text-muted-foreground">Loading...</span>
									</div>
								) : (
									<div className="flex flex-col items-end gap-1">
										<div>{formatSats(balance?.confirmed || BigInt(0))}</div>
										{balance?.unconfirmed && balance.unconfirmed > BigInt(0) ? (
											<div className="text-sm text-muted-foreground font-normal">
												+{formatSats(balance.unconfirmed)} unconfirmed
											</div>
										) : null}
									</div>
								)}
							</div>
						</div>
					</div>
				</CardHeader>
				<CardContent>
					<div className="flex gap-2">
						<Button onClick={() => setSendTxOpen(true)}>Send BTC</Button>
					</div>
				</CardContent>
			</Card>

			{/* Tabs */}
			<Tabs defaultValue="transactions" className="w-full">
				<TabsList className="grid w-full grid-cols-3">
					<TabsTrigger value="transactions">
						Transactions
						{pendingCount > 0 ? (
							<Badge variant="secondary" className="ml-2">
								{pendingCount}
							</Badge>
						) : null}
					</TabsTrigger>
					<TabsTrigger value="members">Members</TabsTrigger>
					<TabsTrigger value="settings">Settings</TabsTrigger>
				</TabsList>

				<TabsContent value="transactions" className="mt-6">
					<TransactionsTab
						requests={multisig.requests}
						multisig={{
							...multisig.multisig,
							approval_threshold: Number(multisig.multisig.approval_threshold),
							rejection_threshold: Number(multisig.multisig.rejection_threshold),
						}}
						wallet={multisig.class}
						onVote={handleVote}
						onExecute={handleExecute}
						onBroadcast={handleBroadcast}
					/>
				</TabsContent>

				<TabsContent value="members" className="mt-6">
					<MembersTab
						members={multisig.multisig.members}
						approvalThreshold={Number(multisig.multisig.approval_threshold)}
						rejectionThreshold={Number(multisig.multisig.rejection_threshold)}
						onManageMembers={() => setManageMembersOpen(true)}
					/>
				</TabsContent>

				<TabsContent value="settings" className="mt-6">
					<SettingsTab
						approvalThreshold={Number(multisig.multisig.approval_threshold)}
						rejectionThreshold={Number(multisig.multisig.rejection_threshold)}
						expirationDuration={Number(multisig.multisig.expiration_duration) / 1000}
						network={isTestnet ? 'testnet' : 'mainnet'}
						ikaBalance={BigInt(multisig.multisig.ika_balance.value)}
						suiBalance={BigInt(multisig.multisig.sui_balance.value)}
						onChangeThreshold={() => setChangeThresholdOpen(true)}
						onAddBalance={() => setAddBalanceOpen(true)}
					/>
				</TabsContent>
			</Tabs>

			{/* Modals */}
			<SendTransactionModal
				open={sendTxOpen}
				onOpenChange={setSendTxOpen}
				multisig={multisig.class}
				onSubmit={onCreateTx}
			/>

			<ManageMembersModal
				open={manageMembersOpen}
				onOpenChange={setManageMembersOpen}
				onAddMember={onAddMember}
				onRemoveMember={onRemoveMember}
				currentMembers={multisig.multisig.members}
			/>

			<ChangeThresholdModal
				open={changeThresholdOpen}
				onOpenChange={setChangeThresholdOpen}
				onChangeApprovalThreshold={onChangeApprovalThreshold}
				onChangeRejectionThreshold={onChangeRejectionThreshold}
				onChangeExpirationDuration={onChangeExpirationDuration}
				currentApprovalThreshold={Number(multisig.multisig.approval_threshold)}
				currentRejectionThreshold={Number(multisig.multisig.rejection_threshold)}
				currentExpirationDuration={Number(multisig.multisig.expiration_duration) / 1000}
				memberCount={multisig.multisig.members.length}
			/>

			<AddBalanceModal
				open={addBalanceOpen}
				onOpenChange={setAddBalanceOpen}
				onAddIka={onAddIkaBalance}
				onAddSui={onAddSuiBalance}
			/>

			<VoteConfirmationDialog
				open={voteDialog.open}
				onOpenChange={(open) => setVoteDialog({ ...voteDialog, open })}
				onConfirm={async () => {
					await onVote(voteDialog.requestId, voteDialog.approve);
					setVoteDialog({ ...voteDialog, open: false });
				}}
				isApprove={voteDialog.approve}
				requestId={voteDialog.requestId}
				description={voteDialog.description}
			/>

			<ExecuteConfirmationDialog
				open={executeDialog.open}
				onOpenChange={(open) => setExecuteDialog({ ...executeDialog, open })}
				onExecute={() => onExecute(executeDialog.requestId)}
				requestId={executeDialog.requestId}
				description={executeDialog.description}
			/>

			<BroadcastConfirmationDialog
				open={broadcastDialog.open}
				onOpenChange={(open) => setBroadcastDialog({ ...broadcastDialog, open })}
				onBroadcast={() => onBroadcast(broadcastDialog.requestId)}
				requestId={broadcastDialog.requestId}
				description={broadcastDialog.description}
				network={network}
			/>
		</div>
	);
}
