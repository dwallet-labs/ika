'use client';

import * as bitcoin from 'bitcoinjs-lib';
import { useEffect, useState } from 'react';

import type { RequestWithVote } from '@/hooks/useMultisigData';
import { formatDuration, formatSats, shorten } from '@/lib/formatting';
import type { MultisigBitcoinWallet } from '@/multisig/bitcoin';

import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader } from '../ui/card';

interface RequestCardProps {
	request: RequestWithVote;
	multisig: {
		approval_threshold: bigint | number;
		rejection_threshold: bigint | number;
	};
	wallet: MultisigBitcoinWallet;
	onVote?: (requestId: number, approve: boolean) => void;
	onExecute?: (requestId: number) => void;
	onBroadcast?: (requestId: number) => void;
}

export function RequestCard({
	request,
	multisig,
	wallet,
	onVote,
	onExecute,
	onBroadcast,
}: RequestCardProps) {
	const requestId = Number(request.requestId);
	const approversCount =
		typeof request.approvers_count === 'string'
			? Number(request.approvers_count)
			: Number(request.approvers_count ?? 0);
	const rejectersCount =
		typeof request.rejecters_count === 'string'
			? Number(request.rejecters_count)
			: Number(request.rejecters_count ?? 0);
	const approvalThreshold = Number(multisig.approval_threshold);
	const rejectionThreshold = Number(multisig.rejection_threshold);

	// Broadcast status state
	const [broadcastStatus, setBroadcastStatus] = useState<{
		checking: boolean;
		checked: boolean;
		broadcasted: boolean;
		txid?: string;
		confirmed?: boolean;
		confirmations?: number;
		blockHeight?: number;
	}>({ checking: false, checked: false, broadcasted: false });

	const statusObj = request.status as any;
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

	const canExecute = approversCount >= approvalThreshold && isPending && !isApproved && !isRejected;
	const canVote = isPending && !request.voted;

	const isTransactionRequest =
		request.request_type &&
		typeof request.request_type === 'object' &&
		'Transaction' in request.request_type;

	// Parse transaction details
	const getTransactionDetails = () => {
		if (!request.request_type) return null;
		const reqType = request.request_type as any;

		if (reqType.Transaction && Array.isArray(reqType.Transaction)) {
			try {
				const psbtData = reqType.Transaction[2];
				if (!psbtData) return null;

				const psbtBytes =
					psbtData instanceof Uint8Array ? Buffer.from(psbtData) : Buffer.from(psbtData);
				const psbt = bitcoin.Psbt.fromBuffer(psbtBytes);

				const network =
					wallet.getNetwork() === 'testnet' ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
				const outputs = psbt.txOutputs.map((output) => {
					try {
						const address = bitcoin.address.fromOutputScript(output.script, network);
						return {
							address,
							amount: output.value,
							isChange: address === wallet.getAddress(),
						};
					} catch {
						return null;
					}
				});

				const recipients = outputs.filter(
					(o): o is NonNullable<typeof o> => o !== null && !o.isChange,
				);
				const changeOutput = outputs.find(
					(o): o is NonNullable<typeof o> => o !== null && o.isChange,
				);

				const totalAmount = recipients.reduce((sum, o) => sum + o.amount, BigInt(0));

				return {
					recipients,
					changeOutput,
					totalAmount,
				};
			} catch (error) {
				console.error('Failed to parse PSBT:', error);
				return null;
			}
		}
		return null;
	};

	const getRequestDescription = () => {
		if (!request.request_type) return 'Unknown request';
		const reqType = request.request_type as any;

		if (reqType.Transaction) {
			const txDetails = getTransactionDetails();
			if (txDetails && txDetails.recipients.length > 0) {
				const recipientList = txDetails.recipients
					.map((r) => `${shorten(r.address, 8)} (${formatSats(r.amount)})`)
					.join(', ');
				return `Send ${formatSats(txDetails.totalAmount)} to ${recipientList}`;
			}
			return 'Bitcoin Transaction';
		}
		if (reqType.AddMember) {
			return `Add Member: ${shorten(String(reqType.AddMember))}`;
		}
		if (reqType.RemoveMember) {
			return `Remove Member: ${shorten(String(reqType.RemoveMember))}`;
		}
		if (reqType.ChangeApprovalThreshold) {
			return `Change Approval Threshold: ${reqType.ChangeApprovalThreshold}`;
		}
		if (reqType.ChangeRejectionThreshold) {
			return `Change Rejection Threshold: ${reqType.ChangeRejectionThreshold}`;
		}
		if (reqType.ChangeExpirationDuration) {
			const seconds = Number(reqType.ChangeExpirationDuration) / 1000;
			return `Change Expiration Duration: ${formatDuration(seconds)}`;
		}
		return 'Unknown request type';
	};

	const transactionDetails = getTransactionDetails();

	// Check if transaction is broadcasted
	useEffect(() => {
		const checkBroadcastStatus = async () => {
			// Only check for approved transaction requests
			if (!isApproved || !isTransactionRequest) {
				return;
			}

			setBroadcastStatus((prev) => ({ ...prev, checking: true }));

			try {
				const reqType = request.request_type as any;
				if (!reqType?.Transaction || !Array.isArray(reqType.Transaction)) {
					setBroadcastStatus({ checking: false, checked: true, broadcasted: false });
					return;
				}

				// Extract PSBT from the request
				// Transaction tuple: [preimage, message_centralized_signature, psbt]
				const psbtData = reqType.Transaction[2];

				if (!psbtData) {
					setBroadcastStatus({ checking: false, checked: true, broadcasted: false });
					return;
				}

				// Convert to Buffer and parse PSBT
				const psbtBytes =
					psbtData instanceof Uint8Array ? Buffer.from(psbtData) : Buffer.from(psbtData);
				const psbt = bitcoin.Psbt.fromBuffer(psbtBytes);

				// Use the created_at timestamp to filter transactions
				// created_at is in milliseconds, convert to seconds
				const createdAtMs =
					typeof request.created_at === 'string'
						? Number(request.created_at)
						: Number(request.created_at ?? 0);
				const createdAtSeconds = Math.floor(createdAtMs / 1000);

				console.log('Request created at:', createdAtMs, 'ms (', createdAtSeconds, 'seconds)');

				// Search for a broadcasted transaction with matching outputs
				const result = await wallet.findBroadcastedTransactionByOutputs(psbt, createdAtSeconds);

				setBroadcastStatus({
					checking: false,
					checked: true,
					broadcasted: result.found,
					txid: result.txid,
					confirmed: result.confirmed,
					confirmations: result.confirmations,
					blockHeight: result.blockHeight,
				});
			} catch (error) {
				console.error('Error checking broadcast status:', error);
				setBroadcastStatus({ checking: false, checked: true, broadcasted: false });
			}
		};

		checkBroadcastStatus();
	}, [isApproved, isTransactionRequest, request.request_type, request.created_at, wallet]);

	const getStatusBadge = () => {
		if (isApproved) return <Badge className="bg-green-600">Approved</Badge>;
		if (isRejected) return <Badge variant="destructive">Rejected</Badge>;
		return <Badge variant="secondary">Pending</Badge>;
	};

	const getVoteStatus = () => {
		if (!request.voted) return null;
		if (request.userVote === true) return 'You approved';
		if (request.userVote === false) return 'You rejected';
		return 'You voted';
	};

	return (
		<Card
			className={
				isApproved
					? 'border-green-200 bg-green-50/50 dark:border-green-800 dark:bg-green-950/20'
					: isRejected
						? 'border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/20'
						: ''
			}
		>
			<CardHeader className="pb-3">
				<div className="flex items-start justify-between gap-4">
					<div className="flex-1">
						<div className="flex items-center gap-2 mb-1">
							<span className="font-mono text-sm font-semibold">#{requestId}</span>
							{getStatusBadge()}
						</div>
						<p className="text-sm text-muted-foreground">{getRequestDescription()}</p>
					</div>
					<div className="flex items-center gap-2">
						{canVote && onVote && (
							<>
								<Button size="sm" variant="outline" onClick={() => onVote(requestId, true)}>
									Approve
								</Button>
								<Button size="sm" variant="outline" onClick={() => onVote(requestId, false)}>
									Reject
								</Button>
							</>
						)}
						{canExecute && onExecute && (
							<Button size="sm" onClick={() => onExecute(requestId)}>
								Execute
							</Button>
						)}
						{isApproved && isTransactionRequest && onBroadcast && !broadcastStatus.broadcasted && (
							<Button
								size="sm"
								className="bg-green-600 hover:bg-green-700"
								onClick={() => onBroadcast(requestId)}
							>
								Broadcast
							</Button>
						)}
						{isApproved && isTransactionRequest && broadcastStatus.broadcasted && (
							<Badge className="bg-blue-600">Broadcasted</Badge>
						)}
					</div>
				</div>
			</CardHeader>

			<CardContent className="space-y-2">
				{transactionDetails && transactionDetails.recipients.length > 0 && (
					<div className="space-y-1">
						{transactionDetails.recipients.map((recipient, idx) => (
							<div key={idx} className="flex items-center gap-2 text-sm">
								<span className="text-muted-foreground">To:</span>
								<span className="font-mono">{shorten(recipient.address, 10)}</span>
								<span className="text-muted-foreground">•</span>
								<span className="font-medium">{formatSats(recipient.amount)}</span>
							</div>
						))}
						{transactionDetails.changeOutput && (
							<div className="flex items-center gap-2 text-sm text-muted-foreground">
								<span>Change:</span>
								<span className="font-mono">
									{shorten(transactionDetails.changeOutput.address, 10)}
								</span>
								<span>•</span>
								<span>{formatSats(transactionDetails.changeOutput.amount)}</span>
							</div>
						)}
					</div>
				)}

				{/* Broadcast status details */}
				{broadcastStatus.broadcasted && broadcastStatus.txid && (
					<div className="space-y-1 pt-2 border-t">
						<div className="flex items-center gap-2 text-sm">
							<span className="text-muted-foreground">Transaction ID:</span>
							<a
								href={`${wallet.getNetwork() === 'testnet' ? 'https://blockstream.info/testnet' : 'https://blockstream.info'}/tx/${broadcastStatus.txid}`}
								target="_blank"
								rel="noopener noreferrer"
								className="font-mono text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 underline"
							>
								{shorten(broadcastStatus.txid, 12)}
							</a>
						</div>
						<div className="flex items-center gap-2 text-sm">
							<span className="text-muted-foreground">Status:</span>
							{broadcastStatus.confirmed ? (
								<Badge className="bg-green-600">
									Confirmed ({broadcastStatus.confirmations} confirmation
									{broadcastStatus.confirmations !== 1 ? 's' : ''})
								</Badge>
							) : (
								<Badge
									variant="outline"
									className="border-yellow-500 text-yellow-600 dark:text-yellow-400"
								>
									Unconfirmed
								</Badge>
							)}
						</div>
						{broadcastStatus.blockHeight && (
							<div className="flex items-center gap-2 text-sm">
								<span className="text-muted-foreground">Block Height:</span>
								<span className="font-medium">{broadcastStatus.blockHeight}</span>
							</div>
						)}
					</div>
				)}

				<div className="flex items-center gap-4 text-sm pt-2 border-t">
					<span className="text-muted-foreground">
						Approvals:{' '}
						<span className="font-medium text-foreground">
							{approversCount} / {approvalThreshold}
						</span>
					</span>
					<span className="text-muted-foreground">
						Rejections:{' '}
						<span className="font-medium text-foreground">
							{rejectersCount} / {rejectionThreshold}
						</span>
					</span>
					{getVoteStatus() && (
						<Badge variant="outline" className="ml-auto">
							{getVoteStatus()}
						</Badge>
					)}
				</div>
			</CardContent>
		</Card>
	);
}
