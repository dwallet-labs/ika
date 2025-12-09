'use client';

import { ExternalLink } from 'lucide-react';
import { useEffect, useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';
import { shorten } from '@/lib/formatting';

import {
	AlertDialog,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from '../ui/alert-dialog';
import { Button } from '../ui/button';

interface BroadcastConfirmationDialogProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onBroadcast: () => Promise<any>;
	requestId: number;
	description: string;
	broadcastStatus?: {
		broadcasted: boolean;
		txid?: string;
		confirmed?: boolean;
		confirmations?: number;
	} | null;
	network?: 'testnet' | 'mainnet';
}

export function BroadcastConfirmationDialog({
	open,
	onOpenChange,
	onBroadcast,
	requestId,
	description,
	broadcastStatus,
	network = 'testnet',
}: BroadcastConfirmationDialogProps) {
	const [isBroadcasting, setIsBroadcasting] = useState(false);
	const [alreadyBroadcasted, setAlreadyBroadcasted] = useState(false);

	useEffect(() => {
		setAlreadyBroadcasted(broadcastStatus?.broadcasted ?? false);
	}, [broadcastStatus]);

	const explorerUrl = broadcastStatus?.txid
		? network === 'mainnet'
			? `https://blockstream.info/tx/${broadcastStatus.txid}`
			: `https://blockstream.info/testnet/tx/${broadcastStatus.txid}`
		: null;

	const handleBroadcast = async () => {
		setIsBroadcasting(true);
		try {
			const result = await onBroadcast();
			const txid = result?.txid;

			if (txid) {
				showSuccessToast('Transaction broadcasted!', `TXID: ${shorten(txid, 12)}`);
			} else {
				showSuccessToast('Transaction broadcasted successfully!');
			}

			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to broadcast transaction');
		} finally {
			setIsBroadcasting(false);
		}
	};

	return (
		<AlertDialog open={open} onOpenChange={onOpenChange}>
			<AlertDialogContent>
				<AlertDialogHeader>
					<AlertDialogTitle>Broadcast Transaction #{requestId}</AlertDialogTitle>
					<AlertDialogDescription asChild>
						<div className="space-y-3">
							<div className="bg-muted rounded-md p-3">
								<div className="text-sm font-medium text-foreground">{description}</div>
							</div>
							{alreadyBroadcasted && broadcastStatus?.txid ? (
								<div className="space-y-3">
									<div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 rounded-md p-3">
										<div className="text-sm text-green-900 dark:text-green-100 font-medium mb-1">
											✓ Already Broadcasted
										</div>
										<div className="text-xs text-green-900/80 dark:text-green-100/80 mb-2">
											This transaction has already been broadcasted to the Bitcoin network.
										</div>
										<div className="bg-green-100 dark:bg-green-900/30 rounded px-2 py-1 font-mono text-xs text-green-900 dark:text-green-100 break-all">
											{broadcastStatus.txid}
										</div>
										{broadcastStatus.confirmed && (
											<div className="text-xs text-green-900/80 dark:text-green-100/80 mt-2">
												✓ Confirmed ({broadcastStatus.confirmations ?? 0} confirmations)
											</div>
										)}
										{!broadcastStatus.confirmed && (
											<div className="text-xs text-yellow-900 dark:text-yellow-100 mt-2">
												⏳ Pending confirmation...
											</div>
										)}
									</div>
									{explorerUrl && (
										<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
											<div className="text-sm text-blue-900 dark:text-blue-100 font-medium mb-2">
												View Transaction Details
											</div>
											<a
												href={explorerUrl}
												target="_blank"
												rel="noopener noreferrer"
												className="inline-flex items-center gap-2 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline"
											>
												<ExternalLink className="h-3 w-3" />
												Open in Bitcoin Explorer
											</a>
										</div>
									)}
								</div>
							) : (
								<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
									<div className="text-sm text-blue-900 dark:text-blue-100 font-medium mb-1">
										📡 Broadcasting to Bitcoin Network
									</div>
									<div className="text-xs text-blue-900/80 dark:text-blue-100/80">
										This will broadcast the already-signed transaction to the Bitcoin network. The
										transaction will be publicly visible and irreversible once confirmed.
									</div>
								</div>
							)}
							{isBroadcasting && (
								<div className="bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800 rounded-md p-3 animate-pulse">
									<div className="text-sm text-yellow-900 dark:text-yellow-100">
										⏳ Broadcasting in progress...
									</div>
								</div>
							)}
						</div>
					</AlertDialogDescription>
				</AlertDialogHeader>
				<AlertDialogFooter>
					{alreadyBroadcasted ? (
						<>
							<Button variant="outline" onClick={() => onOpenChange(false)}>
								Close
							</Button>
							{explorerUrl && (
								<Button asChild>
									<a href={explorerUrl} target="_blank" rel="noopener noreferrer">
										<ExternalLink className="h-4 w-4 mr-2" />
										View in Explorer
									</a>
								</Button>
							)}
						</>
					) : (
						<>
							<Button
								variant="outline"
								onClick={() => onOpenChange(false)}
								disabled={isBroadcasting}
							>
								Cancel
							</Button>
							<Button onClick={handleBroadcast} disabled={isBroadcasting}>
								{isBroadcasting ? 'Broadcasting...' : '📡 Broadcast Now'}
							</Button>
						</>
					)}
				</AlertDialogFooter>
			</AlertDialogContent>
		</AlertDialog>
	);
}
