'use client';

import { useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';

import {
	AlertDialog,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from '../ui/alert-dialog';
import { Button } from '../ui/button';

interface ExecuteConfirmationDialogProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onExecute: () => Promise<any>;
	requestId: number;
	description: string;
}

export function ExecuteConfirmationDialog({
	open,
	onOpenChange,
	onExecute,
	requestId,
	description,
}: ExecuteConfirmationDialogProps) {
	const [isExecuting, setIsExecuting] = useState(false);

	const handleExecute = async () => {
		setIsExecuting(true);
		try {
			const result = await onExecute();
			if (result?.txid) {
				showSuccessToast('Transaction executed!', `TXID: ${result.txid}`);
			} else {
				showSuccessToast('Request executed successfully!');
			}
			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to execute request');
		} finally {
			setIsExecuting(false);
		}
	};

	return (
		<AlertDialog open={open} onOpenChange={onOpenChange}>
			<AlertDialogContent>
				<AlertDialogHeader>
					<AlertDialogTitle>Execute Request #{requestId}</AlertDialogTitle>
					<AlertDialogDescription asChild>
						<div className="space-y-3">
							<div className="bg-muted rounded-md p-3">
								<div className="text-sm font-medium text-foreground">{description}</div>
							</div>
							<div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 rounded-md p-3">
								<div className="text-sm text-green-900 dark:text-green-100 font-medium mb-1">
									✓ Ready to Execute
								</div>
								<div className="text-xs text-green-900/80 dark:text-green-100/80">
									This request has received enough approvals. Executing will finalize the multisig
									signing process and prepare the transaction for broadcast.
								</div>
							</div>
							{isExecuting && (
								<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3 animate-pulse">
									<div className="text-sm text-blue-900 dark:text-blue-100 font-medium">
										🔐 Signing in progress...
									</div>
									<div className="text-xs text-blue-900/80 dark:text-blue-100/80 mt-1">
										Computing cryptographic signatures. This may take a moment.
									</div>
								</div>
							)}
						</div>
					</AlertDialogDescription>
				</AlertDialogHeader>
				<AlertDialogFooter>
					<Button variant="outline" onClick={() => onOpenChange(false)} disabled={isExecuting}>
						Cancel
					</Button>
					<Button onClick={handleExecute} disabled={isExecuting}>
						{isExecuting ? 'Executing...' : '⚡ Execute Now'}
					</Button>
				</AlertDialogFooter>
			</AlertDialogContent>
		</AlertDialog>
	);
}
