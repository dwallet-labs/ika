'use client';

import { CheckCircle2, XCircle } from 'lucide-react';

import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from '../ui/alert-dialog';

interface VoteConfirmationDialogProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onConfirm: () => void;
	isApprove: boolean;
	requestId: number;
	description: string;
}

export function VoteConfirmationDialog({
	open,
	onOpenChange,
	onConfirm,
	isApprove,
	requestId,
	description,
}: VoteConfirmationDialogProps) {
	return (
		<AlertDialog open={open} onOpenChange={onOpenChange}>
			<AlertDialogContent>
				<AlertDialogHeader>
					<AlertDialogTitle className="flex items-center gap-2">
						{isApprove ? (
							<CheckCircle2 className="h-5 w-5 text-green-500" />
						) : (
							<XCircle className="h-5 w-5 text-red-500" />
						)}
						{isApprove ? 'Approve' : 'Reject'} Request #{requestId}
					</AlertDialogTitle>
					<AlertDialogDescription asChild>
						<div className="space-y-3">
							<div className="bg-muted rounded-md p-3">
								<div className="text-sm font-medium text-foreground">{description}</div>
							</div>
							<div
								className={`rounded-md p-3 border ${
									isApprove
										? 'bg-green-50 dark:bg-green-950/20 border-green-200 dark:border-green-800'
										: 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800'
								}`}
							>
								<div
									className={`text-sm ${
										isApprove
											? 'text-green-900 dark:text-green-100'
											: 'text-red-900 dark:text-red-100'
									}`}
								>
									{isApprove
										? '✓ Your approval will be recorded on-chain. If enough members approve, the request can be executed.'
										: '✗ Your rejection will be recorded on-chain. If enough members reject, the request will be cancelled.'}
								</div>
							</div>
						</div>
					</AlertDialogDescription>
				</AlertDialogHeader>
				<AlertDialogFooter>
					<AlertDialogCancel>Cancel</AlertDialogCancel>
					<AlertDialogAction
						onClick={onConfirm}
						className={isApprove ? '' : 'bg-destructive hover:bg-destructive/90'}
					>
						{isApprove ? '✓ Approve' : '✗ Reject'}
					</AlertDialogAction>
				</AlertDialogFooter>
			</AlertDialogContent>
		</AlertDialog>
	);
}
