'use client';

import { ConnectButton, useCurrentAccount } from '@mysten/dapp-kit';
import { AlertTriangle, Menu, Wallet } from 'lucide-react';
import { useEffect, useState } from 'react';

import { BalanceDisplay } from '@/components/common/BalanceDisplay';
import { EmptyState } from '@/components/common/EmptyState';
import { CreateMultisigModal } from '@/components/modals/CreateMultisigModal';
import { MultisigDetailsView } from '@/components/multisig/MultisigDetailsView';
import { AppSidebar } from '@/components/sidebar/AppSidebar';
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import {
	Sheet,
	SheetContent,
	SheetDescription,
	SheetHeader,
	SheetTitle,
} from '@/components/ui/sheet';
import { useMultisigContext } from '@/contexts/MultisigContext';
import { useIsMobile } from '@/hooks/use-mobile';
import { useMultisigOwnership } from '@/hooks/useMultisigData';
import { useMultisigFunctions } from '@/hooks/useMultisigFunctions';
import { useIds } from '@/hooks/useObjects';
import {
	dismissToast,
	showErrorToast,
	showLoadingToast,
	showSuccessToast,
} from '@/lib/error-handling';

export default function Dashboard() {
	const account = useCurrentAccount();
	const { data: ownerships, isLoading } = useMultisigOwnership();
	const { selectedMultisig, selectMultisig, selectedMultisigId } = useMultisigContext();
	const [createMultisigOpen, setCreateMultisigOpen] = useState(false);
	const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
	const [warningOpen, setWarningOpen] = useState(true);
	const { ikaPackageId } = useIds();
	const isMobile = useIsMobile();

	const {
		createMultisig,
		addPresignToMultisig,
		createTransactionRequest,
		voteOnRequest,
		executeMultisigRequest,
		broadcastApprovedTransaction,
		createAddMemberRequest,
		createRemoveMemberRequest,
		createChangeApprovalThresholdRequest,
		createChangeRejectionThresholdRequest,
		createChangeExpirationDurationRequest,
		addIkaBalanceToMultisig,
		addSuiBalanceToMultisig,
		isKeysReady,
		isLoadingKeys,
	} = useMultisigFunctions();

	// Auto-close mobile menu when a multisig is selected
	useEffect(() => {
		if (isMobile && selectedMultisig) {
			setMobileMenuOpen(false);
		}
	}, [isMobile, selectedMultisig]);

	// Sync selectedMultisig with fresh data when ownerships refetch
	// This ensures the selected multisig is always up-to-date
	useEffect(() => {
		if (selectedMultisigId && ownerships) {
			const freshMultisig = ownerships.find((m) => m.id === selectedMultisigId);
			if (freshMultisig) {
				// Only update if the object reference has changed (data was refetched)
				if (freshMultisig !== selectedMultisig) {
					selectMultisig(freshMultisig);
				}
			} else {
				// Selected multisig no longer exists, clear selection
				selectMultisig(null);
			}
		}
	}, [ownerships, selectedMultisigId]);

	const handleCreateMultisig = async (params: {
		members: string[];
		approvalThreshold: number;
		rejectionThreshold: number;
		expirationDuration: number;
	}) => {
		const toastId = showLoadingToast('Creating multisig...');
		try {
			// Convert seconds to milliseconds for the contract
			await createMultisig({
				...params,
				expirationDuration: params.expirationDuration * 1000,
			});
			dismissToast(toastId);
			showSuccessToast('Multisig created successfully!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create multisig');
			throw error;
		}
	};

	const handleCreateTx = async (params: any) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating transaction request...');
		try {
			await createTransactionRequest({
				multisig: selectedMultisig.class,
				...params,
			});
			dismissToast(toastId);
			showSuccessToast('Transaction request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create transaction request');
			throw error;
		}
	};

	const handleVote = async (requestId: number, vote: boolean) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast(vote ? 'Approving...' : 'Rejecting...');
		try {
			await voteOnRequest({
				multisig: selectedMultisig.class,
				requestId,
				vote,
			});
			dismissToast(toastId);
			showSuccessToast(vote ? 'Request approved!' : 'Request rejected!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to vote');
		}
	};

	const handleExecute = async (requestId: number) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Executing request...');
		try {
			const result = await executeMultisigRequest({
				multisig: selectedMultisig.class,
				requestId,
			});
			dismissToast(toastId);
			return result;
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to execute request');
			throw error;
		}
	};

	const handleBroadcast = async (requestId: number) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Broadcasting transaction...');
		try {
			const result = await broadcastApprovedTransaction({
				multisig: selectedMultisig.class,
				requestId,
			});
			dismissToast(toastId);
			// No need to refetch - this doesn't change on-chain state
			return result;
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to broadcast transaction');
			throw error;
		}
	};

	const handleAddMember = async (address: string) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating add member request...');
		try {
			await createAddMemberRequest({
				multisig: selectedMultisig.class,
				memberAddress: address,
			});
			dismissToast(toastId);
			showSuccessToast('Add member request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create add member request');
			throw error;
		}
	};

	const handleRemoveMember = async (address: string) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating remove member request...');
		try {
			await createRemoveMemberRequest({
				multisig: selectedMultisig.class,
				memberAddress: address,
			});
			dismissToast(toastId);
			showSuccessToast('Remove member request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create remove member request');
			throw error;
		}
	};

	const handleChangeApprovalThreshold = async (threshold: number) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating threshold change request...');
		try {
			await createChangeApprovalThresholdRequest({
				multisig: selectedMultisig.class,
				newThreshold: threshold,
			});
			dismissToast(toastId);
			showSuccessToast('Approval threshold change request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create threshold change request');
			throw error;
		}
	};

	const handleChangeRejectionThreshold = async (threshold: number) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating threshold change request...');
		try {
			await createChangeRejectionThresholdRequest({
				multisig: selectedMultisig.class,
				newThreshold: threshold,
			});
			dismissToast(toastId);
			showSuccessToast('Rejection threshold change request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create threshold change request');
			throw error;
		}
	};

	const handleChangeExpirationDuration = async (durationSeconds: number) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Creating expiration duration change request...');
		try {
			// Convert seconds to milliseconds
			const durationMs = durationSeconds * 1000;
			await createChangeExpirationDurationRequest({
				multisig: selectedMultisig.class,
				newDuration: durationMs,
			});
			dismissToast(toastId);
			showSuccessToast('Expiration duration change request created!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to create expiration duration change request');
			throw error;
		}
	};

	const handleAddIkaBalance = async (amount: bigint) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Adding IKA balance...');
		try {
			await addIkaBalanceToMultisig({
				multisig: selectedMultisig.class,
				amount,
			});
			dismissToast(toastId);
			showSuccessToast('IKA balance added successfully!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to add IKA balance');
			throw error;
		}
	};

	const handleAddSuiBalance = async (amount: bigint) => {
		if (!selectedMultisig) return;

		const toastId = showLoadingToast('Adding SUI balance...');
		try {
			await addSuiBalanceToMultisig({
				multisig: selectedMultisig.class,
				amount,
			});
			dismissToast(toastId);
			showSuccessToast('SUI balance added successfully!');
		} catch (error) {
			dismissToast(toastId);
			showErrorToast(error, 'Failed to add SUI balance');
			throw error;
		}
	};

	return (
		<div className="flex h-screen bg-background overflow-hidden">
			{/* Warning Dialog */}
			<AlertDialog open={warningOpen} onOpenChange={setWarningOpen}>
				<AlertDialogContent>
					<AlertDialogHeader>
						<div className="flex items-center gap-2 text-destructive">
							<AlertTriangle className="h-5 w-5" />
							<AlertDialogTitle>⚠️ Testnet Only - Developer Warning</AlertDialogTitle>
						</div>
						<AlertDialogDescription className="text-left space-y-2 pt-2">
							<p className="font-semibold text-foreground">
								This Bitcoin multisig demo is provided for developer testing and educational
								purposes only and must be used on Bitcoin testnet only (not mainnet).
							</p>
							<p>
								It has not been audited and may contain bugs or unexpected behavior. Do not use it
								with real funds or production wallets. Use only test keys and disposable test
								amounts.
							</p>
							<p className="font-semibold text-destructive">You assume all risk by proceeding.</p>
						</AlertDialogDescription>
					</AlertDialogHeader>
					<AlertDialogFooter>
						<AlertDialogAction onClick={() => setWarningOpen(false)}>
							I Understand - Proceed with Testnet Only
						</AlertDialogAction>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>

			{/* Desktop Sidebar */}
			<div className="hidden md:block w-80 border-r shrink-0">
				<AppSidebar onCreateNew={() => setCreateMultisigOpen(true)} />
			</div>

			{/* Mobile Sidebar Sheet */}
			<Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
				<SheetContent side="left" className="w-80 p-0">
					<SheetHeader className="sr-only">
						<SheetTitle>Navigation Menu</SheetTitle>
						<SheetDescription>Access your multisig wallets and settings</SheetDescription>
					</SheetHeader>
					<div className="h-full">
						<AppSidebar
							onCreateNew={() => {
								setCreateMultisigOpen(true);
								setMobileMenuOpen(false);
							}}
						/>
					</div>
				</SheetContent>
			</Sheet>

			{/* Main Content */}
			<div className="flex-1 flex flex-col overflow-hidden min-w-0">
				{/* Header */}
				<header className="border-b bg-background shrink-0">
					<div className="flex items-center justify-between px-4 md:px-6 py-3 md:py-4 gap-4">
						<div className="flex items-center gap-3 min-w-0 flex-1">
							{/* Mobile Menu Button */}
							{account && (
								<Button
									variant="ghost"
									size="icon"
									className="md:hidden shrink-0"
									onClick={() => setMobileMenuOpen(true)}
								>
									<Menu className="h-5 w-5" />
								</Button>
							)}
							<div className="min-w-0 flex-1">
								<h1 className="text-lg md:text-xl font-semibold truncate tracking-tight">
									{selectedMultisig ? 'Multisig Details' : 'bitisi'}
								</h1>
								<p className="text-xs md:text-sm text-muted-foreground truncate">
									{account ? 'bitcoin multisig on sui' : 'connect wallet to get started'}
								</p>
							</div>
						</div>
						<div className="flex items-center gap-2 shrink-0">
							<BalanceDisplay ikaPackageId={ikaPackageId} />
							<ConnectButton />
						</div>
					</div>
				</header>

				{/* Content Area */}
				<main className="flex-1 overflow-auto p-4 md:p-6">
					<div className="max-w-7xl mx-auto">
						{!account ? (
							<EmptyState
								icon={<Wallet className="h-12 w-12" />}
								title="Connect Your Wallet"
								description="Connect your Sui wallet to create and manage Bitcoin multisig wallets."
							/>
						) : isLoadingKeys ? (
							<EmptyState
								title="Initializing..."
								description="Setting up encryption keys. This will only take a moment."
							/>
						) : !isKeysReady ? (
							<EmptyState
								title="Keys Not Ready"
								description="Encryption keys are not ready yet. Please refresh the page."
							/>
						) : selectedMultisig ? (
							<MultisigDetailsView
								multisig={selectedMultisig}
								onCreateTx={handleCreateTx}
								onVote={handleVote}
								onExecute={handleExecute}
								onBroadcast={handleBroadcast}
								onAddMember={handleAddMember}
								onRemoveMember={handleRemoveMember}
								onChangeApprovalThreshold={handleChangeApprovalThreshold}
								onChangeRejectionThreshold={handleChangeRejectionThreshold}
								onChangeExpirationDuration={handleChangeExpirationDuration}
								onAddIkaBalance={handleAddIkaBalance}
								onAddSuiBalance={handleAddSuiBalance}
							/>
						) : ownerships && ownerships.length > 0 ? (
							<EmptyState
								title="Select a Multisig"
								description="Choose a multisig from the sidebar to view its details and manage transactions."
								action={
									isMobile
										? {
												label: 'Open Menu',
												onClick: () => setMobileMenuOpen(true),
											}
										: undefined
								}
							/>
						) : (
							<EmptyState
								title="No Multisigs Yet"
								description="Create your first multisig wallet to get started with secure Bitcoin transactions."
								action={{
									label: 'Create Multisig',
									onClick: () => setCreateMultisigOpen(true),
								}}
							/>
						)}
					</div>
				</main>
			</div>

			{/* Create Multisig Modal */}
			<CreateMultisigModal
				open={createMultisigOpen}
				onOpenChange={setCreateMultisigOpen}
				onSubmit={handleCreateMultisig}
				ikaPackageId={ikaPackageId}
			/>
		</div>
	);
}
