import { useCurrentAccount } from '@mysten/dapp-kit';
import {
	AlertCircle,
	Bitcoin,
	CheckCircle,
	Copy,
	ExternalLink,
	Plus,
	Send,
	Users,
	Wallet,
} from 'lucide-react';
import React, { useState } from 'react';

import { BitcoinFaucet } from '@/components/BitcoinFaucet';
import { CreateMultisigModal, MultisigParams } from '@/components/CreateMultisigModal';
import { CreateTransaction } from '@/components/CreateTransaction';
import {
	TransactionState,
	TransactionStates,
	useTransactionStates,
} from '@/components/TransactionStates';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useMultisig } from '@/contract/multisig';
import { BitcoinUtils } from '@/lib/bitcoin-utils';

import * as RequestModule from '../generated/ika_btc_multisig/multisig_request';

interface MultisigWallet {
	id: string;
	dwalletID: string | null;
	bitcoinAddress: string | null;
	participants: string[];
	threshold: number;
	totalParticipants: number;
	status: 'creating' | 'active' | 'error';
	createdAt: Date;
	isFetched?: boolean; // indicates if this was fetched vs created
}

export function MultisigDashboard() {
	const { createMultisig, fetchMultisig, fetchPendingRequests, voteOnRequest, executeRequest } =
		useMultisig();
	const currentAccount = useCurrentAccount();
	const [isCreating, setIsCreating] = useState(false);
	const [multisigWallets, setMultisigWallets] = useState<MultisigWallet[]>([]);
	const [error, setError] = useState<string | null>(null);
	const [showCreateTransaction, setShowCreateTransaction] = useState<string | null>(null);
	const [showFaucet, setShowFaucet] = useState(false);
	const [showCreateModal, setShowCreateModal] = useState(false);

	// Transaction states for multisig creation
	const {
		states: transactionStates,
		setStateStatus,
		resetStates,
	} = useTransactionStates([
		{
			id: 'encryption_key',
			title: 'Register Encryption Key',
			description: 'Setting up user encryption keys for secure communication',
		},
		{
			id: 'create_multisig',
			title: 'Create Multisig Contract',
			description: 'Deploying the multisig wallet contract on the blockchain',
		},
		{
			id: 'dkg_second_round',
			title: 'Distributed Key Generation',
			description: 'Generating shared cryptographic keys across participants',
		},
		{
			id: 'accept_and_share',
			title: 'Accept & Share Keys',
			description: 'Finalizing key distribution and accepting the generated keys',
		},
		{
			id: 'generate_address',
			title: 'Generate Bitcoin Address',
			description: 'Creating the Bitcoin address from the distributed public key',
		},
	]);

	// Fetch multisig state
	const [fetchMultisigId, setFetchMultisigId] = useState('');
	const [isFetching, setIsFetching] = useState(false);
	const [fetchError, setFetchError] = useState<string | null>(null);

	// Pending requests state
	const [pendingRequests, setPendingRequests] = useState<
		(typeof RequestModule.Request.$inferType & {
			request_id: string;
			parsed_votes: { [key: string]: boolean };
		})[]
	>([]);
	const [isLoadingRequests, setIsLoadingRequests] = useState(false);
	const [votingRequest, setVotingRequest] = useState<{ [key: number]: boolean }>({});
	const [executingRequest, setExecutingRequest] = useState<{ [key: number]: boolean }>({});
	const [selectedMultisigForRequests, setSelectedMultisigForRequests] = useState<string | null>(
		null,
	);

	// Store multisig data for threshold checking
	const [multisigData, setMultisigData] = useState<{
		id: string;
		approvalThreshold: number;
		rejectionThreshold: number;
	} | null>(null);

	const handleCreateMultisig = async (params: MultisigParams) => {
		try {
			setIsCreating(true);
			setError(null);
			resetStates();

			const result = await createMultisig(params, setStateStatus);

			console.log('=== DASHBOARD RECEIVED RESULT ===');
			console.log('Result multisigID:', result.multisigID);
			console.log('Result dwalletID:', result.dwalletID);
			console.log('Result bitcoinAddress:', result.bitcoinAddress);

			console.log(
				'Dashboard address validation:',
				BitcoinUtils.validateAddress(result.bitcoinAddress),
			);
			console.log('==================================');

			const newWallet: MultisigWallet = {
				id: result.multisigID,
				dwalletID: result.dwalletID,
				bitcoinAddress: result.bitcoinAddress,
				participants: params.members,
				threshold: params.approvalThreshold,
				totalParticipants: params.members.length,
				status: 'active',
				createdAt: new Date(),
			};

			setMultisigWallets((prev) => [newWallet, ...prev]);
			setShowCreateModal(false);
		} catch (err) {
			console.error('Failed to create multisig:', err);
			setError(err instanceof Error ? err.message : 'Failed to create multisig wallet');
		} finally {
			setIsCreating(false);
		}
	};

	const handleFetchMultisig = async () => {
		if (!fetchMultisigId.trim()) {
			setFetchError('Please enter a multisig ID');
			return;
		}

		if (!currentAccount) {
			setFetchError('Please connect your wallet first');
			return;
		}

		try {
			setIsFetching(true);
			setFetchError(null);

			// Check if multisig is already in the list
			if (multisigWallets.some((wallet) => wallet.id === fetchMultisigId)) {
				setFetchError('This multisig is already in your dashboard');
				return;
			}

			const multisigData = await fetchMultisig(fetchMultisigId);

			// Check if current user is a member
			const isMember = multisigData.members.some(
				(member) => member.toLowerCase() === currentAccount.address.toLowerCase(),
			);

			if (!isMember) {
				setFetchError('You are not a member of this multisig wallet');
				return;
			}

			// Add to dashboard
			const fetchedWallet: MultisigWallet = {
				id: multisigData.id,
				dwalletID: multisigData.dwalletId || null,
				bitcoinAddress: multisigData.bitcoinAddress || null,
				participants: multisigData.members,
				threshold: parseInt(multisigData.approvalThreshold.toString()),
				totalParticipants: multisigData.members.length,
				status: multisigData.ready ? 'active' : 'error',
				createdAt: new Date(), // We don't have creation date from fetch, so use current
				isFetched: true,
			};

			setMultisigWallets((prev) => [fetchedWallet, ...prev]);
			setFetchMultisigId(''); // Clear input
		} catch (err) {
			console.error('Failed to fetch multisig:', err);
			setFetchError(err instanceof Error ? err.message : 'Failed to fetch multisig wallet');
		} finally {
			setIsFetching(false);
		}
	};

	const loadPendingRequests = async (multisigId: string) => {
		try {
			setIsLoadingRequests(true);
			const requests = await fetchPendingRequests(multisigId);
			// @ts-ignore
			setPendingRequests(requests);
			setSelectedMultisigForRequests(multisigId);

			// Also fetch multisig data for threshold checking
			const multisigInfo = await fetchMultisig(multisigId);
			setMultisigData({
				id: multisigInfo.id,
				approvalThreshold: parseInt(multisigInfo.approvalThreshold.toString()),
				rejectionThreshold: parseInt(multisigInfo.rejectionThreshold.toString()),
			});
		} catch (error) {
			console.error('Failed to load pending requests:', error);
			setPendingRequests([]);
		} finally {
			setIsLoadingRequests(false);
		}
	};

	const handleVote = async (multisigId: string, requestId: number, approve: boolean) => {
		try {
			setVotingRequest((prev) => ({ ...prev, [requestId]: approve }));

			await voteOnRequest(multisigId, requestId, approve);

			// Reload pending requests after voting
			await loadPendingRequests(multisigId);
		} catch (error) {
			console.error('Failed to vote on request:', error);
		} finally {
			setVotingRequest((prev) => {
				const newState = { ...prev };
				delete newState[requestId];
				return newState;
			});
		}
	};

	const handleExecuteRequest = async (multisigId: string, requestId: number) => {
		try {
			setExecutingRequest((prev) => ({ ...prev, [requestId]: true }));

			await executeRequest(multisigId, requestId);

			// Reload pending requests after execution
			await loadPendingRequests(multisigId);
		} catch (error) {
			console.error('Failed to execute request:', error);
		} finally {
			setExecutingRequest((prev) => {
				const newState = { ...prev };
				delete newState[requestId];
				return newState;
			});
		}
	};

	const isRequestReadyToExecute = (request: any) => {
		if (!multisigData) {
			console.log('No multisig data available');
			return false;
		}

		console.log('Checking request execution readiness:', {
			requestId: request.request_id,
			status: request.status,
			approversCount: request.approvers_count,
			rejectersCount: request.rejecters_count,
			approvalThreshold: multisigData.approvalThreshold,
			rejectionThreshold: multisigData.rejectionThreshold,
		});

		// Check if request is still pending
		if (!request.status || !request.status.Pending) {
			console.log('Request not pending:', request.status);
			return false;
		}

		// Check if approval threshold is met
		const approversCount = parseInt(request.approvers_count.toString());
		const hasEnoughApprovals = approversCount >= multisigData.approvalThreshold;
		console.log(
			'Has enough approvals:',
			hasEnoughApprovals,
			'(',
			approversCount,
			'>=',
			multisigData.approvalThreshold,
			')',
		);

		// Check if rejection threshold is not met
		const rejectersCount = parseInt(request.rejecters_count.toString());
		const hasNotEnoughRejections = rejectersCount < multisigData.rejectionThreshold;
		console.log('Has not enough rejections:', hasNotEnoughRejections);

		const result = hasEnoughApprovals && hasNotEnoughRejections;
		console.log('Is ready to execute:', result);

		return result;
	};

	const formatRequestType = (requestType: any) => {
		if (typeof requestType === 'string') return requestType;

		// Handle different request types
		if (requestType.Transaction) {
			return 'Bitcoin Transaction';
		}
		if (requestType.AddMember) {
			return 'Add Member';
		}
		if (requestType.RemoveMember) {
			return 'Remove Member';
		}
		if (requestType.ChangeApprovalThreshold) {
			return 'Change Approval Threshold';
		}
		if (requestType.ChangeRejectionThreshold) {
			return 'Change Rejection Threshold';
		}
		if (requestType.ChangeExpirationDuration) {
			return 'Change Expiration Duration';
		}

		return 'Unknown Request Type';
	};

	const copyToClipboard = (text: string) => {
		navigator.clipboard.writeText(text);
	};

	const truncateAddress = (address: string) => {
		return `${address.slice(0, 6)}...${address.slice(-4)}`;
	};

	return (
		<div className="p-4">
			<div className="max-w-6xl mx-auto">
				{/* Header */}
				<div className="mb-8">
					<div className="flex items-center justify-between">
						<div>
							<h1 className="text-3xl font-bold text-foreground mb-2">Multisig Bitcoin Wallet</h1>
							<p className="text-muted-foreground">
								Create and manage secure multisignature wallets using IKA protocol
							</p>
						</div>
						<Button
							onClick={() => setShowFaucet(true)}
							variant="outline"
							className="flex items-center gap-2"
						>
							<Bitcoin className="w-4 h-4" />
							Get Testnet BTC
						</Button>
					</div>
				</div>

				{/* Create Multisig Card */}
				<Card className="mb-8">
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<Plus className="w-5 h-5" />
							Create New Multisig Wallet
						</CardTitle>
						<CardDescription>
							Create a new multisignature wallet with customizable parameters and distributed key
							generation
						</CardDescription>
					</CardHeader>
					<CardContent>
						<div className="flex items-center gap-4 mb-4">
							<div className="flex items-center gap-2">
								<Users className="w-4 h-4 text-muted-foreground" />
								<span className="text-sm text-muted-foreground">Customizable thresholds</span>
							</div>
							<div className="flex items-center gap-2">
								<Wallet className="w-4 h-4 text-muted-foreground" />
								<span className="text-sm text-muted-foreground">Distributed keys</span>
							</div>
						</div>

						{error && (
							<div className="flex items-center gap-2 p-3 mb-4 bg-destructive/10 border border-destructive/20 rounded-lg">
								<AlertCircle className="w-4 h-4 text-destructive" />
								<span className="text-sm text-destructive">{error}</span>
							</div>
						)}

						<Button
							onClick={() => setShowCreateModal(true)}
							disabled={isCreating}
							className="w-full sm:w-auto"
						>
							<Plus className="w-4 h-4 mr-2" />
							Create Multisig Wallet
						</Button>
					</CardContent>
				</Card>

				{/* Transaction States Display */}
				{isCreating && (
					<TransactionStates
						states={transactionStates}
						title="Multisig Creation Progress"
						className="mb-8"
					/>
				)}

				{/* Fetch Existing Multisig Card */}
				<Card className="mb-8">
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<Wallet className="w-5 h-5" />
							Add Existing Multisig Wallet
						</CardTitle>
						<CardDescription>
							Enter a multisig wallet ID to add it to your dashboard if you're a member
						</CardDescription>
					</CardHeader>
					<CardContent>
						<div className="flex gap-2 mb-4">
							<div className="flex-1">
								<Label htmlFor="multisig-id" className="sr-only">
									Multisig ID
								</Label>
								<Input
									id="multisig-id"
									placeholder="Enter multisig wallet ID..."
									value={fetchMultisigId}
									onChange={(e) => setFetchMultisigId(e.target.value)}
									disabled={isFetching}
								/>
							</div>
							<Button
								onClick={handleFetchMultisig}
								disabled={isFetching || !fetchMultisigId.trim()}
								className="px-6"
							>
								{isFetching ? (
									<>
										<div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
										Fetching...
									</>
								) : (
									'Add Wallet'
								)}
							</Button>
						</div>

						{fetchError && (
							<div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
								<AlertCircle className="w-4 h-4 text-destructive" />
								<span className="text-sm text-destructive">{fetchError}</span>
							</div>
						)}
					</CardContent>
				</Card>

				{/* Pending Requests Section */}
				{selectedMultisigForRequests && (
					<Card className="mb-8">
						<CardHeader>
							<CardTitle className="flex items-center gap-2">
								<AlertCircle className="w-5 h-5" />
								Pending Requests
							</CardTitle>
							<CardDescription>
								Transaction and governance requests that need your vote
							</CardDescription>
						</CardHeader>
						<CardContent>
							{isLoadingRequests ? (
								<div className="flex items-center justify-center py-8">
									<div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mr-2" />
									<span>Loading requests...</span>
								</div>
							) : pendingRequests.length === 0 ? (
								<div className="text-center py-8 text-muted-foreground">
									<CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-500" />
									<p>No pending requests at this time</p>
								</div>
							) : (
								<div className="space-y-4">
									{pendingRequests.map((request, index) => (
										<div key={index} className="border rounded-lg p-4">
											<div className="flex items-start justify-between mb-3">
												<div>
													<h4 className="font-medium text-foreground">Request #{index + 1}</h4>
													<p className="text-sm text-muted-foreground">
														{formatRequestType(request.request_type)}
													</p>
												</div>
												<div className="text-right">
													<p className="text-xs text-muted-foreground">
														Created {new Date(+request.created_at).toLocaleDateString()}
													</p>
												</div>
											</div>

											<div className="flex items-center gap-4 mb-3">
												<div className="flex items-center gap-2">
													<CheckCircle className="w-4 h-4 text-green-500" />
													<span className="text-sm">{request.approvers_count} Approvals</span>
												</div>
												<div className="flex items-center gap-2">
													<AlertCircle className="w-4 h-4 text-red-500" />
													<span className="text-sm">{request.rejecters_count} Rejections</span>
												</div>
											</div>

											{/* User's Vote Status */}
											{currentAccount &&
												request.parsed_votes[currentAccount.address] !== undefined && (
													<div
														className={`flex items-center gap-2 mb-3 p-3 rounded-lg border-2 ${
															request.parsed_votes[currentAccount.address]
																? 'bg-green-50 border-green-200 dark:bg-green-950 dark:border-green-800'
																: 'bg-red-50 border-red-200 dark:bg-red-950 dark:border-red-800'
														}`}
													>
														<div
															className={`w-3 h-3 rounded-full ${
																request.parsed_votes[currentAccount.address]
																	? 'bg-green-500'
																	: 'bg-red-500'
															}`}
														></div>
														<span
															className={`text-sm font-semibold ${
																request.parsed_votes[currentAccount.address]
																	? 'text-green-700 dark:text-green-300'
																	: 'text-red-700 dark:text-red-300'
															}`}
														>
															You voted to{' '}
															{request.parsed_votes[currentAccount.address] ? 'APPROVE' : 'REJECT'}
														</span>
														<div
															className={`ml-auto px-2 py-1 rounded-full text-xs font-medium ${
																request.parsed_votes[currentAccount.address]
																	? 'bg-green-200 text-green-800 dark:bg-green-800 dark:text-green-200'
																	: 'bg-red-200 text-red-800 dark:bg-red-800 dark:text-red-200'
															}`}
														>
															Voted
														</div>
													</div>
												)}

											{/* Voting Buttons */}
											<div className="flex gap-2">
												<Button
													size="sm"
													variant="outline"
													className={`transition-all ${
														currentAccount && request.parsed_votes[currentAccount.address] === true
															? 'bg-green-100 border-green-300 text-green-700 cursor-not-allowed opacity-60 dark:bg-green-900 dark:border-green-700 dark:text-green-300'
															: 'text-green-600 border-green-600 hover:bg-green-50 hover:border-green-700'
													}`}
													onClick={() =>
														handleVote(selectedMultisigForRequests!, +request.request_id, true)
													}
													// @ts-ignore
													disabled={
														votingRequest[+request.request_id] !== undefined ||
														(currentAccount &&
															request.parsed_votes[currentAccount.address] !== undefined)
													}
												>
													{votingRequest[+request.request_id] === true ? (
														<>
															<div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin mr-1" />
															Voting...
														</>
													) : (
														<>
															<CheckCircle className="w-3 h-3 mr-1" />
															Approve
														</>
													)}
												</Button>
												<Button
													size="sm"
													variant="outline"
													className={`transition-all ${
														currentAccount && request.parsed_votes[currentAccount.address] === false
															? 'bg-red-100 border-red-300 text-red-700 cursor-not-allowed opacity-60 dark:bg-red-900 dark:border-red-700 dark:text-red-300'
															: 'text-red-600 border-red-600 hover:bg-red-50 hover:border-red-700'
													}`}
													onClick={() =>
														handleVote(selectedMultisigForRequests!, +request.request_id, false)
													}
													// @ts-ignore
													disabled={
														votingRequest[+request.request_id] !== undefined ||
														(currentAccount &&
															request.parsed_votes[currentAccount.address] !== undefined)
													}
												>
													{votingRequest[+request.request_id] === false ? (
														<>
															<div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin mr-1" />
															Voting...
														</>
													) : (
														<>
															<AlertCircle className="w-3 h-3 mr-1" />
															Reject
														</>
													)}
												</Button>
											</div>

											{/* Execute Button - Only show if request is ready to execute */}
											{isRequestReadyToExecute(request) && (
												<div className="flex justify-center mt-3 pt-3 border-t border-border">
													<Button
														size="sm"
														className="bg-blue-600 hover:bg-blue-700 text-white transition-all"
														onClick={() =>
															handleExecuteRequest(
																selectedMultisigForRequests!,
																+request.request_id,
															)
														}
														disabled={executingRequest[+request.request_id] !== undefined}
													>
														{executingRequest[+request.request_id] ? (
															<>
																<div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin mr-1" />
																Executing...
															</>
														) : (
															<>
																<CheckCircle className="w-3 h-3 mr-1" />
																Execute Request
															</>
														)}
													</Button>
												</div>
											)}
										</div>
									))}
								</div>
							)}
						</CardContent>
					</Card>
				)}

				{/* Multisig Wallets List */}
				<div className="space-y-4">
					<h2 className="text-xl font-semibold text-foreground mb-4">Your Multisig Wallets</h2>

					{multisigWallets.length === 0 ? (
						<Card>
							<CardContent className="flex flex-col items-center justify-center py-12">
								<Wallet className="w-12 h-12 text-muted-foreground mb-4" />
								<h3 className="text-lg font-medium text-foreground mb-2">
									No multisig wallets yet
								</h3>
								<p className="text-muted-foreground text-center mb-4">
									Create your first multisignature wallet to get started
								</p>
								<Button onClick={() => setShowCreateModal(true)} disabled={isCreating}>
									<Plus className="w-4 h-4 mr-2" />
									Create Your First Wallet
								</Button>
							</CardContent>
						</Card>
					) : (
						multisigWallets.map((wallet) => (
							<Card key={wallet.id}>
								<CardHeader>
									<div className="flex items-center justify-between">
										<CardTitle className="flex items-center gap-2">
											<Wallet className="w-5 h-5" />
											Multisig Wallet
										</CardTitle>
										<Badge variant={wallet.status === 'active' ? 'default' : 'secondary'}>
											{wallet.status === 'active' && <CheckCircle className="w-3 h-3 mr-1" />}
											{wallet.status === 'creating' ? 'Creating...' : 'Active'}
										</Badge>
									</div>
									<CardDescription>
										{wallet.isFetched ? 'Added to dashboard' : 'Created'} on{' '}
										{wallet.createdAt.toLocaleDateString()}
									</CardDescription>
								</CardHeader>
								<CardContent>
									<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
										<div>
											<h4 className="font-medium text-foreground mb-2">Wallet ID</h4>
											<div className="flex items-center gap-2">
												<code className="text-sm bg-muted px-2 py-1 rounded">
													{truncateAddress(wallet.id)}
												</code>
												<Button
													variant="ghost"
													size="sm"
													onClick={() => copyToClipboard(wallet.id)}
												>
													<Copy className="w-3 h-3" />
												</Button>
											</div>
										</div>

										{wallet.dwalletID && (
											<div>
												<h4 className="font-medium text-foreground mb-2">DWallet ID</h4>
												<div className="flex items-center gap-2">
													<code className="text-sm bg-muted px-2 py-1 rounded">
														{truncateAddress(wallet.dwalletID)}
													</code>
													<Button
														variant="ghost"
														size="sm"
														onClick={() => wallet.dwalletID && copyToClipboard(wallet.dwalletID)}
														disabled={!wallet.dwalletID}
													>
														<Copy className="w-3 h-3" />
													</Button>
												</div>
											</div>
										)}
									</div>

									{wallet.bitcoinAddress && (
										<div className="mt-4">
											<h4 className="font-medium text-foreground mb-2 flex items-center gap-2">
												<Bitcoin className="w-4 h-4" />
												Bitcoin Address
											</h4>
											<div className="flex items-center gap-2">
												<code className="text-sm bg-muted px-2 py-1 rounded font-mono">
													{wallet.bitcoinAddress}
												</code>
												<Button
													variant="ghost"
													size="sm"
													onClick={() =>
														wallet.bitcoinAddress && copyToClipboard(wallet.bitcoinAddress)
													}
													disabled={!wallet.bitcoinAddress}
												>
													<Copy className="w-3 h-3" />
												</Button>
												<Button
													variant="ghost"
													size="sm"
													onClick={() =>
														window.open(
															`https://mempool.space/testnet/address/${wallet.bitcoinAddress}`,
															'_blank',
														)
													}
												>
													<ExternalLink className="w-3 h-3" />
												</Button>
											</div>
										</div>
									)}

									<div className="mt-4">
										<h4 className="font-medium text-gray-900 dark:text-white mb-2">
											Participants ({wallet.threshold} of {wallet.totalParticipants} required)
										</h4>
										<div className="space-y-2">
											{wallet.participants.map((participant, index) => (
												<div key={index} className="flex items-center gap-2">
													<div className="w-2 h-2 bg-blue-500 rounded-full"></div>
													<code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
														{truncateAddress(participant)}
													</code>
													<Button
														variant="ghost"
														size="sm"
														onClick={() => copyToClipboard(participant)}
													>
														<Copy className="w-3 h-3" />
													</Button>
												</div>
											))}
										</div>
									</div>

									<div className="mt-4 flex gap-2">
										<Button
											variant="outline"
											size="sm"
											onClick={() => loadPendingRequests(wallet.id)}
											disabled={isLoadingRequests}
										>
											{isLoadingRequests && selectedMultisigForRequests === wallet.id ? (
												<>
													<div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin mr-1" />
													Loading...
												</>
											) : (
												<>
													<AlertCircle className="w-3 h-3 mr-1" />
													View Requests
												</>
											)}
										</Button>
										<Button variant="outline" size="sm">
											<ExternalLink className="w-3 h-3 mr-1" />
											View on Explorer
										</Button>
										{wallet.status === 'active' && wallet.bitcoinAddress && (
											<Button
												variant="outline"
												size="sm"
												onClick={() => setShowCreateTransaction(wallet.id)}
											>
												<Send className="w-3 h-3 mr-1" />
												Create Transaction
											</Button>
										)}
									</div>
								</CardContent>
							</Card>
						))
					)}
				</div>
			</div>

			{/* Transaction Creation Modal */}
			{showCreateTransaction &&
				(() => {
					const wallet = multisigWallets.find((w) => w.id === showCreateTransaction);
					return wallet && wallet.bitcoinAddress ? (
						<CreateTransaction
							multisigId={showCreateTransaction}
							bitcoinAddress={wallet.bitcoinAddress}
							onClose={() => setShowCreateTransaction(null)}
						/>
					) : null;
				})()}

			{/* Bitcoin Faucet Modal */}
			{showFaucet && <BitcoinFaucet onClose={() => setShowFaucet(false)} />}

			{/* Create Multisig Modal */}
			<CreateMultisigModal
				isOpen={showCreateModal}
				onClose={() => setShowCreateModal(false)}
				onSubmit={handleCreateMultisig}
				isCreating={isCreating}
			/>
		</div>
	);
}
