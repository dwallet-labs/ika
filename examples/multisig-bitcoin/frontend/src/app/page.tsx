'use client';

import { useCurrentAccount } from '@mysten/dapp-kit';
import { useQuery } from '@tanstack/react-query';
import * as bitcoin from 'bitcoinjs-lib';
import { useMemo, useState } from 'react';

import { useMultisigOwnership } from '../hooks/useMultisigData';
import { useMultisigFunctions } from '../hooks/useMultisigFunctions';
import type { MultisigBitcoinWallet, UTXO } from '../multisig/bitcoin';

export default function Home() {
	const account = useCurrentAccount();
	const { data: ownerships, isLoading, refetch, error, isError } = useMultisigOwnership();
	const {
		createMultisig,
		addPresignToMultisig,
		createTransactionRequest,
		voteOnRequest,
		executeMultisigRequest,
		broadcastApprovedTransaction,
		isKeysReady,
		isLoadingKeys,
	} = useMultisigFunctions();

	const [membersInput, setMembersInput] = useState('');
	const [approvalThreshold, setApprovalThreshold] = useState<number>(2);
	const [rejectionThreshold, setRejectionThreshold] = useState<number>(1);
	const [expirationDuration, setExpirationDuration] = useState<number>(3600 * 24 * 7);

	const members = useMemo(
		() =>
			membersInput
				.split(',')
				.map((m) => m.trim())
				.filter(Boolean),
		[membersInput],
	);

	return (
		<div className="flex flex-col gap-8">
			<section className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
				<div className="flex flex-col gap-2">
					<h2 className="text-base font-semibold tracking-tight">Create Multisig</h2>
					<p className="text-sm text-zinc-500 dark:text-zinc-400">
						Define members and thresholds, then create a new Bitcoin multisig controlled on Sui.
					</p>
				</div>
				<div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
					<label className="flex flex-col gap-1">
						<span className="text-xs text-zinc-500">Members (comma-separated Sui addresses)</span>
						<input
							className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
							placeholder="0xabc..., 0xdef..., ..."
							value={membersInput}
							onChange={(e) => setMembersInput(e.target.value)}
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-xs text-zinc-500">Approval threshold</span>
						<input
							type="number"
							min={1}
							className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
							value={approvalThreshold}
							onChange={(e) => setApprovalThreshold(Number(e.target.value))}
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-xs text-zinc-500">Rejection threshold</span>
						<input
							type="number"
							min={0}
							className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
							value={rejectionThreshold}
							onChange={(e) => setRejectionThreshold(Number(e.target.value))}
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-xs text-zinc-500">Expiration (seconds)</span>
						<input
							type="number"
							min={60}
							className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
							value={expirationDuration}
							onChange={(e) => setExpirationDuration(Number(e.target.value))}
						/>
					</label>
				</div>
				<div className="mt-4">
					{isLoadingKeys && (
						<p className="mb-2 text-xs text-zinc-500 dark:text-zinc-400">
							Initializing encryption keys...
						</p>
					)}
					<button
						disabled={!account || members.length === 0 || !isKeysReady}
						className="inline-flex items-center justify-center rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:bg-zinc-300 dark:bg-zinc-100 dark:text-black dark:hover:bg-zinc-200 dark:disabled:bg-zinc-700"
						onClick={async () => {
							if (!isKeysReady) {
								return;
							}
							await createMultisig({
								members,
								approvalThreshold,
								rejectionThreshold,
								expirationDuration,
							});
							await refetch();
							setMembersInput('');
						}}
					>
						Create multisig
					</button>
				</div>
				<section className="mt-8 flex flex-col gap-4">
					<div className="flex items-center justify-between">
						<h2 className="text-base font-semibold tracking-tight">Your Multisigs</h2>
						<button
							onClick={() => refetch()}
							className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs text-zinc-700 transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
						>
							Refresh
						</button>
					</div>
					{!account && (
						<p className="text-sm text-zinc-500 dark:text-zinc-400">
							Connect your wallet to view and manage multisigs.
						</p>
					)}
					{account && isLoading && (
						<p className="text-sm text-zinc-500 dark:text-zinc-400">Loading multisigs…</p>
					)}
					{account && ownerships && ownerships.length === 0 && !isError && (
						<p className="text-sm text-zinc-500 dark:text-zinc-400">No multisigs found.</p>
					)}
					{isError && error && (
						<p className="text-sm text-zinc-500 dark:text-zinc-400">
							There was an error: <code className="text-xs">{error.message}</code>
						</p>
					)}
					<div className="grid grid-cols-1 gap-4">
						{ownerships?.map((o) => (
							<MultisigCard
								key={o.id}
								ownershipId={o.id}
								multisigId={o.multisigId}
								wallet={o.class}
								multisig={{
									approval_threshold:
										typeof o.multisig.approval_threshold === 'string'
											? Number(o.multisig.approval_threshold)
											: Number(o.multisig.approval_threshold),
									rejection_threshold:
										typeof o.multisig.rejection_threshold === 'string'
											? Number(o.multisig.rejection_threshold)
											: Number(o.multisig.rejection_threshold),
								}}
								requests={o.requests}
								onAfterAction={refetch}
								onExecute={async (requestId) => {
									await executeMultisigRequest({ multisig: o.class, requestId });
									await refetch();
								}}
								onBroadcast={async (requestId) => {
									await broadcastApprovedTransaction({ multisig: o.class, requestId });
									await refetch();
								}}
								onVote={async (requestId, vote) => {
									await voteOnRequest({ multisig: o.class, requestId, vote });
									await refetch();
								}}
								onAddPresign={async () => {
									await addPresignToMultisig({ multisig: o.class });
									await refetch();
								}}
								onCreateTx={async (params) => {
									await createTransactionRequest({
										multisig: o.class,
										toAddress: params.toAddress,
										amount: params.amount,
										feeRate: params.feeRate,
										utxo: params.utxo,
									});
									await refetch();
								}}
							/>
						))}
					</div>
				</section>
			</section>
		</div>
	);
}

function MultisigCard(props: {
	ownershipId: string;
	multisigId: string;
	wallet: MultisigBitcoinWallet;
	multisig: {
		approval_threshold: bigint | number;
		rejection_threshold: bigint | number;
	};
	requests: Array<{
		requestId: number;
		voted?: boolean;
		userVote?: boolean;
		request_type?: unknown;
		approvers_count?: bigint | number | string;
		rejecters_count?: bigint | number | string;
		status?: unknown;
	}>;
	onAfterAction: () => Promise<any> | void;
	onExecute: (requestId: number) => Promise<any>;
	onBroadcast: (requestId: number) => Promise<any>;
	onVote: (requestId: number, vote: boolean) => Promise<any>;
	onAddPresign: () => Promise<any>;
	onCreateTx: (params: {
		toAddress: string;
		amount: bigint;
		feeRate: number;
		utxo: UTXO;
	}) => Promise<any>;
}) {
	const { wallet } = props;
	const [isActiveExpanded, setIsActiveExpanded] = useState(true);
	const [isApprovedExpanded, setIsApprovedExpanded] = useState(true);
	const [isRejectedExpanded, setIsRejectedExpanded] = useState(false);

	const {
		data: balance,
		isLoading: isLoadingBalance,
		refetch: refetchBalance,
	} = useQuery({
		queryKey: ['btc-balance', wallet.getAddress()],
		queryFn: async () => wallet.getBalance(),
	});

	const [showTxForm, setShowTxForm] = useState(false);
	const [toAddress, setToAddress] = useState('');
	const [amountSats, setAmountSats] = useState<string>('');
	const [feeRate, setFeeRate] = useState<number>(10);

	const {
		data: utxos,
		isLoading: isLoadingUtxos,
		refetch: refetchUtxos,
	} = useQuery({
		enabled: showTxForm,
		queryKey: ['btc-utxos', wallet.getAddress()],
		queryFn: async () => wallet.getUTXOs(),
	});

	const selectedUtxo = useMemo(() => {
		if (!utxos || !amountSats) return null;
		const amount = BigInt(amountSats || '0');
		return wallet.findSuitableUTXO(utxos, amount, feeRate);
	}, [utxos, amountSats, feeRate, wallet]);

	const [copied, setCopied] = useState(false);
	const btcAddress = wallet.getAddress();
	const isTestnet =
		btcAddress.startsWith('tb1') || btcAddress.startsWith('m') || btcAddress.startsWith('n');
	const btcExplorerUrl = isTestnet
		? `https://blockstream.info/testnet/address/${btcAddress}`
		: `https://blockstream.info/address/${btcAddress}`;

	const copyAddress = async () => {
		try {
			await navigator.clipboard.writeText(btcAddress);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch (err) {
			console.error('Failed to copy address:', err);
		}
	};

	return (
		<div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
			<div className="flex flex-wrap items-start justify-between gap-3">
				<div className="flex-1 min-w-0">
					<div className="text-sm text-zinc-500">Multisig</div>
					<div className="flex items-center gap-2 flex-wrap">
						<div className="font-mono text-sm">
							{shorten(props.multisigId)} • BTC {shorten(btcAddress, 8)}
						</div>
						<div className="flex items-center gap-1">
							<a
								href={btcExplorerUrl}
								target="_blank"
								rel="noopener noreferrer"
								className="inline-flex items-center rounded-md border border-zinc-300 bg-white px-2 py-1 text-xs transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
								title="View on Bitcoin Explorer"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									className="h-3 w-3"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
								>
									<path
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={2}
										d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
									/>
								</svg>
							</a>
							<button
								onClick={copyAddress}
								className="inline-flex items-center rounded-md border border-zinc-300 bg-white px-2 py-1 text-xs transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
								title="Copy Bitcoin address"
							>
								{copied ? (
									<svg
										xmlns="http://www.w3.org/2000/svg"
										className="h-3 w-3 text-green-600"
										fill="none"
										viewBox="0 0 24 24"
										stroke="currentColor"
									>
										<path
											strokeLinecap="round"
											strokeLinejoin="round"
											strokeWidth={2}
											d="M5 13l4 4L19 7"
										/>
									</svg>
								) : (
									<svg
										xmlns="http://www.w3.org/2000/svg"
										className="h-3 w-3"
										fill="none"
										viewBox="0 0 24 24"
										stroke="currentColor"
									>
										<path
											strokeLinecap="round"
											strokeLinejoin="round"
											strokeWidth={2}
											d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
										/>
									</svg>
								)}
							</button>
						</div>
					</div>
				</div>
				<div className="flex items-center gap-2">
					<button
						className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
						onClick={() => props.onAddPresign()}
					>
						Add presign
					</button>
					<button
						className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
						onClick={async () => {
							await refetchBalance();
						}}
					>
						{isLoadingBalance ? 'Balance…' : `Balance: ${balance ? Number(balance) : 0} sats`}
					</button>
					<button
						className="rounded-md bg-zinc-900 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-zinc-800 dark:bg-zinc-100 dark:text-black dark:hover:bg-zinc-200"
						onClick={() => setShowTxForm((v) => !v)}
					>
						{showTxForm ? 'Hide send' : 'Send BTC'}
					</button>
				</div>
			</div>

			{showTxForm && (
				<div className="mt-4 rounded-lg border border-zinc-200/60 p-4 dark:border-zinc-800/60">
					<div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
						<label className="flex flex-col gap-1 sm:col-span-2">
							<span className="text-xs text-zinc-500">Recipient (BTC address)</span>
							<input
								className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
								value={toAddress}
								onChange={(e) => setToAddress(e.target.value)}
								placeholder="tb1..."
							/>
						</label>
						<label className="flex flex-col gap-1">
							<span className="text-xs text-zinc-500">Amount (sats)</span>
							<input
								type="number"
								min={1}
								className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
								value={amountSats}
								onChange={(e) => setAmountSats(e.target.value)}
								placeholder="10000"
							/>
						</label>
						<label className="flex flex-col gap-1">
							<span className="text-xs text-zinc-500">Fee rate (sat/vB)</span>
							<input
								type="number"
								min={1}
								className="rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm outline-none ring-0 transition focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-600"
								value={feeRate}
								onChange={(e) => setFeeRate(Number(e.target.value))}
								placeholder="10"
							/>
						</label>
					</div>
					<div className="mt-3 flex items-center justify-between">
						<div className="text-xs text-zinc-500">
							{isLoadingUtxos ? 'Loading UTXOs…' : utxos ? `${utxos.length} UTXOs` : '—'}
						</div>
						<button
							className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs transition hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
							onClick={() => refetchUtxos()}
						>
							Load UTXOs
						</button>
					</div>
					{utxos && (
						<div className="mt-3 overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800">
							<table className="min-w-full text-left text-sm">
								<thead className="bg-zinc-50 text-xs text-zinc-500 dark:bg-zinc-950/60">
									<tr>
										<th className="px-3 py-2 font-medium">TXID</th>
										<th className="px-3 py-2 font-medium">Vout</th>
										<th className="px-3 py-2 font-medium">Value (sats)</th>
										<th className="px-3 py-2 font-medium">Select</th>
									</tr>
								</thead>
								<tbody>
									{utxos.map((u) => {
										const isSelected =
											selectedUtxo && u.txid === selectedUtxo.txid && u.vout === selectedUtxo.vout;
										return (
											<tr
												key={`${u.txid}:${u.vout}`}
												className="border-t border-zinc-200/60 dark:border-zinc-800/60"
											>
												<td className="px-3 py-2 font-mono">{shorten(u.txid)}</td>
												<td className="px-3 py-2">{u.vout}</td>
												<td className="px-3 py-2">{u.value}</td>
												<td className="px-3 py-2">
													<span
														className={`inline-flex rounded-full px-2 py-0.5 text-xs ${
															isSelected
																? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-black'
																: 'bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300'
														}`}
													>
														{isSelected ? 'Auto-selected' : 'Eligible?'}
													</span>
												</td>
											</tr>
										);
									})}
								</tbody>
							</table>
						</div>
					)}
					<div className="mt-3 flex items-center justify-end">
						<button
							disabled={!toAddress || !amountSats || !selectedUtxo}
							className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:bg-zinc-300 dark:bg-zinc-100 dark:text-black dark:hover:bg-zinc-200 dark:disabled:bg-zinc-700"
							onClick={async () => {
								if (!selectedUtxo) return;
								await props.onCreateTx({
									toAddress,
									amount: BigInt(amountSats),
									feeRate,
									utxo: selectedUtxo,
								});
								setShowTxForm(false);
								setToAddress('');
								setAmountSats('');
								await props.onAfterAction();
							}}
						>
							Create request
						</button>
					</div>
				</div>
			)}

			<div className="mt-4">
				<h3 className="mb-2 text-sm font-semibold tracking-tight">Requests</h3>
				{props.requests.length === 0 ? (
					<p className="text-sm text-zinc-500 dark:text-zinc-400">No requests yet.</p>
				) : (
					(() => {
						// Categorize requests by status
						const categorizedRequests = props.requests.reduce(
							(acc, r) => {
								const statusObj = r.status as any;
								const isPending =
									statusObj &&
									typeof statusObj === 'object' &&
									(statusObj.$kind === 'Pending' || ('Pending' in statusObj && statusObj.Pending));
								const isApproved =
									statusObj &&
									typeof statusObj === 'object' &&
									(statusObj.$kind === 'Approved' ||
										('Approved' in statusObj && statusObj.Approved));
								const isRejected =
									statusObj &&
									typeof statusObj === 'object' &&
									(statusObj.$kind === 'Rejected' ||
										('Rejected' in statusObj && statusObj.Rejected));

								if (isPending) {
									acc.active.push(r);
								} else if (isApproved) {
									acc.approved.push(r);
								} else if (isRejected) {
									acc.rejected.push(r);
								}

								return acc;
							},
							{
								active: [] as typeof props.requests,
								approved: [] as typeof props.requests,
								rejected: [] as typeof props.requests,
							},
						);

						// Sort each category by request number (highest first)
						const sortByRequestId = (
							a: (typeof props.requests)[0],
							b: (typeof props.requests)[0],
						) => Number(b.requestId) - Number(a.requestId);

						categorizedRequests.active.sort(sortByRequestId);
						categorizedRequests.approved.sort(sortByRequestId);
						categorizedRequests.rejected.sort(sortByRequestId);

						return (
							<div className="flex flex-col gap-4">
								{categorizedRequests.active.length > 0 && (
									<div className="flex flex-col gap-2">
										<button
											onClick={() => setIsActiveExpanded(!isActiveExpanded)}
											className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-zinc-500 transition hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												className={`h-4 w-4 transition-transform ${isActiveExpanded ? 'rotate-90' : ''}`}
												fill="none"
												viewBox="0 0 24 24"
												stroke="currentColor"
											>
												<path
													strokeLinecap="round"
													strokeLinejoin="round"
													strokeWidth={2}
													d="M9 5l7 7-7 7"
												/>
											</svg>
											<span>Active ({categorizedRequests.active.length})</span>
										</button>
										{isActiveExpanded && (
											<div className="flex flex-col gap-2">
												{categorizedRequests.active.map((r) => {
													const requestId = Number(r.requestId);
													const approversCount =
														typeof r.approvers_count === 'string'
															? Number(r.approvers_count)
															: Number(r.approvers_count ?? 0);
													const rejectersCount =
														typeof r.rejecters_count === 'string'
															? Number(r.rejecters_count)
															: Number(r.rejecters_count ?? 0);
													const approvalThreshold = Number(props.multisig.approval_threshold);
													const rejectionThreshold = Number(props.multisig.rejection_threshold);

													// Check if status is Pending
													const statusObj = r.status as any;
													const isPending =
														statusObj &&
														typeof statusObj === 'object' &&
														(statusObj.$kind === 'Pending' ||
															('Pending' in statusObj && statusObj.Pending));
													const isApproved =
														statusObj &&
														typeof statusObj === 'object' &&
														(statusObj.$kind === 'Approved' ||
															('Approved' in statusObj && statusObj.Approved));
													const isRejected =
														statusObj &&
														typeof statusObj === 'object' &&
														(statusObj.$kind === 'Rejected' ||
															('Rejected' in statusObj && statusObj.Rejected));

													const canExecute =
														approversCount >= approvalThreshold &&
														isPending &&
														!isApproved &&
														!isRejected;
													const canVote = isPending && !r.voted;

													// Parse transaction details from PSBT
													const getTransactionDetails = () => {
														if (!r.request_type) return null;
														const reqType = r.request_type as any;

														if (reqType.Transaction && Array.isArray(reqType.Transaction)) {
															try {
																// Transaction is a tuple of [sighash, message_centralized_signature, psbt]
																const psbtData = reqType.Transaction[2];
																if (!psbtData) return null;

																// Convert to Buffer/Uint8Array
																const psbtBytes =
																	psbtData instanceof Uint8Array
																		? Buffer.from(psbtData)
																		: Buffer.from(psbtData);

																// Parse PSBT
																const psbt = bitcoin.Psbt.fromBuffer(psbtBytes);

																// Extract outputs (recipients)
																const network =
																	wallet.getNetwork() === 'testnet'
																		? bitcoin.networks.testnet
																		: bitcoin.networks.bitcoin;
																const outputs = psbt.txOutputs.map((output, index) => {
																	try {
																		const address = bitcoin.address.fromOutputScript(
																			output.script,
																			network,
																		);
																		return {
																			address,
																			amount: output.value,
																			isChange: address === wallet.getAddress(),
																		};
																	} catch {
																		return null;
																	}
																});

																// Filter out change outputs and get recipient(s)
																const recipients = outputs.filter(
																	(o): o is NonNullable<typeof o> => o !== null && !o.isChange,
																);
																const changeOutput = outputs.find(
																	(o): o is NonNullable<typeof o> => o !== null && o.isChange,
																);

																// Calculate total amount being sent (excluding change)
																const totalAmount = recipients.reduce(
																	(sum, o) => sum + o.amount,
																	BigInt(0),
																);

																return {
																	recipients,
																	changeOutput,
																	totalAmount,
																	inputCount: psbt.inputCount,
																	outputCount: psbt.txOutputs.length,
																};
															} catch (error) {
																console.error('Failed to parse PSBT:', error);
																return null;
															}
														}
														return null;
													};

													// Parse request type to show details
													const getRequestDescription = () => {
														if (!r.request_type) return 'Unknown request';
														const reqType = r.request_type as any;

														if (reqType.Transaction) {
															const txDetails = getTransactionDetails();
															if (txDetails && txDetails.recipients.length > 0) {
																const recipientList = txDetails.recipients
																	.map((r) => `${shorten(r.address, 8)} (${Number(r.amount)} sats)`)
																	.join(', ');
																return `Send ${Number(txDetails.totalAmount)} sats to ${recipientList}`;
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
															return `Change Expiration Duration: ${reqType.ChangeExpirationDuration}ms`;
														}
														return 'Unknown request type';
													};

													const transactionDetails = getTransactionDetails();

													// Check if this is a transaction request that can be broadcast
													const isTransactionRequest =
														r.request_type &&
														typeof r.request_type === 'object' &&
														'Transaction' in r.request_type;

													return (
														<div
															key={requestId}
															className="flex flex-col gap-2 rounded-lg border border-zinc-200/60 bg-zinc-50 px-3 py-2 text-sm dark:border-zinc-800/60 dark:bg-zinc-950/40"
														>
															<div className="flex flex-wrap items-start justify-between gap-3">
																<div className="flex flex-col gap-1 flex-1 min-w-0">
																	<div className="flex items-center gap-3 flex-wrap">
																		<span className="font-mono text-xs font-semibold">
																			#{requestId}
																		</span>
																		<span className="text-xs text-zinc-700 dark:text-zinc-300">
																			{getRequestDescription()}
																		</span>
																	</div>
																	{transactionDetails &&
																		transactionDetails.recipients.length > 0 && (
																			<div className="mt-1 flex flex-col gap-1 text-xs text-zinc-500">
																				{transactionDetails.recipients.map((recipient, idx) => (
																					<div key={idx} className="flex items-center gap-2">
																						<span>To:</span>
																						<span className="font-mono">
																							{shorten(recipient.address, 10)}
																						</span>
																						<span>•</span>
																						<span className="font-medium">
																							{Number(recipient.amount).toLocaleString()} sats
																						</span>
																					</div>
																				))}
																				{transactionDetails.changeOutput && (
																					<div className="flex items-center gap-2 text-zinc-400">
																						<span>Change:</span>
																						<span className="font-mono">
																							{shorten(transactionDetails.changeOutput.address, 10)}
																						</span>
																						<span>•</span>
																						<span>
																							{Number(
																								transactionDetails.changeOutput.amount,
																							).toLocaleString()}{' '}
																							sats
																						</span>
																					</div>
																				)}
																			</div>
																		)}
																	<div className="flex items-center gap-4 text-xs text-zinc-500 mt-1">
																		<span>
																			Approvals: {approversCount} / {approvalThreshold}
																		</span>
																		<span>
																			Rejections: {rejectersCount} / {rejectionThreshold}
																		</span>
																		<span>
																			{isApproved
																				? 'Approved'
																				: isRejected
																					? 'Rejected'
																					: r.voted
																						? r.userVote === undefined
																							? 'You voted'
																							: r.userVote == true
																								? 'You approved'
																								: 'You rejected'
																						: 'Not voted'}
																		</span>
																	</div>
																</div>
																<div className="flex items-center gap-2">
																	{isPending && (
																		<>
																			<button
																				disabled={!canVote}
																				className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs transition hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
																				onClick={() => props.onVote(requestId, true)}
																			>
																				Approve
																			</button>
																			<button
																				disabled={!canVote}
																				className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs transition hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
																				onClick={() => props.onVote(requestId, false)}
																			>
																				Reject
																			</button>
																			<button
																				disabled={!canExecute}
																				className="rounded-md bg-zinc-900 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:bg-zinc-300 dark:bg-zinc-100 dark:text-black dark:hover:bg-zinc-200 dark:disabled:bg-zinc-700"
																				onClick={() => props.onExecute(requestId)}
																			>
																				Execute
																			</button>
																		</>
																	)}
																	{isApproved && isTransactionRequest ? (
																		<button
																			className="rounded-md bg-green-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-green-700 dark:bg-green-500 dark:hover:bg-green-600"
																			onClick={() => {
																				void props.onBroadcast(requestId);
																			}}
																		>
																			Broadcast
																		</button>
																	) : null}
																</div>
															</div>
														</div>
													);
												})}
											</div>
										)}
									</div>
								)}
								{categorizedRequests.approved.length > 0 && (
									<div className="flex flex-col gap-2">
										<button
											onClick={() => setIsApprovedExpanded(!isApprovedExpanded)}
											className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-zinc-500 transition hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												className={`h-4 w-4 transition-transform ${isApprovedExpanded ? 'rotate-90' : ''}`}
												fill="none"
												viewBox="0 0 24 24"
												stroke="currentColor"
											>
												<path
													strokeLinecap="round"
													strokeLinejoin="round"
													strokeWidth={2}
													d="M9 5l7 7-7 7"
												/>
											</svg>
											<span>Approved ({categorizedRequests.approved.length})</span>
										</button>
										{isApprovedExpanded && (
											<div className="flex flex-col gap-2">
												{categorizedRequests.approved.map((r) => {
													const requestId = Number(r.requestId);
													const approversCount =
														typeof r.approvers_count === 'string'
															? Number(r.approvers_count)
															: Number(r.approvers_count ?? 0);
													const rejectersCount =
														typeof r.rejecters_count === 'string'
															? Number(r.rejecters_count)
															: Number(r.rejecters_count ?? 0);
													const approvalThreshold = Number(props.multisig.approval_threshold);
													const rejectionThreshold = Number(props.multisig.rejection_threshold);

													const statusObj = r.status as any;
													const isApproved =
														statusObj &&
														typeof statusObj === 'object' &&
														(statusObj.$kind === 'Approved' ||
															('Approved' in statusObj && statusObj.Approved));

													// Parse transaction details from PSBT
													const getTransactionDetails = () => {
														if (!r.request_type) return null;
														const reqType = r.request_type as any;

														if (reqType.Transaction && Array.isArray(reqType.Transaction)) {
															try {
																const psbtData = reqType.Transaction[2];
																if (!psbtData) return null;

																const psbtBytes =
																	psbtData instanceof Uint8Array
																		? Buffer.from(psbtData)
																		: Buffer.from(psbtData);

																const psbt = bitcoin.Psbt.fromBuffer(psbtBytes);

																const network =
																	wallet.getNetwork() === 'testnet'
																		? bitcoin.networks.testnet
																		: bitcoin.networks.bitcoin;
																const outputs = psbt.txOutputs.map((output, index) => {
																	try {
																		const address = bitcoin.address.fromOutputScript(
																			output.script,
																			network,
																		);
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

																const totalAmount = recipients.reduce(
																	(sum, o) => sum + o.amount,
																	BigInt(0),
																);

																return {
																	recipients,
																	changeOutput,
																	totalAmount,
																	inputCount: psbt.inputCount,
																	outputCount: psbt.txOutputs.length,
																};
															} catch (error) {
																console.error('Failed to parse PSBT:', error);
																return null;
															}
														}
														return null;
													};

													// Parse request type to show details
													const getRequestDescription = () => {
														if (!r.request_type) return 'Unknown request';
														const reqType = r.request_type as any;

														if (reqType.Transaction) {
															const txDetails = getTransactionDetails();
															if (txDetails && txDetails.recipients.length > 0) {
																const recipientList = txDetails.recipients
																	.map((r) => `${shorten(r.address, 8)} (${Number(r.amount)} sats)`)
																	.join(', ');
																return `Send ${Number(txDetails.totalAmount)} sats to ${recipientList}`;
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
															return `Change Expiration Duration: ${reqType.ChangeExpirationDuration}ms`;
														}
														return 'Unknown request type';
													};

													const transactionDetails = getTransactionDetails();
													const isTransactionRequest =
														r.request_type &&
														typeof r.request_type === 'object' &&
														'Transaction' in r.request_type;

													return (
														<div
															key={requestId}
															className="flex flex-col gap-2 rounded-lg border border-green-200/60 bg-green-50/50 px-3 py-2 text-sm dark:border-green-800/60 dark:bg-green-950/20"
														>
															<div className="flex flex-wrap items-start justify-between gap-3">
																<div className="flex flex-col gap-1 flex-1 min-w-0">
																	<div className="flex items-center gap-3 flex-wrap">
																		<span className="font-mono text-xs font-semibold">
																			#{requestId}
																		</span>
																		<span className="text-xs text-zinc-700 dark:text-zinc-300">
																			{getRequestDescription()}
																		</span>
																	</div>
																	{transactionDetails &&
																		transactionDetails.recipients.length > 0 && (
																			<div className="mt-1 flex flex-col gap-1 text-xs text-zinc-500">
																				{transactionDetails.recipients.map((recipient, idx) => (
																					<div key={idx} className="flex items-center gap-2">
																						<span>To:</span>
																						<span className="font-mono">
																							{shorten(recipient.address, 10)}
																						</span>
																						<span>•</span>
																						<span className="font-medium">
																							{Number(recipient.amount).toLocaleString()} sats
																						</span>
																					</div>
																				))}
																				{transactionDetails.changeOutput && (
																					<div className="flex items-center gap-2 text-zinc-400">
																						<span>Change:</span>
																						<span className="font-mono">
																							{shorten(transactionDetails.changeOutput.address, 10)}
																						</span>
																						<span>•</span>
																						<span>
																							{Number(
																								transactionDetails.changeOutput.amount,
																							).toLocaleString()}{' '}
																							sats
																						</span>
																					</div>
																				)}
																			</div>
																		)}
																	<div className="flex items-center gap-4 text-xs text-zinc-500 mt-1">
																		<span>
																			Approvals: {approversCount} / {approvalThreshold}
																		</span>
																		<span>
																			Rejections: {rejectersCount} / {rejectionThreshold}
																		</span>
																		<span className="text-green-600 dark:text-green-400">
																			Approved
																		</span>
																	</div>
																</div>
																<div className="flex items-center gap-2">
																	{isTransactionRequest ? (
																		<button
																			className="rounded-md bg-green-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-green-700 dark:bg-green-500 dark:hover:bg-green-600"
																			onClick={() => {
																				void props.onBroadcast(requestId);
																			}}
																		>
																			Broadcast
																		</button>
																	) : null}
																</div>
															</div>
														</div>
													);
												})}
											</div>
										)}
									</div>
								)}
								{categorizedRequests.rejected.length > 0 && (
									<div className="flex flex-col gap-2">
										<button
											onClick={() => setIsRejectedExpanded(!isRejectedExpanded)}
											className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-zinc-500 transition hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												className={`h-4 w-4 transition-transform ${isRejectedExpanded ? 'rotate-90' : ''}`}
												fill="none"
												viewBox="0 0 24 24"
												stroke="currentColor"
											>
												<path
													strokeLinecap="round"
													strokeLinejoin="round"
													strokeWidth={2}
													d="M9 5l7 7-7 7"
												/>
											</svg>
											<span>Rejected ({categorizedRequests.rejected.length})</span>
										</button>
										{isRejectedExpanded && (
											<div className="flex flex-col gap-2">
												{categorizedRequests.rejected.map((r) => {
													const requestId = Number(r.requestId);
													const approversCount =
														typeof r.approvers_count === 'string'
															? Number(r.approvers_count)
															: Number(r.approvers_count ?? 0);
													const rejectersCount =
														typeof r.rejecters_count === 'string'
															? Number(r.rejecters_count)
															: Number(r.rejecters_count ?? 0);
													const approvalThreshold = Number(props.multisig.approval_threshold);
													const rejectionThreshold = Number(props.multisig.rejection_threshold);

													// Parse request type to show details
													const getRequestDescription = () => {
														if (!r.request_type) return 'Unknown request';
														const reqType = r.request_type as any;

														if (reqType.Transaction) {
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
															return `Change Expiration Duration: ${reqType.ChangeExpirationDuration}ms`;
														}
														return 'Unknown request type';
													};

													return (
														<div
															key={requestId}
															className="flex flex-col gap-2 rounded-lg border border-red-200/60 bg-red-50/50 px-3 py-2 text-sm dark:border-red-800/60 dark:bg-red-950/20"
														>
															<div className="flex flex-wrap items-start justify-between gap-3">
																<div className="flex flex-col gap-1 flex-1 min-w-0">
																	<div className="flex items-center gap-3 flex-wrap">
																		<span className="font-mono text-xs font-semibold">
																			#{requestId}
																		</span>
																		<span className="text-xs text-zinc-700 dark:text-zinc-300">
																			{getRequestDescription()}
																		</span>
																	</div>
																	<div className="flex items-center gap-4 text-xs text-zinc-500 mt-1">
																		<span>
																			Approvals: {approversCount} / {approvalThreshold}
																		</span>
																		<span>
																			Rejections: {rejectersCount} / {rejectionThreshold}
																		</span>
																		<span className="text-red-600 dark:text-red-400">Rejected</span>
																	</div>
																</div>
															</div>
														</div>
													);
												})}
											</div>
										)}
									</div>
								)}
							</div>
						);
					})()
				)}
			</div>
		</div>
	);
}

function shorten(v: string, n: number = 6): string {
	if (!v) return '';
	if (v.length <= n * 2) return v;
	return `${v.slice(0, n)}…${v.slice(-n)}`;
}
