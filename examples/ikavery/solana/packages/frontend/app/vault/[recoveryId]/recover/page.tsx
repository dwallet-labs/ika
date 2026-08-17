'use client';

import {
	buildSweepBundle,
	previewMessageBytes,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
	type SourceTokenAccount,
} from '@fesal-packages/ikavery-core';
import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { discoverTokenAccounts, MAX_MESSAGE_BYTES } from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import { useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	ArrowRight,
	CheckCircle2,
	Loader2,
	Send,
	Sparkles,
	Wallet,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { Mono } from '@/app/setup/_parts';
import { BackToVaultLink } from '@/components/vault/back-to-vault';
import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { SOLANA_RPC } from '@/lib/env';
import { proposeAndApprove } from '@/lib/recover';
import { loadDkgBundle, type DkgBundle, type SerializedTokenAccount } from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

const SOLANA_BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

interface SweepBundle {
	source: string;
	destination: string;
	solBalance: bigint;
	feeReserveLamports: bigint;
	txCount: number;
	totalLamports: bigint;
	totalSpl: Array<{
		mint: string;
		programId: string;
		amount: bigint;
		decimals: number;
	}>;
	txs: Array<{
		messageByteLength: number;
		actions: Array<
			| { kind: 'sol'; amount: bigint }
			| { kind: 'spl'; mint: string; amount: bigint; decimals: number }
		>;
	}>;
	/** Token accounts the sweep references — stashed for later rebuild. */
	tokenAccounts: SerializedTokenAccount[];
	/** Raw message bytes; fed straight to propose. */
	sweepMessages: Uint8Array[];
}

function shortMint(mint: string): string {
	return mint.length <= 12 ? mint : `${mint.slice(0, 6)}…${mint.slice(-4)}`;
}

function formatSplAmount(amount: bigint, decimals: number): string {
	if (decimals === 0) return amount.toString();
	const base = 10n ** BigInt(decimals);
	const whole = amount / base;
	const frac = amount % base;
	const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '');
	return fracStr.length === 0 ? whole.toString() : `${whole}.${fracStr}`;
}

export default function RecoverPage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const queryClient = useQueryClient();

	const vault = useVaultQuery(recoveryId);
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const [destination, setDestination] = React.useState('');
	const validDest = SOLANA_BASE58.test(destination.trim());
	const [bundle, setBundle] = React.useState<SweepBundle | null>(null);
	const [building, setBuilding] = React.useState(false);
	const [buildErr, setBuildErr] = React.useState<string | null>(null);

	const [bundleState, setBundleState] = React.useState<DkgBundle | null>(null);
	React.useEffect(() => {
		void loadDkgBundle(recoveryId).then(setBundleState);
	}, [recoveryId]);

	const [proposeState, setProposeState] = React.useState<
		{ stage: 'idle' } | { stage: 'submitting'; phase: string } | { stage: 'error'; message: string }
	>({ stage: 'idle' });

	const signer = useSignerState(vault.data ? { members: vault.data.account.members } : null);
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const isMember = voter !== null;

	async function handleBuild() {
		if (!vault.data || !validDest) return;
		setBuilding(true);
		setBuildErr(null);
		setBundle(null);
		try {
			const sourcePk = vault.data.dwalletPubkey;
			const destPk = new PublicKey(destination.trim());
			const lamports = BigInt(await connection.getBalance(sourcePk, 'confirmed'));

			// Discover SPL holdings on the dWallet across both Token and
			// Token-2022. Each non-empty balance becomes a CreateIdempotentAta +
			// TransferChecked + CloseAccount triplet in the sweep bundle.
			const discovered = await discoverTokenAccounts(connection, sourcePk);
			const tokenAccounts: SourceTokenAccount[] = discovered.map((d) => ({
				mint: d.mint,
				tokenAccount: d.tokenAccount,
				amount: d.amount,
				decimals: d.decimals,
				programId: d.programId,
			}));
			const { blockhash } = await connection.getLatestBlockhash('confirmed');
			const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT;
			const sweepMessages = buildSweepBundle({
				source: sourcePk,
				destination: destPk,
				solBalance: lamports,
				feeReserveLamports: feeReserve,
				tokenAccounts,
				recentBlockhash: blockhash,
				maxSerializedMessageBytes: MAX_MESSAGE_BYTES,
			});
			const preview = previewMessageBytes(sweepMessages);
			const txs = preview.txs.map((t) => {
				const actions: Array<
					| { kind: 'sol'; amount: bigint }
					| { kind: 'spl'; mint: string; amount: bigint; decimals: number }
				> = [];
				for (const ix of t.instructions) {
					if (ix.kind === 'system-transfer') {
						actions.push({ kind: 'sol', amount: ix.lamports });
					} else if (ix.kind === 'spl-transfer-checked') {
						actions.push({
							kind: 'spl',
							mint: ix.mint,
							amount: ix.amount,
							decimals: ix.decimals,
						});
					}
					// create-ata / close-account / compute-budget are mechanical
					// chrome; don't surface them.
				}
				return { messageByteLength: t.messageByteLength, actions };
			});

			const serializedTokenAccounts: SerializedTokenAccount[] = tokenAccounts.map((t) => ({
				mint: t.mint.toBase58(),
				tokenAccount: t.tokenAccount.toBase58(),
				amount: t.amount.toString(),
				decimals: t.decimals,
				programId: t.programId.toBase58(),
			}));
			setBundle({
				source: sourcePk.toBase58(),
				destination: destination.trim(),
				solBalance: lamports,
				feeReserveLamports: feeReserve,
				txCount: preview.txCount,
				totalLamports: preview.totalLamportsTransferred,
				totalSpl: preview.totalSplTransferred,
				txs,
				tokenAccounts: serializedTokenAccounts,
				sweepMessages,
			});
		} catch (e) {
			setBuildErr(e instanceof Error ? e.message : String(e));
		} finally {
			setBuilding(false);
		}
	}

	async function handlePropose() {
		if (!vault.data || !bundle || !bundleState || !gasPayer) return;
		if (!voter) {
			setProposeState({
				stage: 'error',
				message:
					"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			});
			return;
		}

		setProposeState({ stage: 'submitting', phase: 'Awaiting authorisation…' });
		try {
			const result = await proposeAndApprove({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.data.recovery,
				recoveryId: vault.data.account.recoveryId,
				threshold: vault.data.account.threshold,
				bundle: {
					source: vault.data.dwalletPubkey,
					destination: new PublicKey(bundle.destination),
					solBalanceLamports: bundle.solBalance,
					feeReserveLamports: bundle.feeReserveLamports,
					tokenAccounts: bundle.tokenAccounts,
					sweepMessages: bundle.sweepMessages,
				},
				dwalletPubkey: vault.data.dwalletPubkey,
				dwalletAccount: vault.data.dwalletAccount,
				expectedProposalIndex: vault.data.account.proposalCount,
				onProgress: (p) => {
					setProposeState({
						stage: 'submitting',
						phase:
							p === 'ensuring-alt'
								? 'Preparing lookup table…'
								: p === 'proposing'
									? 'Proposing recovery…'
									: p === 'approving'
										? 'Recording your approval…'
										: 'Working…',
					});
				},
			});
			setProposeState({ stage: 'submitting', phase: 'Opening proposal…' });
			await queryClient.invalidateQueries({
				queryKey: ['solana-vault', recoveryId],
			});
			router.push(`/vault/${recoveryId}/proposal/${result.proposalIndex}`);
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setProposeState({ stage: 'error', message });
		}
	}

	if (vault.isLoading) {
		return (
			<div className="py-24 flex flex-col items-center text-center gap-3">
				<Loader2 className="h-5 w-5 animate-spin text-clay" />
				<span className="smallcaps text-text-2">Reading vault…</span>
			</div>
		);
	}
	if (vault.error) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				message={String(vault.error instanceof Error ? vault.error.message : vault.error)}
			/>
		);
	}
	if (!vault.data) return null;

	return (
		<>
			<BackToVaultLink recoveryId={recoveryId} />

			<header className="mb-10">
				<span className="smallcaps text-clay">Recovery sweep</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[64px] leading-[0.98] tracking-[-0.025em] text-text">
					Move every lamport
					<br />
					<span className="italic text-text-2">to a destination.</span>
				</h1>
				<p className="mt-5 max-w-[640px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					The dWallet signs Solana transactions on the source key&apos;s behalf. We build the bundle
					here in the browser and show every instruction before anyone signs anything. Proposing
					requires a quorum of {vault.data.account.threshold} approval
					{vault.data.account.threshold === 1 ? '' : 's'} from the roster.
				</p>
			</header>

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Source</span>
						<span className="smallcaps text-text-4">Solana · ed25519</span>
					</div>
					<div className="px-5 sm:px-8 py-5 flex flex-col gap-2">
						<Mono className="text-[13px] break-all">{vault.data.dwalletPubkey.toBase58()}</Mono>
						<span className="smallcaps text-text-3">dWallet PDA</span>
						<Mono className="text-[12px] break-all text-text-2">
							{vault.data.dwalletAccount.toBase58()}
						</Mono>
					</div>

					<div className="px-5 sm:px-8 py-3 border-y border-border">
						<span className="smallcaps text-text-3">Destination</span>
					</div>
					<div className="px-5 sm:px-8 py-5">
						<input
							value={destination}
							onChange={(e) => setDestination(e.target.value)}
							placeholder="Solana base58 address"
							spellCheck={false}
							className="w-full px-3 h-10 bg-surface border border-border rounded-[var(--radius-input)] font-mono text-[13px] tabular text-text placeholder:text-text-4 focus:outline-none focus:border-clay focus:ring-1 focus:ring-clay/30"
						/>
						{destination && !validDest && (
							<p className="mt-2 smallcaps text-clay">
								Doesn&apos;t look like a Solana base58 address.
							</p>
						)}
						<Button
							variant="secondary"
							size="default"
							className="mt-4"
							disabled={!validDest || building}
							onClick={handleBuild}
						>
							{building ? (
								<>
									<Loader2 className="h-3.5 w-3.5 animate-spin" />
									Building bundle…
								</>
							) : (
								<>
									<Sparkles className="h-3.5 w-3.5" />
									Build sweep
								</>
							)}
						</Button>
						{buildErr && <p className="mt-3 text-[12.5px] text-clay leading-[1.5]">{buildErr}</p>}
					</div>
				</Card>

				<Card tone="raised" className="lg:col-span-5 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Preview</span>
						{bundle && (
							<span className="smallcaps text-sage inline-flex items-center gap-1">
								<CheckCircle2 className="h-3 w-3" />
								Ready
							</span>
						)}
					</div>
					{bundle ? (
						<div className="divide-y divide-border">
							<Stat
								label="Transactions"
								value={`${bundle.txCount}`}
								hint={
									bundle.txCount === 1
										? 'Single sweep tx under one proposal.'
										: "All txs sign under one proposal's bundle digest."
								}
							/>
							<Stat
								label="SOL transferred"
								value={`${(Number(bundle.totalLamports) / 1e9).toFixed(6)} SOL`}
								hint={`fee reserve: ${(Number(bundle.feeReserveLamports) / 1e9).toFixed(6)} SOL`}
							/>
							{bundle.totalSpl.length > 0 && (
								<Stat label="SPL transfers" value={`${bundle.totalSpl.length}`} />
							)}
							<div className="px-5 sm:px-8 py-4">
								<span className="smallcaps text-text-3">Per-tx breakdown</span>
								<ol className="mt-3 space-y-3.5">
									{bundle.txs.map((t, i) => (
										<li key={i} className="flex items-baseline gap-3">
											<span className="font-mono text-[10.5px] text-text-4 tabular w-6 pt-0.5">
												{String(i + 1).padStart(2, '0')}
											</span>
											<ul className="flex-1 space-y-1">
												{t.actions.length === 0 ? (
													<li className="text-[12.5px] text-text-4 italic">
														(chrome only, no transfers)
													</li>
												) : (
													t.actions.map((a, j) =>
														a.kind === 'sol' ? (
															<li key={j} className="text-[13px] text-text-2 leading-[1.5]">
																Sweep{' '}
																<span className="font-mono tabular text-text">
																	{(Number(a.amount) / 1e9).toFixed(6)}
																</span>{' '}
																<span className="text-text-3">SOL</span>
															</li>
														) : (
															<li key={j} className="text-[13px] text-text-2 leading-[1.5]">
																Sweep{' '}
																<span className="font-mono tabular text-text">
																	{formatSplAmount(a.amount, a.decimals)}
																</span>{' '}
																<span className="text-text-3">of</span>{' '}
																<span className="font-mono text-[11.5px] text-text" title={a.mint}>
																	{shortMint(a.mint)}
																</span>
															</li>
														),
													)
												)}
											</ul>
											<span className="font-mono text-[10.5px] text-text-4 tabular pt-0.5">
												{t.messageByteLength}B
											</span>
										</li>
									))}
								</ol>
							</div>
						</div>
					) : (
						<div className="px-5 sm:px-8 py-10 text-center">
							<div className="smallcaps text-text-3">
								Enter a destination and click Build sweep.
							</div>
						</div>
					)}
				</Card>
			</div>

			<div className="mt-4">
				<SignerGasPayerCard
					state={signer.state}
					onPickSigner={signer.pickSigner}
					onPickGas={signer.pickGas}
					rosterSize={vault.data.account.members.length}
				/>
			</div>

			<Card
				tone="raised"
				className="mt-4 px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4 overflow-visible"
			>
				<div className="flex items-start gap-4 flex-1 min-w-0">
					<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
						<Wallet className="h-3.5 w-3.5 text-text-3" />
					</div>
					<div className="flex-1 min-w-0">
						<div className="smallcaps text-text-3">Reality check</div>
						<p className="mt-1 text-[13.5px] text-text-2 leading-[1.55]">
							Threshold {vault.data.account.threshold} of {vault.data.account.members.length}.
							dWallet balance{' '}
							<span
								className={cn(
									'font-mono tabular',
									vault.data.dwalletBalance < 5_000_000 ? 'text-clay' : 'text-text',
								)}
							>
								{(vault.data.dwalletBalance / 1e9).toFixed(6)} SOL
							</span>
							{vault.data.dwalletBalance < 5_000_000 && (
								<span className="text-clay"> · top up before proposing.</span>
							)}
							.
						</p>
					</div>
				</div>
			</Card>

			{proposeState.stage === 'error' && (
				<Card tone="raised" className="mt-4 px-6 py-5 flex items-start gap-4">
					<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
					<div className="flex-1 text-[13.5px] text-text-2 leading-[1.55]">
						<div className="smallcaps text-clay">Couldn&apos;t submit</div>
						<p className="mt-1">{proposeState.message}</p>
					</div>
				</Card>
			)}

			{(() => {
				const blocker = !signer.state.ready
					? signer.state.options.length === 0
						? 'Pick a signer in the roster, or connect a wallet that is.'
						: 'Pick a wallet to pay gas.'
					: !bundleState
						? 'DKG bundle not on this device. Open from the device that ran setup.'
						: !bundle
							? 'Build the sweep bundle first.'
							: vault.data.dwalletBalance < 5_000_000
								? 'dWallet balance is too low to cover a sweep tx.'
								: null;
				return blocker ? (
					<div className="mt-4 flex items-start gap-2 text-[12.5px] text-text-3 leading-[1.55]">
						<AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-none text-clay" />
						<span>{blocker}</span>
					</div>
				) : null;
			})()}
			{proposeState.stage === 'submitting' && (
				<div className="mt-4 flex items-center gap-2 text-[12.5px] text-text-2">
					<Loader2 className="h-3.5 w-3.5 animate-spin text-clay" />
					<span>{proposeState.phase}</span>
				</div>
			)}
			<div className="mt-4 flex items-center justify-between gap-4 flex-wrap">
				<Button variant="ghost" size="default" onClick={() => router.push(`/vault/${recoveryId}`)}>
					<ArrowLeft className="h-3.5 w-3.5" /> Back to vault
				</Button>
				<div className="flex items-center gap-3">
					<Button
						variant="irreversible"
						size="lg"
						disabled={
							!signer.state.ready ||
							!isMember ||
							!bundle ||
							!bundleState ||
							proposeState.stage === 'submitting' ||
							vault.data.dwalletBalance < 5_000_000
						}
						onClick={handlePropose}
					>
						{proposeState.stage === 'submitting' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Submitting…
							</>
						) : (
							<>
								<Send className="h-4 w-4" />
								Propose recovery
								<ArrowRight className="h-4 w-4" />
							</>
						)}
					</Button>
				</div>
			</div>
		</>
	);
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
	return (
		<div className="px-5 sm:px-8 py-4 flex items-baseline justify-between gap-3">
			<div>
				<div className="smallcaps text-text-3">{label}</div>
				{hint && <div className="smallcaps text-text-4 mt-0.5">{hint}</div>}
			</div>
			<span className="font-mono text-[18px] tabular text-text">{value}</span>
		</div>
	);
}
