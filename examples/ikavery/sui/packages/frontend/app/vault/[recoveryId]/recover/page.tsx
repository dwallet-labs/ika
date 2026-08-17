'use client';

import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { Curve, publicKeyFromDWalletOutput } from '@ika.xyz/sdk';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	ArrowRight,
	CheckCircle2,
	ExternalLink,
	Loader2,
	Send,
	Sparkles,
	Wallet,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { Mono } from '@/app/setup/_parts';
import { ReplenishButton } from '@/components/vault/replenish-button';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { findMyEncryptedShareId } from '@/lib/encrypted-share-discovery';
import { env } from '@/lib/env';
import { ESTIMATE_PROPOSE } from '@/lib/gas-preflight';
import { buildIkaClient } from '@/lib/recovery-client';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { explorerObjectUrl } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import {
	appendSavedVault,
	loadActiveImporter,
	loadSavedVaults,
	type CachedImporter,
	type SavedVault,
} from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

// We import these lazily inside callbacks to avoid pulling Solana web3 into
// the initial bundle for users who never reach this page.
type SweepBundle = {
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
	// Raw bytes — fed straight to proposeRecovery later.
	sweepMessages: Uint8Array[];
};

const SOLANA_BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

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
	const { suiClient, session } = useRecoveryClient();
	const walletSign = dAppKit.signTransaction;
	const wallets = useWallets();
	const { wallet: currentWallet } = useWalletConnection();
	const queryClient = useQueryClient();

	const vault = useVaultQuery(recoveryId, {
		refetchInterval: false,
		staleTime: 8000,
	});

	// Resolve the source's Solana base58 address from the imported-key dWallet.
	// The dWallet's Active.public_output encodes the curve-specific public key;
	// for ED25519 it's the 32-byte raw key plus a one-byte BCS length prefix.
	const sourceAddress = useQuery({
		queryKey: ['recover.source', vault.data?.dwalletId ?? '_'],
		enabled: !!vault.data && !!suiClient,
		queryFn: async () => {
			if (!suiClient || !vault.data) return null;
			const ikaClient = buildIkaClient(suiClient);
			await ikaClient.initialize();
			const dWallet = await ikaClient.getDWalletInParticularState(vault.data.dwalletId, 'Active');
			const active = dWallet.state.Active;
			if (!active) throw new Error('dWallet not in Active state');
			const out = Uint8Array.from(active.public_output);
			const bcsKey = await publicKeyFromDWalletOutput(Curve.ED25519, out);
			// Strip the BCS length prefix (1 byte for 32-byte key).
			const raw = bcsKey.length === 33 ? bcsKey.slice(1) : bcsKey;
			const { PublicKey } = await import('@solana/web3.js');
			return new PublicKey(raw).toBase58();
		},
	});

	const [destination, setDestination] = React.useState('');
	const validDest = SOLANA_BASE58.test(destination.trim());
	const [bundle, setBundle] = React.useState<SweepBundle | null>(null);
	const [building, setBuilding] = React.useState(false);
	const [buildErr, setBuildErr] = React.useState<string | null>(null);

	const signerState = useSignerState(vault.data);

	// Look up *this device's* encrypted-share id for this vault. Set at import
	// time for the importer; will be set at enroll-acceptance for other devices
	// once Phase 5 lands. Without it, propose can't decrypt the share locally.
	const [savedVault, setSavedVault] = React.useState<SavedVault | null>(null);
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	const [shareLookup, setShareLookup] = React.useState<'idle' | 'searching' | 'missing'>('idle');
	React.useEffect(() => {
		void loadSavedVaults().then((vs) => {
			const match = vs.find((v) => v.recoveryId === recoveryId) ?? null;
			setSavedVault(match);
		});
		void loadActiveImporter().then(setCachedImporter);
	}, [recoveryId]);

	// Backfill the share id from chain when storage doesn't have it (vaults
	// imported before we started persisting it). One-shot per page mount.
	React.useEffect(() => {
		if (!suiClient || !vault.data || !cachedImporter) return;
		if (savedVault?.myEncryptedUserShareId) return;
		if (shareLookup !== 'idle') return;
		setShareLookup('searching');
		void (async () => {
			try {
				const found = await findMyEncryptedShareId(
					suiClient,
					vault.data?.dwalletId,
					cachedImporter.encryptionAddress,
				);
				if (!found) {
					setShareLookup('missing');
					return;
				}
				const merged: SavedVault = {
					recoveryId,
					dwalletId: vault.data?.dwalletId,
					threshold: vault.data?.threshold,
					totalMembers: vault.data?.members.length,
					createdAt: savedVault?.createdAt ?? Date.now(),
					myEncryptedUserShareId: found,
				};
				await appendSavedVault(merged);
				setSavedVault(merged);
				setShareLookup('idle');
			} catch {
				setShareLookup('missing');
			}
		})();
	}, [suiClient, vault.data, cachedImporter, savedVault, shareLookup, recoveryId]);

	const [proposeState, setProposeState] = React.useState<
		| { stage: 'idle' }
		| { stage: 'submitting'; phase: string }
		| { stage: 'done'; proposalId: string; digest: string }
		| { stage: 'error'; message: string }
	>({ stage: 'idle' });

	async function handlePropose() {
		if (!session || !suiClient || !vault.data || !bundle) return;
		if (!signerState.state.ready || !signerState.state.active || !signerState.state.gasPayer) {
			setProposeState({
				stage: 'error',
				message: 'Pick a signer and connect a wallet first.',
			});
			return;
		}

		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;

		setProposeState({ stage: 'submitting', phase: 'Awaiting wallet…' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			const result = await session.runProposeRecovery({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				sweepMessages: bundle.sweepMessages,
				authIdentity: signerOptionToIdentity(active),
			});
			setProposeState({ stage: 'submitting', phase: 'Recording proposal…' });
			await queryClient.invalidateQueries({ queryKey: ['vault', recoveryId] });
			setProposeState({ stage: 'submitting', phase: 'Opening proposal…' });
			router.push(`/vault/${recoveryId}/proposal/${result.proposalId}`);
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setProposeState({ stage: 'error', message });
		}
	}

	async function handleBuild() {
		if (!sourceAddress.data || !validDest) return;
		setBuilding(true);
		setBuildErr(null);
		setBundle(null);
		try {
			const [solana, splToken, core] = await Promise.all([
				import('@solana/web3.js'),
				import('@solana/spl-token'),
				import('@fesal-packages/ikavery-core'),
			]);
			const { Connection, PublicKey } = solana;
			const { TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID } = splToken;
			const { buildSweepBundle, SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT, previewMessageBytes } = core;
			const conn = new Connection(env.solanaRpc, 'confirmed');
			const sourcePk = new PublicKey(sourceAddress.data);
			const destPk = new PublicKey(destination.trim());
			const lamports = BigInt(await conn.getBalance(sourcePk, 'confirmed'));

			const tokenAccounts: Array<{
				mint: import('@solana/web3.js').PublicKey;
				tokenAccount: import('@solana/web3.js').PublicKey;
				amount: bigint;
				decimals: number;
				programId: import('@solana/web3.js').PublicKey;
			}> = [];
			for (const programId of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
				const res = await conn.getParsedTokenAccountsByOwner(sourcePk, {
					programId,
				});
				for (const { pubkey, account } of res.value) {
					const info = (
						account.data as {
							parsed: {
								info: {
									mint: string;
									tokenAmount: { amount: string; decimals: number };
								};
							};
						}
					).parsed.info;
					const amount = BigInt(info.tokenAmount.amount);
					if (amount === 0n) continue;
					tokenAccounts.push({
						mint: new PublicKey(info.mint),
						tokenAccount: pubkey,
						amount,
						decimals: info.tokenAmount.decimals,
						programId,
					});
				}
			}

			const { blockhash } = await conn.getLatestBlockhash('confirmed');
			const feeReserve =
				SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + BigInt(Math.max(1, tokenAccounts.length)) * 5_000n;
			const sweepMessages = buildSweepBundle({
				source: sourcePk,
				destination: destPk,
				solBalance: lamports,
				feeReserveLamports: feeReserve,
				tokenAccounts,
				recentBlockhash: blockhash,
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
					// create-ata / close-account / compute-budget are mechanical chrome
					// around the actual transfer — don't surface them to the user.
				}
				return { messageByteLength: t.messageByteLength, actions };
			});
			setBundle({
				source: sourceAddress.data,
				destination: destination.trim(),
				solBalance: lamports,
				feeReserveLamports: feeReserve,
				txCount: preview.txCount,
				totalLamports: preview.totalLamportsTransferred,
				totalSpl: preview.totalSplTransferred,
				txs,
				sweepMessages,
			});
		} catch (e) {
			setBuildErr(e instanceof Error ? e.message : String(e));
		} finally {
			setBuilding(false);
		}
	}

	if (vault.isLoading || sourceAddress.isLoading) {
		return (
			<div className="py-24 flex flex-col items-center text-center gap-3">
				<Loader2 className="h-5 w-5 animate-spin text-clay" />
				<span className="smallcaps text-text-2">Reading vault…</span>
			</div>
		);
	}

	if (vault.error) {
		return (
			<div className="max-w-[640px] mx-auto py-12">
				<BackLink onClick={() => router.push(`/vault/${recoveryId}`)} />
				<Card tone="raised" className="px-6 py-7">
					<p className="text-[14px] text-text-2 leading-[1.55]">
						Couldn&apos;t open the vault.{' '}
						<span className="font-mono text-[12px] text-clay">
							{String(vault.error instanceof Error ? vault.error.message : vault.error)}
						</span>
					</p>
				</Card>
			</div>
		);
	}
	if (!vault.data || !sourceAddress.data) return null;

	return (
		<>
			<BackLink onClick={() => router.push(`/vault/${recoveryId}`)} />

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
					requires a quorum of {vault.data.threshold} approval
					{vault.data.threshold === 1 ? '' : 's'} from the roster.
				</p>
			</header>

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Source</span>
						<span className="smallcaps text-text-4">Solana · ed25519</span>
					</div>
					<div className="px-5 sm:px-8 py-5 flex flex-col gap-2">
						<Mono className="text-[13px] break-all">{sourceAddress.data}</Mono>
						<span className="smallcaps text-text-3">dWallet ID</span>
						<Mono className="text-[12px] break-all text-text-2">{vault.data.dwalletId}</Mono>
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
								hint="Each tx consumes one presign at execute time."
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
														(chrome only — no transfers)
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

			{/* Signer + gas-payer */}
			<div className="mt-4">
				<SignerGasPayerCard
					vault={vault.data}
					state={signerState.state}
					onPickSigner={signerState.pickSigner}
					onPickGas={signerState.pickGas}
					estimate={ESTIMATE_PROPOSE}
				/>
			</div>

			{/* Quorum + presign reality check */}
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
							Threshold {vault.data.threshold} of {vault.data.members.length}. Presign pool{' '}
							<span
								className={cn(
									'font-mono tabular',
									vault.data.presignCount < (bundle?.txCount ?? 1) ? 'text-clay' : 'text-text',
								)}
							>
								{vault.data.presignCount}
							</span>{' '}
							ready
							{bundle && bundle.txCount > vault.data.presignCount && (
								<span className="text-clay">
									{' '}
									— short {bundle.txCount - vault.data.presignCount} for this bundle.
								</span>
							)}
							.
						</p>
					</div>
				</div>
				<div className="sm:ml-auto flex-none">
					<ReplenishButton
						recoveryId={recoveryId}
						suggestedCount={Math.max(2, (bundle?.txCount ?? 1) + 1 - vault.data.presignCount)}
						compact={!bundle || bundle.txCount <= vault.data.presignCount}
					/>
				</div>
			</Card>

			{proposeState.stage === 'done' && (
				<Card
					tone="raised"
					className="mt-4 px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4 border-sage/40"
				>
					<div className="h-9 w-9 flex-none rounded border border-sage/40 bg-sage/10 flex items-center justify-center">
						<CheckCircle2 className="h-3.5 w-3.5 text-sage" />
					</div>
					<div className="flex-1 min-w-0">
						<div className="smallcaps text-sage">Proposal submitted</div>
						<p className="mt-1 text-[13.5px] text-text-2 leading-[1.55]">
							Proposal{' '}
							<span className="font-mono tabular text-text">#{proposeState.proposalId}</span> is on
							chain. Approvers can review and sign from another device.
						</p>
						<div className="mt-1 font-mono text-[10.5px] tabular text-text-4 break-all">
							{proposeState.digest}
						</div>
					</div>
					<a
						href={explorerObjectUrl(proposeState.digest)}
						target="_blank"
						rel="noopener noreferrer"
						className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
					>
						<ExternalLink className="h-3 w-3" />
						Explorer
					</a>
				</Card>
			)}

			{proposeState.stage === 'error' && (
				<Card tone="raised" className="mt-4 px-6 py-5 flex items-start gap-4">
					<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
					<div className="flex-1 text-[13.5px] text-text-2 leading-[1.55]">
						<div className="smallcaps text-clay">Couldn&apos;t submit</div>
						<p className="mt-1">{proposeState.message}</p>
					</div>
				</Card>
			)}

			{/* Footer */}
			{(() => {
				const blocker = !signerState.state.ready
					? 'Pick a signer and connect a gas wallet.'
					: !bundle
						? 'Build the sweep bundle first.'
						: vault.data.presignCount < bundle.txCount
							? `Replenish ${bundle.txCount - vault.data.presignCount} presign(s) before proposing.`
							: null;
				return blocker && proposeState.stage !== 'done' ? (
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
					{proposeState.stage === 'submitting' && (
						<Button
							variant="ghost"
							size="default"
							onClick={() =>
								setProposeState({
									stage: 'error',
									message: 'Cancelled. If a wallet popup is still open, dismiss it and retry.',
								})
							}
						>
							Cancel
						</Button>
					)}
					<Button
						variant="irreversible"
						size="lg"
						disabled={
							!signerState.state.ready ||
							!bundle ||
							proposeState.stage === 'submitting' ||
							proposeState.stage === 'done' ||
							vault.data.presignCount < (bundle?.txCount ?? 1)
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

function BackLink({ onClick }: { onClick: () => void }) {
	return (
		<button
			onClick={onClick}
			className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-8"
		>
			<ArrowLeft className="h-3 w-3" />
			Back to vault
		</button>
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
