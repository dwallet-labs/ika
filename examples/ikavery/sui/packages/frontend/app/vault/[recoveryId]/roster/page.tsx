'use client';

import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	ArrowRight,
	Fingerprint,
	Loader2,
	Minus,
	ShieldCheck,
	Trash2,
	UserMinus,
	Wallet,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { env } from '@/lib/env';
import { bytesToHex, renderMemberIdentity, schemeLabel } from '@/lib/format';
import { ESTIMATE_PROPOSE } from '@/lib/gas-preflight';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import type { Scheme } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import { useVaultQuery } from '@/lib/use-vault';

const MIN_THRESHOLD = 1;

type SubmitState =
	{ stage: 'idle' } | { stage: 'submitting' } | { stage: 'error'; message: string };

export default function ProposeRosterChangePage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const { suiClient, session } = useRecoveryClient();
	const wallets = useWallets();
	const { wallet: currentWallet } = useWalletConnection();
	const walletSign = dAppKit.signTransaction;
	const queryClient = useQueryClient();

	const vault = useVaultQuery(recoveryId, { refetchInterval: 30_000 });

	const signerState = useSignerState(vault.data);

	// Selection of members to remove (keyed by hex of canonical id bytes).
	const [removeIds, setRemoveIds] = React.useState<Set<string>>(new Set());
	// Threshold: null = keep current. We initialize from vault data once loaded.
	const [thresholdMode, setThresholdMode] = React.useState<'keep' | 'change'>('keep');
	const [thresholdInput, setThresholdInput] = React.useState<string>('');
	const [submitState, setSubmitState] = React.useState<SubmitState>({
		stage: 'idle',
	});

	const total = vault.data?.members.length ?? 0;
	const removalCount = removeIds.size;
	const postCount = total - removalCount;

	// Auto-clamp the input when post-count drops below it.
	React.useEffect(() => {
		if (thresholdMode !== 'change' || !thresholdInput) return;
		const t = Number(thresholdInput);
		if (Number.isNaN(t)) return;
		if (postCount > 0 && t > postCount) {
			setThresholdInput(String(postCount));
		}
	}, [postCount, thresholdInput, thresholdMode]);

	function toggleRemove(id: string) {
		setRemoveIds((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			return next;
		});
	}

	// Validation derived from the form.
	const validation = React.useMemo<{
		ok: boolean;
		error: string | null;
	}>(() => {
		if (!vault.data) return { ok: false, error: null };
		const noopChange =
			removalCount === 0 &&
			(thresholdMode === 'keep' ||
				thresholdInput === '' ||
				Number(thresholdInput) === vault.data.threshold);
		if (noopChange)
			return {
				ok: false,
				error: 'Pick at least one removal or a new threshold.',
			};

		if (postCount < MIN_THRESHOLD) {
			return {
				ok: false,
				error: `At least ${MIN_THRESHOLD} member must remain — you’re removing too many.`,
			};
		}

		if (thresholdMode === 'change') {
			if (thresholdInput === '')
				return {
					ok: false,
					error: 'Enter a new threshold or switch back to keep.',
				};
			const t = Number(thresholdInput);
			if (!Number.isFinite(t) || !Number.isInteger(t)) {
				return { ok: false, error: 'Threshold must be a whole number.' };
			}
			if (t < MIN_THRESHOLD || t > postCount) {
				return {
					ok: false,
					error: `Threshold must be between ${MIN_THRESHOLD} and ${postCount} after removals.`,
				};
			}
		} else {
			// keep — make sure current threshold still fits the post-roster size.
			if (vault.data.threshold > postCount) {
				return {
					ok: false,
					error: `Current threshold ${vault.data.threshold} would exceed the ${postCount} remaining member${postCount === 1 ? '' : 's'}. Pick a new threshold below.`,
				};
			}
		}
		return { ok: true, error: null };
	}, [vault.data, removalCount, postCount, thresholdMode, thresholdInput]);

	async function handleSubmit() {
		if (!session || !suiClient || !vault.data) return;
		if (!validation.ok) return;
		if (!signerState.state.ready || !signerState.state.active || !signerState.state.gasPayer) {
			setSubmitState({
				stage: 'error',
				message: 'Pick a signer and a gas payer first.',
			});
			return;
		}
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;

		const removalsBytes: Uint8Array[] = [];
		for (const m of vault.data.members) {
			const hex = bytesToHex(m.id);
			if (removeIds.has(hex)) removalsBytes.push(m.id);
		}

		const newThreshold: bigint | null =
			thresholdMode === 'change' && thresholdInput !== '' ? BigInt(thresholdInput) : null;

		setSubmitState({ stage: 'submitting' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});

			const result = await session.runProposeRosterChange({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				membersToRemove: removalsBytes,
				newThreshold,
				authIdentity: signerOptionToIdentity(active),
			});
			await queryClient.invalidateQueries({ queryKey: ['vault', recoveryId] });
			router.push(`/vault/${recoveryId}/roster/${result.rosterChangeId}`);
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setSubmitState({ stage: 'error', message });
		}
	}

	return (
		<div className="max-w-[860px] mx-auto py-10">
			<button
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<span className="smallcaps text-text-3">Roster change</span>
				<h1 className="mt-2 font-display text-[34px] sm:text-[40px] leading-[1.04] text-text">
					Edit members & threshold
				</h1>
				<p className="mt-3 text-[14px] text-text-2 leading-[1.6] max-w-[640px]">
					Drop members from the roster and/or change the approval threshold. Both apply atomically
					when the proposal executes — t-of-N approvals required, same as enrollment. Adding members
					goes through{' '}
					<button
						type="button"
						className="underline decoration-dotted underline-offset-2 hover:text-text"
						onClick={() => router.push(`/vault/${recoveryId}/enroll`)}
					>
						Add device
					</button>{' '}
					instead.
				</p>
			</header>

			{/* Members to remove */}
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Members</span>
					<span className="font-mono text-[12px] text-text-3 tabular">
						{removalCount > 0 ? `${removalCount} marked for removal` : `${total} total`}
					</span>
				</div>
				{!vault.data ? (
					<div className="px-5 sm:px-8 py-7 smallcaps text-text-3 inline-flex items-center gap-1.5">
						<Loader2 className="h-3 w-3 animate-spin" />
						Loading members…
					</div>
				) : (
					<ul className="divide-y divide-border">
						{vault.data.members.map((m) => {
							const hex = bytesToHex(m.id);
							const checked = removeIds.has(hex);
							return (
								<li
									key={hex}
									className={cn(
										'px-5 sm:px-8 py-3 flex items-start gap-3 transition-colors',
										checked && 'bg-clay/[0.04]',
									)}
								>
									<button
										type="button"
										onClick={() => toggleRemove(hex)}
										className={cn(
											'mt-0.5 h-5 w-5 flex-none rounded border transition-colors inline-flex items-center justify-center',
											checked
												? 'border-clay/70 bg-clay/15 text-clay'
												: 'border-border bg-surface-2 text-transparent hover:border-border-strong',
										)}
										aria-label={checked ? 'Unmark for removal' : 'Mark for removal'}
									>
										{checked && <Minus className="h-3 w-3" />}
									</button>
									<div className="flex-1 min-w-0">
										<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
											<SchemeIcon scheme={m.scheme} />
											{schemeLabel(m.scheme)}
										</div>
										<div className="mt-1 font-mono text-[12px] tabular text-text break-all">
											{renderMemberIdentity(m)}
										</div>
									</div>
								</li>
							);
						})}
					</ul>
				)}
			</Card>

			{/* Threshold */}
			<Card tone="raised" className="mt-4 p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Threshold</span>
					{vault.data && (
						<span className="font-mono text-[12px] text-text-3 tabular">
							currently {vault.data.threshold} of {total}
						</span>
					)}
				</div>
				<div className="px-5 sm:px-8 py-5 space-y-4">
					<div className="grid grid-cols-2 gap-2">
						<ThresholdTab
							active={thresholdMode === 'keep'}
							onClick={() => setThresholdMode('keep')}
							label="Keep current"
							hint={vault.data ? `t=${vault.data.threshold} stays the same` : 'no change'}
						/>
						<ThresholdTab
							active={thresholdMode === 'change'}
							onClick={() => setThresholdMode('change')}
							label="Change"
							hint={`Pick a value between ${MIN_THRESHOLD} and ${postCount || total}`}
						/>
					</div>

					{thresholdMode === 'change' && vault.data && (
						<div>
							<label className="smallcaps text-text-3 block mb-2">New threshold</label>
							<div className="flex items-center gap-3">
								<input
									type="number"
									inputMode="numeric"
									min={MIN_THRESHOLD}
									max={Math.max(MIN_THRESHOLD, postCount)}
									value={thresholdInput}
									onChange={(e) => setThresholdInput(e.target.value.replace(/[^0-9]/g, ''))}
									className="font-mono text-[14px] tabular bg-surface-2 border border-border rounded-md px-3 py-2 w-32 focus:outline-none focus:border-clay/60"
									placeholder={String(vault.data.threshold)}
								/>
								<span className="smallcaps text-text-3">of {postCount} after removals</span>
							</div>
							<p className="mt-2 text-[12px] text-text-3 leading-[1.55]">
								The proposal commits to this exact value. The current proposer still needs t-of-N
								approvals from the current roster — the new threshold only takes effect on execute.
							</p>
						</div>
					)}
				</div>
			</Card>

			{/* Summary preview */}
			{vault.data && (validation.ok || removalCount > 0 || thresholdMode === 'change') && (
				<Card tone="raised" className="mt-4 px-5 sm:px-8 py-4">
					<div className="smallcaps text-text-3 mb-2">After execute</div>
					<div className="flex items-baseline gap-3">
						<span className="font-display text-[40px] leading-[0.95] tabular text-text">
							{thresholdMode === 'change' && thresholdInput !== ''
								? thresholdInput
								: vault.data.threshold}
						</span>
						<span className="font-display italic text-text-3 text-[18px] tracking-tight">of</span>
						<span className="font-display text-[40px] leading-[0.95] tabular text-text-2">
							{postCount}
						</span>
						<span className="ml-auto smallcaps text-text-3 inline-flex items-center gap-1.5">
							<Trash2 className="h-3 w-3" />
							{removalCount} removed
						</span>
					</div>
				</Card>
			)}

			{/* Signer + gas-payer */}
			<div className="mt-4">
				{vault.data ? (
					<SignerGasPayerCard
						vault={vault.data}
						state={signerState.state}
						onPickSigner={signerState.pickSigner}
						onPickGas={signerState.pickGas}
						estimate={ESTIMATE_PROPOSE}
					/>
				) : (
					<Card tone="raised" className="px-6 py-6">
						<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
							<Loader2 className="h-3 w-3 animate-spin" />
							Loading vault…
						</span>
					</Card>
				)}
			</div>

			<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
				{validation.error && (
					<p className="flex-1 text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
						<AlertCircle className="h-3 w-3" />
						{validation.error}
					</p>
				)}
				{submitState.stage === 'error' && (
					<p className="flex-1 text-[12.5px] text-clay leading-[1.5]">{submitState.message}</p>
				)}
				<Button variant="ghost" size="default" onClick={() => router.push(`/vault/${recoveryId}`)}>
					Cancel
				</Button>
				<Button
					variant="primary"
					size="lg"
					disabled={
						!validation.ok || !signerState.state.ready || submitState.stage === 'submitting'
					}
					onClick={handleSubmit}
				>
					{submitState.stage === 'submitting' ? (
						<>
							<Loader2 className="h-4 w-4 animate-spin" />
							Proposing roster change…
						</>
					) : (
						<>
							<UserMinus className="h-4 w-4" />
							Propose roster change
							<ArrowRight className="h-4 w-4" />
						</>
					)}
				</Button>
			</div>
		</div>
	);
}

// ===== sub-components =====

function ThresholdTab({
	active,
	onClick,
	label,
	hint,
}: {
	active: boolean;
	onClick: () => void;
	label: string;
	hint: string;
}) {
	return (
		<button
			type="button"
			onClick={onClick}
			className={cn(
				'text-left px-4 py-3 rounded-md border transition-colors',
				active
					? 'border-clay/60 bg-clay/[0.06] text-text'
					: 'border-border bg-surface-2 text-text-3 hover:text-text hover:border-border-strong',
			)}
		>
			<div className="smallcaps">{label}</div>
			<div className="mt-1 text-[11.5px] text-text-3 leading-[1.4]">{hint}</div>
		</button>
	);
}

function SchemeIcon({ scheme }: { scheme: Scheme }) {
	if (scheme === 'webauthn') return <Fingerprint className="h-3 w-3" />;
	if (scheme === 'sender_address') return <ShieldCheck className="h-3 w-3" />;
	return <Wallet className="h-3 w-3" />;
}
