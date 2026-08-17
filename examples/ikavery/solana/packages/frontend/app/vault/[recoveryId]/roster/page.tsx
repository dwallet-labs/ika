'use client';

import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { memberIdBytes, SCHEME_SOLANA_ADDRESS } from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import { useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowRight,
	Loader2,
	Minus,
	ShieldCheck,
	Trash2,
	UserMinus,
	Wallet,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { BackToVaultLink } from '@/components/vault/back-to-vault';
import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { SOLANA_RPC } from '@/lib/env';
import { proposeAndApproveRoster } from '@/lib/roster';
import { useVaultQuery } from '@/lib/use-vault';

const MIN_THRESHOLD = 1;

type SubmitState =
	{ stage: 'idle' } | { stage: 'submitting'; phase: string } | { stage: 'error'; message: string };

export default function ProposeRosterChangePage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const queryClient = useQueryClient();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const vault = useVaultQuery(recoveryId);

	const [removeIdx, setRemoveIdx] = React.useState<Set<number>>(new Set());
	const [thresholdMode, setThresholdMode] = React.useState<'keep' | 'change'>('keep');
	const [thresholdInput, setThresholdInput] = React.useState<string>('');
	const [submitState, setSubmitState] = React.useState<SubmitState>({
		stage: 'idle',
	});

	const total = vault.data?.account.members.length ?? 0;
	const removalCount = removeIdx.size;
	const postCount = total - removalCount;

	React.useEffect(() => {
		if (thresholdMode !== 'change' || !thresholdInput) return;
		const t = Number(thresholdInput);
		if (Number.isNaN(t)) return;
		if (postCount > 0 && t > postCount) {
			setThresholdInput(String(postCount));
		}
	}, [postCount, thresholdInput, thresholdMode]);

	const signer = useSignerState(vault.data ? { members: vault.data.account.members } : null);
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const isMember = voter !== null;

	function toggleRemove(idx: number) {
		setRemoveIdx((prev) => {
			const next = new Set(prev);
			if (next.has(idx)) next.delete(idx);
			else next.add(idx);
			return next;
		});
	}

	const validation = React.useMemo<{
		ok: boolean;
		error: string | null;
	}>(() => {
		if (!vault.data) return { ok: false, error: null };
		const noopChange =
			removalCount === 0 &&
			(thresholdMode === 'keep' ||
				thresholdInput === '' ||
				Number(thresholdInput) === vault.data.account.threshold);
		if (noopChange) {
			return {
				ok: false,
				error: 'Pick at least one removal or a new threshold.',
			};
		}
		if (postCount < MIN_THRESHOLD) {
			return {
				ok: false,
				error: `At least ${MIN_THRESHOLD} member must remain; you're removing too many.`,
			};
		}
		if (thresholdMode === 'change') {
			if (thresholdInput === '') {
				return {
					ok: false,
					error: 'Enter a new threshold or switch back to keep.',
				};
			}
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
		} else if (vault.data.account.threshold > postCount) {
			return {
				ok: false,
				error: `Current threshold ${vault.data.account.threshold} would exceed the ${postCount} remaining member${postCount === 1 ? '' : 's'}. Pick a new threshold below.`,
			};
		}
		return { ok: true, error: null };
	}, [vault.data, removalCount, postCount, thresholdMode, thresholdInput]);

	async function handleSubmit() {
		if (!gasPayer || !vault.data) return;
		if (!validation.ok) return;
		if (!voter) {
			setSubmitState({
				stage: 'error',
				message:
					"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			});
			return;
		}
		const newThreshold =
			thresholdMode === 'change' && thresholdInput !== '' ? Number(thresholdInput) : null;
		const removalIndexes = Array.from(removeIdx).sort((a, b) => a - b);

		setSubmitState({ stage: 'submitting', phase: 'Awaiting authorisation…' });
		try {
			const result = await proposeAndApproveRoster({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.data.recovery,
				recoveryId: vault.data.account.recoveryId,
				dwalletPubkey: vault.data.dwalletPubkey,
				dwalletAccount: vault.data.dwalletAccount,
				currentMembers: vault.data.account.members,
				threshold: vault.data.account.threshold,
				expectedIndex: vault.data.account.rosterChangeCount,
				draft: {
					additions: [],
					removalIndexes,
					newThreshold,
					approverOnlyBitmap: 0,
				},
				onProgress: (p) =>
					setSubmitState({
						stage: 'submitting',
						phase:
							p === 'ensuring-alt'
								? 'Preparing lookup table…'
								: p === 'proposing'
									? 'Proposing roster change…'
									: p === 'approving'
										? 'Recording your approval…'
										: 'Working…',
					}),
			});
			setSubmitState({ stage: 'submitting', phase: 'Opening proposal…' });
			await queryClient.invalidateQueries({
				queryKey: ['solana-vault', recoveryId],
			});
			router.push(`/vault/${recoveryId}/roster/${result.rosterChangeIndex}`);
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setSubmitState({ stage: 'error', message });
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
	if (vault.error || !vault.data) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				message={String(vault.error instanceof Error ? vault.error.message : vault.error)}
			/>
		);
	}

	return (
		<div className="max-w-[860px] mx-auto py-10">
			<BackToVaultLink recoveryId={recoveryId} />

			<header className="mb-6">
				<span className="smallcaps text-text-3">Roster change</span>
				<h1 className="mt-2 font-display text-[34px] sm:text-[40px] leading-[1.04] text-text">
					Edit members & threshold
				</h1>
				<p className="mt-3 text-[14px] text-text-2 leading-[1.6] max-w-[640px]">
					Drop members from the roster and/or change the approval threshold. Both apply atomically
					when the proposal executes; t-of-N approvals required, same as enrollment. Adding members
					goes through{' '}
					<button
						type="button"
						className="underline decoration-dotted underline-offset-2 hover:text-text"
						onClick={() => router.push(`/vault/${recoveryId}/enroll`)}
					>
						Add member
					</button>{' '}
					instead.
				</p>
			</header>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Members</span>
					<span className="font-mono text-[12px] text-text-3 tabular">
						{removalCount > 0 ? `${removalCount} marked for removal` : `${total} total`}
					</span>
				</div>
				<ul className="divide-y divide-border">
					{vault.data.account.members.map((slot, idx) => {
						const checked = removeIdx.has(idx);
						return (
							<li
								key={idx}
								className={cn(
									'px-5 sm:px-8 py-3 flex items-start gap-3 transition-colors',
									checked && 'bg-clay/[0.04]',
								)}
							>
								<button
									type="button"
									onClick={() => toggleRemove(idx)}
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
										<SchemeIcon scheme={slot[0] ?? 0} />
										{schemeLabel(slot[0] ?? 0)}
									</div>
									<div className="mt-1 font-mono text-[12px] tabular text-text break-all">
										{slotDisplay(slot)}
									</div>
								</div>
							</li>
						);
					})}
				</ul>
			</Card>

			<Card tone="raised" className="mt-4 p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Threshold</span>
					<span className="font-mono text-[12px] text-text-3 tabular">
						currently {vault.data.account.threshold} of {total}
					</span>
				</div>
				<div className="px-5 sm:px-8 py-5 space-y-4">
					<div className="grid grid-cols-2 gap-2">
						<ThresholdTab
							active={thresholdMode === 'keep'}
							onClick={() => setThresholdMode('keep')}
							label="Keep current"
							hint={`t=${vault.data.account.threshold} stays the same`}
						/>
						<ThresholdTab
							active={thresholdMode === 'change'}
							onClick={() => setThresholdMode('change')}
							label="Change"
							hint={`Pick a value between ${MIN_THRESHOLD} and ${postCount || total}`}
						/>
					</div>
					{thresholdMode === 'change' && (
						<div>
							<label htmlFor="roster-threshold" className="smallcaps text-text-3 block mb-2">
								New threshold
							</label>
							<div className="flex items-center gap-3">
								<input
									id="roster-threshold"
									type="number"
									inputMode="numeric"
									min={MIN_THRESHOLD}
									max={Math.max(MIN_THRESHOLD, postCount)}
									value={thresholdInput}
									onChange={(e) => setThresholdInput(e.target.value.replace(/[^0-9]/g, ''))}
									className="font-mono text-[14px] tabular bg-surface-2 border border-border rounded-md px-3 py-2 w-32 focus:outline-none focus:border-clay/60"
									placeholder={String(vault.data.account.threshold)}
								/>
								<span className="smallcaps text-text-3">of {postCount} after removals</span>
							</div>
							<p className="mt-2 text-[12px] text-text-3 leading-[1.55]">
								The proposal commits to this exact value. The current proposer still needs t-of-N
								approvals from the current roster; the new threshold only takes effect on execute.
							</p>
						</div>
					)}
				</div>
			</Card>

			{(validation.ok || removalCount > 0 || thresholdMode === 'change') && (
				<Card tone="raised" className="mt-4 px-5 sm:px-8 py-4">
					<div className="smallcaps text-text-3 mb-2">After execute</div>
					<div className="flex items-baseline gap-3">
						<span className="font-display text-[40px] leading-[0.95] tabular text-text">
							{thresholdMode === 'change' && thresholdInput !== ''
								? thresholdInput
								: vault.data.account.threshold}
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

			<div className="mt-6">
				<SignerGasPayerCard
					state={signer.state}
					onPickSigner={signer.pickSigner}
					onPickGas={signer.pickGas}
					rosterSize={vault.data?.account.members.length ?? 0}
				/>
			</div>

			<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
				{validation.error && (
					<p className="flex-1 text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
						<AlertCircle className="h-3 w-3" />
						{validation.error}
					</p>
				)}
				{submitState.stage === 'submitting' && (
					<p className="flex-1 text-[12.5px] text-text-2 leading-[1.5] inline-flex items-center gap-1.5">
						<Loader2 className="h-3 w-3 animate-spin" />
						{submitState.phase}
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
					disabled={!validation.ok || !isMember || !gasPayer || submitState.stage === 'submitting'}
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

function SchemeIcon({ scheme }: { scheme: number }) {
	if (scheme === SCHEME_SOLANA_ADDRESS) return <Wallet className="h-3 w-3" />;
	return <ShieldCheck className="h-3 w-3" />;
}

function schemeLabel(scheme: number): string {
	if (scheme === SCHEME_SOLANA_ADDRESS) return 'Solana address';
	return `scheme ${scheme}`;
}

function slotDisplay(slot: Uint8Array): string {
	if (slot[0] === SCHEME_SOLANA_ADDRESS) {
		try {
			return new PublicKey(slot.slice(1, 33)).toBase58();
		} catch {
			return '<bad slot>';
		}
	}
	return Array.from(memberIdBytes(slot), (b) => b.toString(16).padStart(2, '0')).join('');
}
