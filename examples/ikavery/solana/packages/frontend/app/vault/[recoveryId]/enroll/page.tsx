'use client';

import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { memberIdBytes, packSolanaMember } from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import { useQueryClient } from '@tanstack/react-query';
import { AlertCircle, ArrowRight, Loader2, ShieldCheck, UserPlus, Wallet } from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { BackToVaultLink } from '@/components/vault/back-to-vault';
import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { proposeAndApproveEnrollment } from '@/lib/enrollment';
import { SOLANA_RPC } from '@/lib/env';
import { useVaultQuery } from '@/lib/use-vault';

type MemberType = 'wallet' | 'approver';

type SubmitState =
	{ stage: 'idle' } | { stage: 'submitting'; phase: string } | { stage: 'error'; message: string };

export default function EnrollPage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const queryClient = useQueryClient();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const vault = useVaultQuery(recoveryId);

	const [memberType, setMemberType] = React.useState<MemberType>('wallet');
	const [addressInput, setAddressInput] = React.useState('');
	const [submitState, setSubmitState] = React.useState<SubmitState>({
		stage: 'idle',
	});

	const signer = useSignerState(vault.data ? { members: vault.data.account.members } : null);
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const isMember = voter !== null;

	const built = React.useMemo<{
		pubkey: PublicKey | null;
		error: string | null;
	}>(() => {
		const trimmed = addressInput.trim();
		if (!trimmed) return { pubkey: null, error: null };
		try {
			return { pubkey: new PublicKey(trimmed), error: null };
		} catch {
			return {
				pubkey: null,
				error: "Doesn't look like a valid base58 Solana address.",
			};
		}
	}, [addressInput]);

	const alreadyMember = React.useMemo(() => {
		if (!vault.data || !built.pubkey) return false;
		const newSlot = packSolanaMember(built.pubkey);
		const newId = memberIdBytes(newSlot);
		return vault.data.account.members.some((slot) => bytesEq(memberIdBytes(slot), newId));
	}, [vault.data, built.pubkey]);

	const inputError = built.error ?? (alreadyMember ? 'This address is already a member.' : null);

	async function handleSubmit() {
		if (!gasPayer || !vault.data || !built.pubkey) return;
		if (!voter) {
			setSubmitState({
				stage: 'error',
				message:
					"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			});
			return;
		}

		setSubmitState({ stage: 'submitting', phase: 'Awaiting authorisation…' });
		try {
			const result = await proposeAndApproveEnrollment({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.data.recovery,
				recoveryId: vault.data.account.recoveryId,
				dwalletPubkey: vault.data.dwalletPubkey,
				dwalletAccount: vault.data.dwalletAccount,
				threshold: vault.data.account.threshold,
				expectedIndex: vault.data.account.enrollmentCount,
				draft: {
					newMemberAddress: built.pubkey.toBase58(),
					approverOnly: memberType === 'approver',
				},
				onProgress: (p) =>
					setSubmitState({
						stage: 'submitting',
						phase:
							p === 'ensuring-alt'
								? 'Preparing lookup table…'
								: p === 'proposing'
									? 'Proposing enrollment…'
									: p === 'approving'
										? 'Recording your approval…'
										: 'Working…',
					}),
			});
			setSubmitState({ stage: 'submitting', phase: 'Opening proposal…' });
			await queryClient.invalidateQueries({
				queryKey: ['solana-vault', recoveryId],
			});
			router.push(`/vault/${recoveryId}/enroll/${result.enrollmentIndex}`);
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
				<span className="smallcaps text-text-3">Enrollment</span>
				<h1 className="mt-2 font-display text-[34px] sm:text-[40px] leading-[1.04] text-text">
					Add a member
				</h1>
				<p className="mt-3 text-[14px] text-text-2 leading-[1.6] max-w-[640px]">
					Paste a Solana address and post the enrollment. Wallet members can approve and broadcast
					recoveries; approver-only members vote on proposals via{' '}
					<span className="font-mono text-[12.5px]">on-tx Signer</span> match but can&apos;t
					broadcast.
				</p>
			</header>

			<div className="grid grid-cols-2 gap-2 mb-4">
				<TypeTab
					active={memberType === 'wallet'}
					onClick={() => setMemberType('wallet')}
					icon={<Wallet className="h-3.5 w-3.5" />}
					label="Wallet"
					hint="Solana address · approver"
				/>
				<TypeTab
					active={memberType === 'approver'}
					onClick={() => setMemberType('approver')}
					icon={<ShieldCheck className="h-3.5 w-3.5" />}
					label="Approver only"
					hint="Same scheme · vote-only"
				/>
			</div>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border">
					<span className="smallcaps text-text-3">New member</span>
				</div>
				<div className="px-5 sm:px-8 py-5 space-y-4">
					<div>
						<label htmlFor="enroll-addr" className="smallcaps text-text-3 block mb-2">
							Solana address
						</label>
						<input
							id="enroll-addr"
							type="text"
							inputMode="text"
							autoComplete="off"
							spellCheck={false}
							placeholder="9wXJp1xs… (base58)"
							value={addressInput}
							onChange={(e) => setAddressInput(e.target.value)}
							className="w-full font-mono text-[13px] tabular bg-surface-2 border border-border rounded-md px-3 py-2.5 focus:outline-none focus:border-clay/60"
						/>
						<p className="mt-2 text-[12px] text-text-3 leading-[1.55]">
							{memberType === 'wallet'
								? 'Any Solana base58 address. The wallet behind it can sign approvals once enrolled. No SOL needed at enrollment time.'
								: "Any Solana base58 address. Approver-only members can vote on proposals via the on-tx Signer check, but can't execute or broadcast."}
						</p>
					</div>

					{inputError && (
						<p className="text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
							<AlertCircle className="h-3 w-3" />
							{inputError}
						</p>
					)}
				</div>
			</Card>

			<div className="mt-6">
				<SignerGasPayerCard
					state={signer.state}
					onPickSigner={signer.pickSigner}
					onPickGas={signer.pickGas}
					rosterSize={vault.data?.account.members.length ?? 0}
				/>
			</div>

			<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
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
					disabled={
						!built.pubkey ||
						alreadyMember ||
						!isMember ||
						!gasPayer ||
						submitState.stage === 'submitting'
					}
					onClick={handleSubmit}
				>
					{submitState.stage === 'submitting' ? (
						<>
							<Loader2 className="h-4 w-4 animate-spin" />
							Proposing enrollment…
						</>
					) : (
						<>
							<UserPlus className="h-4 w-4" />
							Propose enrollment
							<ArrowRight className="h-4 w-4" />
						</>
					)}
				</Button>
			</div>
		</div>
	);
}

function TypeTab({
	active,
	onClick,
	icon,
	label,
	hint,
}: {
	active: boolean;
	onClick: () => void;
	icon: React.ReactNode;
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
			<div className="inline-flex items-center gap-1.5">
				{icon}
				<span className="smallcaps">{label}</span>
			</div>
			<div className="mt-1 text-[11.5px] text-text-3 leading-[1.4]">{hint}</div>
		</button>
	);
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}
