'use client';

import {
	Button,
	Card,
	ProposalDetailSkeleton,
	truncateAddress,
} from '@fesal-packages/ikavery-frontend-ui';
import {
	enrollmentApprovalPda,
	memberIdHash,
	SCHEME_SOLANA_ADDRESS,
	STATUS_EXECUTED,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import {
	AlertCircle,
	ArrowLeft,
	Check,
	CheckCircle2,
	Copy,
	ExternalLink,
	Loader2,
	Send,
	Signature,
	UserPlus,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import {
	approveEnrollmentAsMember,
	executeEnrollment,
	type EnrollmentPhase,
} from '@/lib/enrollment';
import { SOLANA_RPC } from '@/lib/env';
import { useEnrollmentQuery } from '@/lib/use-enrollment';
import { useVaultQuery, type VaultState } from '@/lib/use-vault';
import { memberSlotForVoter } from '@/lib/voter';

const SOLSCAN_BASE = 'https://solscan.io';
const SOLSCAN_CLUSTER = '?cluster=devnet';

export default function EnrollmentApprovalPage() {
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const enrollmentIndex = Number.parseInt(params.id, 10);

	const vaultQ = useVaultQuery(recoveryId);
	const enrollQ = useEnrollmentQuery(
		vaultQ.data?.recovery ?? null,
		Number.isFinite(enrollmentIndex) ? enrollmentIndex : null,
	);

	if (!Number.isFinite(enrollmentIndex)) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Bad enrollment id"
				message={`Enrollment index ${params.id} isn't a valid integer.`}
			/>
		);
	}
	if (vaultQ.isLoading || enrollQ.isLoading) {
		return (
			<ProposalDetailSkeleton
				recoveryId={recoveryId}
				idStr={params.id}
				kindLabel="Enrollment"
				kindAccent="text-text-3"
				Icon={UserPlus}
			/>
		);
	}
	if (vaultQ.error || !vaultQ.data) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Couldn't open this vault"
				message={String(vaultQ.error instanceof Error ? vaultQ.error.message : vaultQ.error)}
			/>
		);
	}
	if (!enrollQ.data?.account) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Enrollment not found"
				message={`Enrollment ${enrollmentIndex} doesn't exist on this vault — it may have been replaced by a newer one.`}
			/>
		);
	}

	return (
		<View
			recoveryId={recoveryId}
			vault={vaultQ.data}
			enrollment={enrollQ.data.enrollment}
			enrollmentIndex={enrollmentIndex}
			account={enrollQ.data.account}
		/>
	);
}

function View({
	recoveryId,
	vault,
	enrollment,
	enrollmentIndex,
	account,
}: {
	recoveryId: string;
	vault: VaultState;
	enrollment: PublicKey;
	enrollmentIndex: number;
	account: NonNullable<ReturnType<typeof useEnrollmentQuery>['data']>['account'];
}) {
	const router = useRouter();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const signer = useSignerState({ members: vault.account.members });
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const meSlot = React.useMemo(() => (voter ? memberSlotForVoter(voter) : null), [voter]);
	const isMember = voter !== null;

	const [hasMyApproval, setHasMyApproval] = React.useState<boolean | 'checking'>('checking');
	const approvalCountSignal = account?.approvalCount;
	// biome-ignore lint/correctness/useExhaustiveDependencies: approvalCountSignal is the manual invalidation key, not a value the effect reads.
	React.useEffect(() => {
		if (!meSlot || !isMember) {
			setHasMyApproval(false);
			return;
		}
		let cancelled = false;
		(async () => {
			const memberHash = memberIdHash(meSlot);
			const approval = enrollmentApprovalPda(enrollment, memberHash);
			const info = await connection.getAccountInfo(approval, 'confirmed');
			if (!cancelled) setHasMyApproval(info !== null);
		})();
		return () => {
			cancelled = true;
		};
	}, [enrollment, meSlot, isMember, connection, approvalCountSignal]);

	const [busy, setBusy] = React.useState<EnrollmentPhase | null>(null);
	const [executeSig, setExecuteSig] = React.useState<string | null>(null);
	const [error, setError] = React.useState<string | null>(null);

	if (!account) return null;

	const status = account.status;
	const approvalCount = account.approvalCount;
	const threshold = vault.account.threshold;
	const reachedThreshold = approvalCount >= threshold || status >= STATUS_EXECUTED;
	const executed = status === STATUS_EXECUTED || executeSig !== null;
	const newMemberAddress = decodeMemberAddress(account.newMember);
	const memberRendered = renderNewMember(account.newMember, newMemberAddress);

	async function handleApprove() {
		if (!gasPayer) return;
		if (!voter) {
			setError(
				"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			);
			return;
		}
		setError(null);
		setBusy('ensuring-alt');
		try {
			await approveEnrollmentAsMember({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.recovery,
				recoveryId: vault.account.recoveryId,
				enrollment,
				enrollmentIndex,
				dwalletPubkey: vault.dwalletPubkey,
				dwalletAccount: vault.dwalletAccount,
				onProgress: (p) => setBusy(p),
			});
			setBusy(null);
			setHasMyApproval(true);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			setError(msg);
			setBusy(null);
		}
	}

	async function handleExecute() {
		if (!gasPayer) return;
		setError(null);
		setBusy('executing');
		try {
			const r = await executeEnrollment({
				connection,
				primaryWallet: gasPayer.wallet,
				recovery: vault.recovery,
				enrollment,
				onProgress: (p) => setBusy(p),
			});
			setExecuteSig(r.signature);
			setBusy(null);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			setError(msg);
			setBusy(null);
		}
	}

	return (
		<div className="max-w-[820px] mx-auto py-10">
			<button
				type="button"
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<UserPlus className="h-3 w-3" />
					Enrollment #{enrollmentIndex.toString().padStart(2, '0')}
				</div>
				<h1 className="mt-2 font-display text-[32px] sm:text-[38px] leading-[1.05] text-text">
					{executed ? 'Enrollment complete' : 'Add a new member'}
				</h1>
			</header>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Proposed member</span>
					<span className="smallcaps text-text-4">{memberRendered.kindLabel}</span>
				</div>
				<div className="px-5 sm:px-8 py-5">
					<div className="font-mono text-[13px] tabular text-text break-all">
						{memberRendered.identity}
					</div>
					{account.additionApproverOnly === 1 && (
						<p className="mt-3 text-[12.5px] text-text-3 leading-[1.55]">
							Approver-only — auth via <span className="font-mono text-[12px]">on-tx Signer</span>{' '}
							match. Can vote on proposals but cannot execute a recovery (no encrypted share is
							provisioned for this member).
						</p>
					)}
				</div>
				<div className="px-5 sm:px-8 py-4 border-t border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Approvals</span>
					<span
						className={`font-mono text-[20px] tabular ${
							reachedThreshold ? 'text-sage' : 'text-text'
						}`}
					>
						{approvalCount} / {threshold}
					</span>
				</div>
			</Card>

			{!executed && (
				<div className="mt-4">
					<SignerGasPayerCard
						state={signer.state}
						onPickSigner={signer.pickSigner}
						onPickGas={signer.pickGas}
						rosterSize={vault.account.members.length}
					/>
				</div>
			)}

			{!executed && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{error && (
						<p className="flex-1 text-[12.5px] text-clay leading-[1.5] inline-flex items-start gap-1.5">
							<AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-none" />
							{error}
						</p>
					)}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!isMember ||
							!gasPayer ||
							hasMyApproval === true ||
							hasMyApproval === 'checking' ||
							reachedThreshold ||
							busy !== null
						}
						onClick={handleApprove}
					>
						{busy === 'ensuring-alt' || busy === 'approving' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								{busy === 'ensuring-alt' ? 'Preparing lookup table…' : 'Approving…'}
							</>
						) : hasMyApproval === true ? (
							<>
								<CheckCircle2 className="h-4 w-4" />
								You approved
							</>
						) : reachedThreshold ? (
							<>
								<CheckCircle2 className="h-4 w-4" />
								Quorum reached
							</>
						) : (
							<>
								<Signature className="h-4 w-4" />
								Approve
							</>
						)}
					</Button>
					<Button
						variant="irreversible"
						size="lg"
						disabled={!reachedThreshold || !gasPayer || busy !== null}
						onClick={handleExecute}
					>
						{busy === 'executing' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Executing…
							</>
						) : (
							<>
								<Send className="h-4 w-4" />
								Execute enrollment
							</>
						)}
					</Button>
				</div>
			)}

			{!executed && (
				<div className="mt-4">
					<ShareLink recoveryId={recoveryId} enrollmentIndex={enrollmentIndex} />
				</div>
			)}

			{!account.additionApproverOnly && !executed && (
				<Card tone="raised" className="mt-6 px-6 py-4 border-border">
					<p className="text-[12.5px] text-text-3 leading-[1.55] inline-flex items-start gap-2">
						<AlertCircle className="h-3.5 w-3.5 text-text-3 flex-none mt-0.5" />
						<span>
							Solana ika pre-alpha doesn&apos;t expose a re-encrypt CPI yet, so this execute only
							records the new member on-chain. Real key-holder share migration arrives with mainnet.
						</span>
					</p>
				</Card>
			)}

			{executed && (
				<Card tone="raised" className="mt-6 px-6 py-5 border-sage/40">
					<div className="flex items-start gap-3">
						<CheckCircle2 className="h-4 w-4 text-sage mt-0.5 flex-none" />
						<div className="flex-1 min-w-0">
							<div className="smallcaps text-sage">Member added</div>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55]">
								The new member is in the roster and can vote on future proposals.
							</p>
							{executeSig && (
								<a
									href={`${SOLSCAN_BASE}/tx/${executeSig}${SOLSCAN_CLUSTER}`}
									target="_blank"
									rel="noopener noreferrer"
									className="mt-4 block surface px-4 py-3 hover:border-clay/40 transition-colors group"
								>
									<span className="smallcaps text-text-3">Execute tx</span>
									<div className="mt-1 flex items-center justify-between gap-2">
										<span className="font-mono text-[12px] tabular text-text-2 group-hover:text-text">
											{truncateAddress(executeSig, 10, 8)}
										</span>
										<ExternalLink className="h-3.5 w-3.5 text-text-3 group-hover:text-clay" />
									</div>
								</a>
							)}
						</div>
					</div>
				</Card>
			)}
		</div>
	);
}

function ShareLink({
	recoveryId,
	enrollmentIndex,
}: {
	recoveryId: string;
	enrollmentIndex: number;
}) {
	const [copied, setCopied] = React.useState(false);
	const url =
		typeof window !== 'undefined'
			? `${window.location.origin}/vault/${recoveryId}/enroll/${enrollmentIndex}`
			: '';
	return (
		<button
			type="button"
			onClick={async () => {
				await navigator.clipboard.writeText(url);
				setCopied(true);
				setTimeout(() => setCopied(false), 1600);
			}}
			className="inline-flex items-center gap-1.5 smallcaps text-text-3 hover:text-text"
		>
			{copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
			{copied ? 'Link copied' : 'Copy share link · approve from another device'}
		</button>
	);
}

// ─── helpers ─────────────────────────────────────────────────────────

function renderNewMember(
	slot: Uint8Array,
	resolvedAddress: string | null,
): { kindLabel: string; identity: string } {
	const scheme = slot[0];
	if (scheme === SCHEME_SOLANA_ADDRESS && resolvedAddress) {
		return {
			kindLabel: 'Wallet · Solana',
			identity: resolvedAddress,
		};
	}
	return {
		kindLabel: schemeLabel(scheme),
		identity: bytesToHex(slot.slice(1, 1 + idLen(scheme))),
	};
}

function schemeLabel(scheme: number | undefined): string {
	switch (scheme) {
		case 0:
			return 'Wallet · ed25519';
		case 1:
			return 'Wallet · secp256k1';
		case 2:
			return 'Wallet · secp256r1';
		case 3:
			return 'Passkey';
		case 4:
			return 'Wallet · Solana';
		default:
			return 'Unknown scheme';
	}
}

function idLen(scheme: number | undefined): number {
	switch (scheme) {
		case 0:
			return 32;
		case 1:
		case 2:
		case 3:
			return 33;
		case 4:
			return 32;
		default:
			return 0;
	}
}

function decodeMemberAddress(slot: Uint8Array): string | null {
	if (slot[0] === SCHEME_SOLANA_ADDRESS) {
		try {
			return new PublicKey(slot.slice(1, 33)).toBase58();
		} catch {
			return null;
		}
	}
	return null;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
