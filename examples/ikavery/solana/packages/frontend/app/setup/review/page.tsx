'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import {
	AlertCircle,
	ArrowLeft,
	CheckCircle2,
	Copy,
	Loader2,
	Sparkles,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { IKAVERY_PROGRAM_ID, SOLANA_RPC } from '@/lib/env';
import { parseSolanaSecret } from '@/lib/parse-secret';
import { sealVault } from '@/lib/seal-vault';
import { appendSavedVault } from '@/lib/storage';
import {
	memberDisplayId,
	memberFullId,
	memberKey,
	memberKindLabel,
	useSetup,
	type SealPhase,
	type StoredMember,
} from '@/store/setup';

import { Mono, StepFooter, StepHeader } from '../_parts';

type SubmitState =
	| { stage: 'idle' }
	| { stage: 'submitting'; phase: SealPhase }
	| { stage: 'error'; message: string }
	| { stage: 'done' };

export default function ReviewStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const threshold = useSetup((s) => s.threshold);
	const secretInput = useSetup((s) => s.solanaSecretInput);
	const setResult = useSetup((s) => s.setResult);
	const { primaryWallet, sdkHasLoaded } = useDynamicContext();

	const [state, setState] = React.useState<SubmitState>({ stage: 'idle' });

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
		else if (members.length === 0) router.replace('/setup/threshold');
		else if (!secretInput) router.replace('/setup/key');
	}, [importer, members.length, secretInput, router]);

	const parsed = React.useMemo(() => parseSolanaSecret(secretInput), [secretInput]);

	if (!importer) return null;
	if (!parsed.ok) return null;

	async function handleSubmit() {
		if (!importer || !primaryWallet || !parsed.ok) return;
		setState({ stage: 'submitting', phase: 'dkg' });
		try {
			const result = await sealVault({
				primaryWallet,
				importer,
				members,
				threshold,
				solanaSecretKey: parsed.bytes,
				onProgress: (phase) => setState({ stage: 'submitting', phase }),
			});
			setResult(result);
			await appendSavedVault({
				recovery: result.recovery,
				recoveryId: result.recoveryId,
				dwalletPubkey: result.dwalletPubkey,
				threshold,
				totalMembers: members.length,
				createdAt: Date.now(),
			});
			setState({ stage: 'done' });
			router.push('/setup/sealed');
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setState({ stage: 'error', message });
		}
	}

	const submitting = state.stage === 'submitting';
	const noWallet = !primaryWallet;
	const initializing = !sdkHasLoaded;

	return (
		<>
			<StepHeader
				ord="04 / Review"
				title="One last look"
				italic="before sealing."
				hint="Submitting triggers two on-chain transactions. The first transfers the freshly-DKG'd dWallet's authority to the ikavery CPI PDA so the program can sign sweeps. The second creates the on-chain Recovery account holding your roster and threshold. Your connected wallet signs both."
			/>

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-8 p-0 overflow-hidden">
					<div className="px-6 py-4 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-2">Vault summary</span>
						<span className="smallcaps text-text-3">solana · devnet</span>
					</div>
					<div className="divide-y divide-border">
						<Row label="Threshold" value={`${threshold} of ${members.length}`} />
						<Row
							label="Initial user"
							value={memberDisplayId(importer)}
							sub={memberKindLabel(importer)}
						/>
						<Row
							label="Solana key (paste)"
							value={parsed.publicKey}
							sub={`${parsed.bytes.length} bytes detected`}
						/>
						<PrealphaNote />
						<Row
							label="Roster"
							value={
								<ul className="space-y-2 mt-1">
									{members.map((m, i) => (
										<li key={memberKey(m)} className="flex items-baseline gap-3 text-[13px]">
											<span className="font-mono text-[10px] text-text-4 tabular w-6">
												{String(i + 1).padStart(2, '0')}
											</span>
											<span className="text-text-3 smallcaps w-20">
												{memberSlotLabel(m, i === 0)}
											</span>
											<Mono className="text-[12px]">{memberDisplayId(m)}</Mono>
										</li>
									))}
								</ul>
							}
						/>
						<Row label="Ikavery program" value={IKAVERY_PROGRAM_ID} small />
						<Row label="Solana RPC" value={SOLANA_RPC} mono={false} />
					</div>
				</Card>

				<Card tone="raised" className="lg:col-span-4 p-6 sm:p-7">
					<div className="flex items-baseline justify-between gap-3">
						<span className="smallcaps text-text-2 inline-flex items-center gap-1.5">
							<Wallet className="h-3 w-3" />
							Identity
						</span>
						<CopyChip value={memberFullId(importer)} />
					</div>
					<Mono className="block mt-2">{memberDisplayId(importer)}</Mono>
					<p className="mt-4 text-[12.5px] text-text-3 leading-[1.55]">
						{importer.kind === 'passkey'
							? 'Your passkey authorises the on-chain create. A connected wallet pays Solana fees and signs the dWallet authority transfer — total a couple of fractional cents of devnet SOL.'
							: 'The connected wallet signs both transactions and pays Solana fees. Total: a couple of fractional cents of devnet SOL.'}
					</p>
					<div className="rule-h my-4" />
					<p className="text-[12px] text-text-4 leading-[1.55]">
						After sealing you&apos;ll need to send some devnet SOL to the generated dWallet pubkey
						before any sweep can run — same dance the e2e scripts do with `airdrop` + manual
						transfer.
					</p>
				</Card>
			</div>

			{submitting && (
				<div className="mt-6 surface px-5 py-4 border border-border">
					<div className="flex items-start gap-3">
						<Loader2 className="h-4 w-4 text-clay mt-0.5 animate-spin flex-none" />
						<div className="flex-1 min-w-0">
							<span className="smallcaps text-clay">Sealing · {phaseLabel(state.phase)}</span>
							<p className="mt-1 text-[12.5px] text-text-3 leading-[1.55]">
								{phaseHint(state.phase)}
							</p>
						</div>
					</div>
				</div>
			)}

			{state.stage === 'error' && (
				<div className="mt-6 surface px-5 py-4 border border-clay/40 bg-clay/[0.05]">
					<div className="flex items-start gap-3">
						<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
						<div className="flex-1 min-w-0">
							<span className="smallcaps text-clay">Submission failed</span>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55] break-words">
								{state.message}
							</p>
						</div>
					</div>
				</div>
			)}

			<StepFooter
				hint={
					submitting
						? 'Do not refresh this page; transactions are in flight.'
						: 'Once you continue, two transactions are submitted to Solana devnet. The recoveryId returned on the next screen is the only handle to your vault.'
				}
				back={
					<Button
						variant="ghost"
						size="default"
						disabled={submitting}
						onClick={() => router.push('/setup/key')}
					>
						<ArrowLeft className="h-3.5 w-3.5" /> Back
					</Button>
				}
				next={
					<Button
						variant="irreversible"
						size="lg"
						disabled={submitting || initializing || noWallet}
						onClick={handleSubmit}
					>
						{submitting ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Sealing ({phaseLabel(state.phase)})…
							</>
						) : state.stage === 'done' ? (
							<>
								<CheckCircle2 className="h-4 w-4" /> Sealed
							</>
						) : initializing ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" /> Warming up…
							</>
						) : noWallet ? (
							<>
								<Wallet className="h-4 w-4" /> Reconnect wallet
							</>
						) : (
							<>
								<Sparkles className="h-4 w-4" /> Seal the vault
							</>
						)}
					</Button>
				}
			/>
		</>
	);
}

function phaseLabel(p: SealPhase): string {
	switch (p) {
		case 'dkg':
			return 'DKG';
		case 'awaiting-pda':
			return 'awaiting PDA';
		case 'transfer-authority':
			return 'transfer authority';
		case 'create-recovery':
			return 'create recovery';
		case 'done':
			return 'done';
		default:
			return 'preparing';
	}
}

function phaseHint(p: SealPhase): string {
	switch (p) {
		case 'dkg':
			return "Running gRPC DKG against the Ika pre-alpha mock signer. The network is generating a fresh dWallet keypair and binding it to your wallet's session.";
		case 'awaiting-pda':
			return 'Waiting for the dWallet PDA to materialize on-chain (typically 5–15s).';
		case 'transfer-authority':
			return 'Transferring dWallet authority to the ikavery CPI PDA so the program can sign sweeps. Your wallet should prompt to approve.';
		case 'create-recovery':
			return 'Creating the on-chain Recovery account with your roster + threshold. Approve in your wallet to finalize.';
		default:
			return '';
	}
}

function PrealphaNote() {
	return (
		<div className="px-6 py-3 bg-clay/[0.05] flex items-start gap-3 text-[12px] text-text-3 leading-[1.5]">
			<AlertCircle className="h-3.5 w-3.5 text-clay mt-0.5 flex-none" />
			<p>
				Ika pre-alpha generates a fresh dWallet rather than importing your pasted key. The dWallet
				pubkey shown on the next screen is the one you&apos;ll fund — your pasted key stays
				untouched.
			</p>
		</div>
	);
}

function memberSlotLabel(m: StoredMember, isImporter: boolean): string {
	if (m.kind === 'passkey') return 'Passkey';
	if (isImporter) return m.walletName ?? 'Wallet';
	return 'Address';
}

function CopyChip({ value }: { value: string }) {
	const [copied, setCopied] = React.useState(false);
	function copy() {
		void navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
	return (
		<button
			type="button"
			onClick={copy}
			className="inline-flex items-center gap-1.5 smallcaps text-text-3 hover:text-text"
			aria-label="Copy address"
		>
			{copied ? (
				<>
					<CheckCircle2 className="h-3 w-3 text-sage" />
					<span className="text-sage">Copied</span>
				</>
			) : (
				<>
					<Copy className="h-3 w-3" />
					Copy
				</>
			)}
		</button>
	);
}

function Row({
	label,
	value,
	sub,
	mono = true,
	small,
}: {
	label: string;
	value: React.ReactNode;
	sub?: string;
	mono?: boolean;
	small?: boolean;
}) {
	return (
		<div className="grid grid-cols-1 md:grid-cols-3 gap-2 px-6 py-4">
			<div className="md:col-span-1 smallcaps text-text-3">{label}</div>
			<div className="md:col-span-2 text-[14px] text-text">
				{typeof value === 'string' ? (
					mono ? (
						<Mono className={small ? 'text-[11.5px]' : 'text-[13px]'}>{value}</Mono>
					) : (
						<span className="text-[13px] text-text">{value}</span>
					)
				) : (
					value
				)}
				{sub && <div className="smallcaps text-text-4 mt-1">{sub}</div>}
			</div>
		</div>
	);
}
