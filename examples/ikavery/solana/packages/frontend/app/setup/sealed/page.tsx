'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import {
	ArrowRight,
	Check,
	Copy,
	Download,
	ExternalLink,
	RotateCcw,
	ShieldCheck,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { IKAVERY_PROGRAM_ID } from '@/lib/env';
import { useSetup } from '@/store/setup';

import { Mono, StepFooter } from '../_parts';

const SOLSCAN_BASE = 'https://solscan.io';
const SOLSCAN_CLUSTER = '?cluster=devnet';

export default function SealedStep() {
	const router = useRouter();
	const result = useSetup((s) => s.result);
	const threshold = useSetup((s) => s.threshold);
	const members = useSetup((s) => s.members);
	const reset = useSetup((s) => s.reset);

	const sealedAt = React.useMemo(() => new Date(), []);

	React.useEffect(() => {
		if (!result) router.replace('/setup/connect');
	}, [result, router]);

	if (!result) return null;

	function startOver() {
		reset();
		router.push('/setup/connect');
	}

	const fundingSol = result.recommendedFundingLamports / 1e9;

	return (
		<>
			<header className="mb-10">
				<span className="smallcaps text-sage inline-flex items-center gap-1.5">
					<ShieldCheck className="h-3.5 w-3.5" />
					05 / Sealed
				</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
					The vault is sealed.
					<br />
					<span className="italic text-text-2">Keep the IDs close.</span>
				</h1>
				<p className="mt-5 max-w-[600px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					The dWallet now sits behind {threshold} of {members.length} approvals on the ikavery
					program. Save the recovery ID — it&apos;s the only public handle to your vault.
				</p>
			</header>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-6 sm:px-10 pt-6 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery PDA</span>
					<span className="smallcaps text-sage">Active on devnet</span>
				</div>
				<BlockId value={result.recovery} big accent="clay" explorerKind="account" />
				<div className="rule-h" />
				<div className="px-6 sm:px-10 pt-5 pb-2 flex items-baseline justify-between border-t border-border">
					<span className="smallcaps text-text-3">dWallet pubkey</span>
					<span className="smallcaps text-text-4">fund this address</span>
				</div>
				<BlockId value={result.dwalletPubkey} accent="text" explorerKind="account" />
			</Card>

			<FundDwalletCallout dwalletPubkey={result.dwalletPubkey} recommendedSol={fundingSol} />

			<Card tone="raised" className="mt-4 p-0 overflow-hidden">
				<div className="px-6 py-4 border-b border-border flex items-center justify-between">
					<span className="smallcaps text-text-2">Receipt</span>
					<span className="font-mono text-[10px] text-text-4 tabular">
						{sealedAt.toISOString()}
					</span>
				</div>
				<div className="divide-y divide-border">
					<Row label="Recovery ID" value={result.recoveryId} />
					<Row label="dWallet PDA" value={result.dwalletAccount} />
					<Row label="create_recovery tx" value={result.signature} explorerKind="tx" />
					<Row label="Quorum" display={`${threshold} of ${members.length}`} mono={false} />
					<Row label="Network" display="solana · devnet" mono={false} />
					<Row label="Ikavery program" value={IKAVERY_PROGRAM_ID} small />
				</div>
			</Card>

			<div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3">
				<NextTile
					ord="i"
					title="Save the recovery ID"
					body="Anywhere you can find it: notes, password manager, taped to the wall. Without it you can't find your vault."
				/>
				<NextTile
					ord="ii"
					title="Fund the dWallet"
					body="Send some devnet SOL to the dWallet pubkey above. The sweep can't move what isn't there."
				/>
				<NextTile
					ord="iii"
					title="Practice a recovery"
					body="Run a sweep on devnet now while the procedure is fresh. Real recoveries shouldn't be your first one."
				/>
			</div>

			<StepFooter
				hint={
					<span className="inline-flex items-center gap-2">
						<ShieldCheck className="h-3.5 w-3.5 text-sage" />
						The pasted Solana key was wiped from this tab. Only the dWallet and Recovery PDAs
						persist on-chain.
					</span>
				}
				back={
					<Button variant="ghost" size="default" onClick={startOver}>
						<RotateCcw className="h-3.5 w-3.5" /> Start over
					</Button>
				}
				next={
					<>
						<DownloadReceiptButton
							data={{
								recovery: result.recovery,
								recoveryId: result.recoveryId,
								dwalletPubkey: result.dwalletPubkey,
								dwalletAccount: result.dwalletAccount,
								signature: result.signature,
								threshold,
								totalMembers: members.length,
								network: 'devnet',
								ikaveryProgramId: IKAVERY_PROGRAM_ID,
								sealedAt: sealedAt.toISOString(),
							}}
						/>
						<Button
							variant="primary"
							size="lg"
							onClick={() => router.push(`/vault/${result.recovery}`)}
						>
							Open the vault
							<ArrowRight className="h-4 w-4" />
						</Button>
					</>
				}
			/>
		</>
	);
}

function FundDwalletCallout({
	dwalletPubkey,
	recommendedSol,
}: {
	dwalletPubkey: string;
	recommendedSol: number;
}) {
	const [copied, setCopied] = React.useState(false);
	function copy() {
		void navigator.clipboard.writeText(dwalletPubkey).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
	return (
		<Card tone="vault" className="mt-4 p-5 sm:p-6">
			<div className="flex items-start gap-3">
				<span className="h-8 w-8 flex-none flex items-center justify-center rounded-md border border-clay/40 bg-clay/10">
					<Wallet className="h-3.5 w-3.5 text-clay" />
				</span>
				<div className="flex-1 min-w-0">
					<span className="smallcaps text-clay">Next: fund the dWallet</span>
					<p className="mt-1 text-[13.5px] text-text-2 leading-[1.55]">
						Send at least <span className="text-text">{recommendedSol} devnet SOL</span> to the
						dWallet pubkey above before any sweep runs. The dWallet pays its own tx fees on Solana.
					</p>
					<div className="mt-3 flex flex-wrap items-center gap-2">
						<Button variant="secondary" size="sm" onClick={copy}>
							{copied ? (
								<>
									<Check className="h-3 w-3 text-sage" />
									<span className="text-sage">Copied</span>
								</>
							) : (
								<>
									<Copy className="h-3 w-3" />
									Copy dWallet address
								</>
							)}
						</Button>
						<Button variant="ghost" size="sm" asChild>
							<a href="https://faucet.solana.com/" target="_blank" rel="noopener noreferrer">
								<ExternalLink className="h-3 w-3" />
								Devnet faucet
							</a>
						</Button>
					</div>
				</div>
			</div>
		</Card>
	);
}

function BlockId({
	value,
	big,
	accent,
	explorerKind,
}: {
	value: string;
	big?: boolean;
	accent: 'clay' | 'text';
	explorerKind: 'account' | 'tx';
}) {
	const [copied, setCopied] = React.useState(false);
	function copy() {
		void navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
	const explorerUrl = `${SOLSCAN_BASE}/${explorerKind}/${value}${SOLSCAN_CLUSTER}`;
	return (
		<div className="px-6 sm:px-10 py-6 sm:py-8 flex items-start gap-5">
			<div className="flex-1 min-w-0">
				<div
					className={`font-display ${
						big
							? 'text-[28px] sm:text-[44px] lg:text-[56px] leading-[1.02]'
							: 'text-[18px] sm:text-[24px] lg:text-[30px] leading-[1.1]'
					} tracking-[-0.018em] tabular ${accent === 'clay' ? 'text-clay' : 'text-text'} break-all`}
					style={{ fontVariantLigatures: 'none' }}
				>
					{value}
				</div>
			</div>
			<div className="flex-none mt-1 flex items-center gap-3">
				<a
					href={explorerUrl}
					target="_blank"
					rel="noopener noreferrer"
					className="inline-flex items-center gap-1.5 smallcaps text-text-3 hover:text-text"
					aria-label="View on explorer"
				>
					<ExternalLink className="h-3.5 w-3.5" />
					Explorer
				</a>
				<button
					type="button"
					onClick={copy}
					className="inline-flex items-center gap-1.5 smallcaps text-text-3 hover:text-text"
					aria-label="Copy"
				>
					{copied ? (
						<>
							<Check className="h-3.5 w-3.5 text-sage" />
							<span className="text-sage">Copied</span>
						</>
					) : (
						<>
							<Copy className="h-3.5 w-3.5" />
							Copy
						</>
					)}
				</button>
			</div>
		</div>
	);
}

function Row({
	label,
	value,
	display,
	mono = true,
	small,
	explorerKind,
}: {
	label: string;
	value?: string;
	display?: string;
	mono?: boolean;
	small?: boolean;
	explorerKind?: 'account' | 'tx';
}) {
	const [copied, setCopied] = React.useState(false);
	const text = value ?? display ?? '';
	function copy() {
		if (!value) return;
		void navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
	return (
		<div className="grid grid-cols-1 md:grid-cols-3 gap-2 px-6 py-4">
			<div className="md:col-span-1 smallcaps text-text-3">{label}</div>
			<div className="md:col-span-2 flex items-start gap-3 min-w-0">
				<div className="flex-1 min-w-0">
					{mono ? (
						<Mono className={small ? 'text-[11.5px]' : 'text-[13px]'}>{text}</Mono>
					) : (
						<span className="text-[14px] text-text">{text}</span>
					)}
				</div>
				{value && (
					<div className="flex-none flex items-center gap-3">
						{explorerKind && (
							<a
								href={`${SOLSCAN_BASE}/${explorerKind}/${value}${SOLSCAN_CLUSTER}`}
								target="_blank"
								rel="noopener noreferrer"
								className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
							>
								<ExternalLink className="h-3 w-3" />
								Explorer
							</a>
						)}
						<button
							type="button"
							onClick={copy}
							className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
							aria-label={`Copy ${label}`}
						>
							{copied ? <Check className="h-3 w-3 text-sage" /> : <Copy className="h-3 w-3" />}
							{copied ? 'Copied' : 'Copy'}
						</button>
					</div>
				)}
			</div>
		</div>
	);
}

function NextTile({ ord, title, body }: { ord: string; title: string; body: string }) {
	return (
		<div className="surface px-5 py-5">
			<span className="font-display italic text-[14px] text-clay tabular">{ord}</span>
			<div className="mt-2 text-[15px] text-text leading-[1.35]">{title}</div>
			<p className="mt-2 text-[12.5px] text-text-3 leading-[1.55]">{body}</p>
		</div>
	);
}

function DownloadReceiptButton({ data }: { data: Record<string, unknown> }) {
	function download() {
		const blob = new Blob([JSON.stringify(data, null, 2)], {
			type: 'application/json',
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `recovery-${String(data.recovery).slice(0, 10)}.json`;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}
	return (
		<Button variant="secondary" size="lg" onClick={download}>
			<Download className="h-4 w-4" />
			Save receipt
		</Button>
	);
}
