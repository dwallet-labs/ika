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
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { env } from '@/lib/env';
import { useSetup } from '@/store/setup';

import { Mono, StepFooter } from '../_parts';

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

	const totalMembers = members.length;

	function startOver() {
		reset();
		router.push('/setup/connect');
	}

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
					<span className="italic text-text-2">Keep this number close.</span>
				</h1>
				<p className="mt-5 max-w-[600px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					Your Solana key now lives behind {threshold} of {totalMembers} passkey approvals. The
					recovery ID below is the only public handle to your vault. Save it somewhere you can find
					again.
				</p>
			</header>

			{/* Block-printed primary IDs */}
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-6 sm:px-10 pt-6 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery ID</span>
					<span className="smallcaps text-sage">Active on {env.network}</span>
				</div>
				<BlockId value={result.recoveryId} big accent="clay" />
				<div className="rule-h" />
				<div className="px-6 sm:px-10 pt-5 pb-2 flex items-baseline justify-between border-t border-border">
					<span className="smallcaps text-text-3">dWallet ID</span>
					<span className="smallcaps text-text-4">Ika 2PC-MPC</span>
				</div>
				<BlockId value={result.dwalletId} accent="text" />
			</Card>

			{/* Metadata ledger */}
			<Card tone="raised" className="mt-4 p-0 overflow-hidden">
				<div className="px-6 py-4 border-b border-border flex items-center justify-between">
					<span className="smallcaps text-text-2">Receipt</span>
					<span className="font-mono text-[10px] text-text-4 tabular">
						{sealedAt.toISOString()}
					</span>
				</div>
				<div className="divide-y divide-border">
					<Row label="Encrypted user share" value={result.encryptedUserShareId} />
					<Row label="Verification tx" value={result.txDigest} explorer />
					<Row label="Quorum" display={`${threshold} of ${totalMembers}`} mono={false} />
					<Row label="Network" display={env.network} mono={false} />
					<Row label="Recovery package" value={env.recoveryPackageId} small />
				</div>
			</Card>

			{/* What now */}
			<div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3">
				<NextTile
					ord="i"
					title="Save the recovery ID"
					body="Anywhere you can find it: notes app, password manager, taped to a wall. Without it you cannot find your vault."
				/>
				<NextTile
					ord="ii"
					title="Enroll more devices"
					body="Quorum works best when devices live in different places. Open the vault to add a second passkey from a phone or another laptop."
				/>
				<NextTile
					ord="iii"
					title="Practice a recovery"
					body="Run a sweep on devnet now while the procedure is fresh. Real recoveries should not be the first ones you do."
				/>
			</div>

			<StepFooter
				hint={
					<span className="inline-flex items-center gap-2">
						<ShieldCheck className="h-3.5 w-3.5 text-sage" />
						The Solana secret is wiped from this tab. The encrypted share lives on Sui under your
						passkey.
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
								recoveryId: result.recoveryId,
								dwalletId: result.dwalletId,
								encryptedUserShareId: result.encryptedUserShareId,
								txDigest: result.txDigest,
								threshold,
								totalMembers,
								network: env.network,
								recoveryPackageId: env.recoveryPackageId,
								sealedAt: sealedAt.toISOString(),
							}}
						/>
						<Button
							variant="primary"
							size="lg"
							onClick={() => router.push(`/vault/${result.recoveryId}`)}
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

function BlockId({
	value,
	big,
	accent,
}: {
	value: string;
	big?: boolean;
	accent: 'clay' | 'text';
}) {
	const [copied, setCopied] = React.useState(false);
	function copy() {
		void navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
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
					href={`https://suiscan.xyz/${env.network}/object/${value}`}
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
	explorer,
}: {
	label: string;
	value?: string;
	display?: string;
	mono?: boolean;
	small?: boolean;
	explorer?: boolean;
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
						{explorer && (
							<a
								href={`https://suiscan.xyz/${env.network}/tx/${value}`}
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
		a.download = `recovery-${String(data.recoveryId).slice(0, 10)}.json`;
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
