'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { useCurrentAccount, useWalletConnection } from '@mysten/dapp-kit-react';
import { fromBase64 } from '@mysten/sui/utils';
import {
	AlertCircle,
	ArrowLeft,
	Check,
	CheckCircle2,
	Copy,
	Loader2,
	Sparkles,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { GasBudgetRow } from '@/components/vault/gas-budget-row';
import { WalletConnect } from '@/components/wallet-connect';
import { dAppKit } from '@/lib/dapp-kit';
import { env } from '@/lib/env';
import { bytesToHex } from '@/lib/format';
import { ESTIMATE_IMPORT } from '@/lib/gas-preflight';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import type { ImportKeyPhase } from '@/lib/session';
import { simulateOrThrow } from '@/lib/sponsored-sign';
import { appendSavedVault, hexToBytes } from '@/lib/storage';
import { sameIdentity, toNewMember, useSetup } from '@/store/setup';

import { Mono, StepFooter, StepHeader } from '../_parts';

type SubmitState =
	| { stage: 'idle' }
	| { stage: 'submitting'; phase: ImportKeyPhase }
	| { stage: 'error'; message: string }
	| { stage: 'done' };

export default function ReviewStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const threshold = useSetup((s) => s.threshold);
	const secretInput = useSetup((s) => s.solanaSecretInput);
	const setResult = useSetup((s) => s.setResult);

	const { session, suiClient, status: clientStatus } = useRecoveryClient();
	const account = useCurrentAccount();
	const { isConnecting: walletReconnecting } = useWalletConnection();
	// Sign-only — we run executeTransaction ourselves to get the rich
	// events/effects/objectTypes shape the recovery SDK consumes.
	// useSignAndExecuteTransaction would post-process for `effects.bcs` /
	// `rawEffects`, which the new core API doesn't expose at the top level.
	const walletSign = dAppKit.signTransaction;

	const [state, setState] = React.useState<SubmitState>({ stage: 'idle' });

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
		else if (members.length === 0) router.replace('/setup/threshold');
		else if (!secretInput) router.replace('/setup/key');
	}, [importer, members, secretInput, router]);

	// Reorder so the importer is first; the SDK requires initialMembers[0] to be
	// the importer (the entity whose encryption identity owns the DKG share).
	const orderedMembers = React.useMemo(() => {
		if (!importer) return members;
		const rest = members.filter((m) => !sameIdentity(m, importer));
		const importerInRoster = members.find((m) => sameIdentity(m, importer));
		return importerInRoster ? [importerInRoster, ...rest] : [importer, ...rest];
	}, [importer, members]);

	if (!importer) return null;

	const secretBytes = parseSecret(secretInput);

	async function handleSubmit() {
		if (!importer || !secretBytes || !account || !session) return;
		if (importer.kind === 'approver') {
			// Defense-in-depth — `setup/connect` already blocks this path, but if
			// a stale store puts an approver in the importer slot, fail loud.
			setState({
				stage: 'error',
				message:
					'The initial user must hold an encryption identity (passkey or ' +
					'regular Sui wallet). Restart /setup with a key-holding wallet.',
			});
			return;
		}
		setState({ stage: 'submitting', phase: 'preparing' });
		try {
			const importerKeyBytes = hexToBytes(importer.encryptionKeysBytesHex);

			// Importer is index 0 of orderedMembers. For each remaining member, the
			// worker either receives a serialized UserShareEncryptionKeys (key-
			// holder, gets a re-encrypted share) or an approver-only marker
			// (zkLogin/MultiSig/Passkey-as-sender — added to the roster but no
			// share work since they can't decrypt one).
			const additionalMembers = orderedMembers.slice(1).map((m) =>
				m.kind === 'approver'
					? { kind: 'approver-only' as const }
					: {
							kind: 'key-holder' as const,
							keyBytes: hexToBytes(m.encryptionKeysBytesHex),
						},
			);

			const result = await session.runImportSolanaKey({
				walletAddress: account.address,
				signAndExecute: async (transaction) => {
					if (!suiClient) throw new Error('Sui client not initialized');
					await simulateOrThrow(suiClient, transaction);
					const { bytes, signature } = await walletSign({ transaction });
					return await suiClient.core.executeTransaction({
						transaction: fromBase64(bytes),
						signatures: [signature],
						include: { events: true, effects: true, objectTypes: true },
					});
				},
				importerKeyBytes,
				solanaSecretKey: secretBytes,
				initialMembers: orderedMembers.map(toNewMember),
				threshold,
				additionalMembers,
				onProgress: (phase) => setState({ stage: 'submitting', phase }),
			});

			setResult(result);
			await appendSavedVault({
				recoveryId: result.recoveryId,
				dwalletId: result.dwalletId,
				threshold,
				totalMembers: orderedMembers.length,
				createdAt: Date.now(),
				myEncryptedUserShareId: result.encryptedUserShareId,
			});

			setState({ stage: 'done' });
			router.push('/setup/sealed');
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setState({ stage: 'error', message });
		}
	}

	const submitting = state.stage === 'submitting';
	const initializing = clientStatus === 'initializing';
	const noWallet = !account;

	return (
		<>
			<StepHeader
				ord="04 / Review"
				title="One last look"
				italic="before sealing."
				hint="Submitting triggers three on-chain PTBs: register every member's encryption key + verify import + create Recovery, then re-encrypt the share for each member, then accept on every member's behalf. The whole batch is signed by the connected wallet."
			/>

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-8 p-0 overflow-hidden">
					<div className="px-6 py-4 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-2">Vault summary</span>
						<span className="smallcaps text-text-3">{env.network}</span>
					</div>
					<div className="divide-y divide-border">
						<Row label="Threshold" value={`${threshold} of ${orderedMembers.length}`} />
						<Row
							label="Initial user"
							value={
								importer.kind === 'passkey'
									? truncate(importer.publicKeyHex)
									: truncate(importer.address)
							}
							sub={
								importer.kind === 'passkey'
									? 'passkey · ES256'
									: importer.walletName
										? `wallet · ${importer.walletName}`
										: 'wallet'
							}
						/>
						{importer.kind !== 'approver' && (
							<Row label="Encryption Sui address" value={truncate(importer.encryptionAddress)} />
						)}
						<Row
							label="Solana key"
							value={truncate(bytesToHex(secretBytes ?? new Uint8Array()), 8, 6)}
							sub={`${secretBytes?.length ?? 0} bytes detected`}
						/>
						<Row
							label="Roster"
							value={
								<ul className="space-y-2 mt-1">
									{orderedMembers.map((m, i) => (
										<li key={i} className="flex flex-col gap-0.5">
											<div className="flex items-baseline gap-3 text-[13px]">
												<span className="font-mono text-[10px] text-text-4 tabular w-6">
													{String(i + 1).padStart(2, '0')}
												</span>
												<span className="text-text-3 smallcaps w-20">
													{m.kind === 'passkey'
														? 'Passkey'
														: m.kind === 'approver'
															? 'Approver'
															: (m.walletName ?? 'Wallet')}
												</span>
												<Mono className="text-[12px]">
													{m.kind === 'passkey' ? truncate(m.publicKeyHex) : truncate(m.address)}
												</Mono>
											</div>
											<div className="pl-[6.5rem] smallcaps text-text-4">
												{m.kind === 'approver'
													? "approver-only — votes, can't execute"
													: `enc ${truncate(m.encryptionAddress, 8, 4)}`}
											</div>
										</li>
									))}
								</ul>
							}
						/>
						<Row label="Recovery package" value={truncate(env.recoveryPackageId)} />
					</div>
				</Card>

				<Card tone="raised" className="lg:col-span-4 p-6 sm:p-7">
					<div className="flex items-baseline justify-between gap-3">
						<span className="smallcaps text-text-2 inline-flex items-center gap-1.5">
							<Wallet className="h-3 w-3" />
							Gas payer
						</span>
						{account && <CopyChip value={account.address} />}
					</div>
					{account ? (
						<>
							<Mono className="block mt-2">{truncate(account.address, 10, 6)}</Mono>
							<div className="mt-4">
								<GasBudgetRow gasPayerAddress={account.address} estimate={ESTIMATE_IMPORT} />
							</div>
							<div className="rule-h my-4" />
							<p className="text-[12.5px] text-text-3 leading-[1.55]">
								This wallet pays for setup gas. It does not have to be a member of the roster —
								member wallets only sign personal messages and don&apos;t need any SUI.
							</p>
						</>
					) : walletReconnecting ? (
						<div className="mt-3 inline-flex items-center gap-1.5 smallcaps text-text-3">
							<Loader2 className="h-3 w-3 animate-spin" />
							Reconnecting wallet…
						</div>
					) : (
						<>
							<p className="mt-3 text-[13px] text-text-2 leading-[1.55]">
								Connect a wallet to pay gas. Sui Wallet, Slush, Phantom, or any zkLogin-backed
								wallet works — and it does not have to be a member of the roster.
							</p>
							<div className="mt-4">
								<WalletConnect align="start" />
							</div>
							<p className="mt-3 inline-flex items-center gap-1.5 smallcaps text-clay">
								<AlertCircle className="h-3 w-3" />
								No wallet connected
							</p>
						</>
					)}
				</Card>
			</div>

			{state.stage === 'error' && (
				<div className="mt-6 surface px-5 py-4 border border-clay/40 bg-clay/[0.05]">
					<div className="flex items-start gap-3">
						<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
						<div className="flex-1 min-w-0">
							<span className="smallcaps text-clay">Submission failed</span>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55] break-words">
								{state.message}
							</p>
							<ErrorGuidance message={state.message} />
						</div>
					</div>
				</div>
			)}

			<StepFooter
				hint={
					submitting
						? 'Do not refresh this page; transactions are in flight.'
						: 'Once you continue, two transactions are submitted to Sui testnet. The recoveryId returned on the next screen is the only handle to your vault.'
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
						disabled={submitting || !secretBytes || initializing || noWallet}
						onClick={handleSubmit}
					>
						{submitting ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Sealing vault ({state.phase})…
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
							walletReconnecting ? (
								<>
									<Loader2 className="h-4 w-4 animate-spin" /> Reconnecting…
								</>
							) : (
								<>
									<Wallet className="h-4 w-4" /> Connect a wallet
								</>
							)
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
					<Check className="h-3 w-3 text-sage" />
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

function Row({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
	return (
		<div className="grid grid-cols-1 md:grid-cols-3 gap-2 px-6 py-4">
			<div className="md:col-span-1 smallcaps text-text-3">{label}</div>
			<div className="md:col-span-2 text-[14px] text-text">
				{typeof value === 'string' ? <Mono>{value}</Mono> : value}
				{sub && <div className="smallcaps text-text-4 mt-1">{sub}</div>}
			</div>
		</div>
	);
}

function parseSecret(input: string): Uint8Array | null {
	const trimmed = input.trim();
	if (!trimmed) return null;
	if (trimmed.startsWith('[')) {
		try {
			const arr = JSON.parse(trimmed) as number[];
			if (!Array.isArray(arr)) return null;
			if (arr.length !== 32 && arr.length !== 64) return null;
			return new Uint8Array(arr);
		} catch {
			return null;
		}
	}
	if (/^(0x)?[0-9a-fA-F]+$/.test(trimmed)) {
		const clean = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
		if (clean.length === 64 || clean.length === 128) {
			const out = new Uint8Array(clean.length / 2);
			for (let i = 0; i < out.length; i++) {
				out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
			}
			return out;
		}
	}
	try {
		return base58Decode(trimmed);
	} catch {
		return null;
	}
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(s: string): Uint8Array {
	let n = 0n;
	for (const ch of s) {
		const idx = B58.indexOf(ch);
		if (idx < 0) throw new Error('bad char');
		n = n * 58n + BigInt(idx);
	}
	const out: number[] = [];
	while (n > 0n) {
		out.unshift(Number(n & 0xffn));
		n >>= 8n;
	}
	for (const ch of s) {
		if (ch !== '1') break;
		out.unshift(0);
	}
	return new Uint8Array(out);
}

function truncate(s: string, head = 10, tail = 6): string {
	if (s.length <= head + tail + 1) return s;
	return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function ErrorGuidance({ message }: { message: string }) {
	const m = message.toLowerCase();
	let hint: string | null = null;
	if (m.includes('insufficient') && m.includes('ika'))
		hint =
			"Top up the gas wallet's IKA balance and resubmit. Setup needs roughly 0.5 IKA on testnet.";
	else if (m.includes('insufficient') && m.includes('sui'))
		hint =
			"Top up the gas wallet's SUI balance and resubmit. Setup needs roughly 0.1 SUI for fees.";
	else if (
		m.includes('reject') ||
		m.includes('denied') ||
		m.includes('user closed') ||
		m.includes('popup')
	)
		hint =
			'Looks like a wallet popup was dismissed. Click Seal the vault again and approve every prompt.';
	else if (
		m.includes('network') ||
		m.includes('rpc') ||
		m.includes('timeout') ||
		m.includes('fetch')
	)
		hint =
			'Network hiccup. Check your connection and resubmit — partial state on chain (if any) is safe to retry.';
	else if (m.includes('session worker') || m.includes('not initialized'))
		hint = 'Refresh the tab so the session worker reinitializes, then try again.';
	else if (m.includes('not in active') || m.includes('dwallet'))
		hint =
			"The dWallet didn't reach Active in time. The Ika network may be slow — wait a minute and resubmit.";
	else if (m.includes('encryption') || m.includes('signature'))
		hint =
			'Encryption identity mismatch. Re-pick the initial user from /setup/connect (or re-add the affected wallet member).';
	if (!hint) return null;
	return (
		<p className="mt-3 text-[12.5px] text-text-3 leading-[1.55] border-t border-border pt-2">
			<span className="smallcaps text-text-2">Try this</span> {hint}
		</p>
	);
}
