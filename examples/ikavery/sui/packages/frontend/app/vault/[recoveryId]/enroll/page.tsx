'use client';

import { Button, Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import type { NewMemberInput } from '@fesal-packages/ikavery-sui-sdk';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { isEnokiWallet } from '@mysten/enoki';
import { fromHex, isValidSuiAddress, normalizeSuiAddress } from '@mysten/sui/utils';
import { useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	ArrowRight,
	CheckCircle2,
	Fingerprint,
	Loader2,
	RotateCcw,
	ShieldCheck,
	UserPlus,
	Wallet,
	X,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { env } from '@/lib/env';
import { ESTIMATE_PROPOSE } from '@/lib/gas-preflight';
import { capturePasskeyMember, captureWalletMember } from '@/lib/member-identity';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { findMember } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import { hexToBytes, saveEnrollmentStash } from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

type MemberType = 'approver' | 'passkey' | 'wallet';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000000000000000000000000000';

type CapturedPasskey = {
	kind: 'passkey';
	publicKeyHex: string;
	credentialIdHex: string;
	encryptionKeysBytesHex: string;
	encryptionAddress: string;
};
type CapturedWalletKeyHolder = {
	kind: 'wallet';
	walletName?: string;
	address: string;
	scheme: 'ed25519' | 'secp256k1' | 'secp256r1';
	publicKeyHex: string;
	encryptionKeysBytesHex: string;
	encryptionAddress: string;
};
type CapturedWalletApprover = {
	kind: 'wallet-approver';
	walletName?: string;
	address: string;
	origin: 'zklogin' | 'multisig' | 'passkey' | 'unknown';
};
type Captured = CapturedPasskey | CapturedWalletKeyHolder | CapturedWalletApprover;

type SubmitStage = 'registering-key' | 'proposing';
type SubmitState =
	| { stage: 'idle' }
	| { stage: 'submitting'; phase: SubmitStage }
	| { stage: 'error'; message: string };

export default function EnrollPage() {
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

	const [memberType, setMemberType] = React.useState<MemberType>('passkey');
	const [addressInput, setAddressInput] = React.useState('');
	const [captured, setCaptured] = React.useState<Captured | null>(null);
	const [submitState, setSubmitState] = React.useState<SubmitState>({
		stage: 'idle',
	});

	function pickType(t: MemberType) {
		setMemberType(t);
		setSubmitState({ stage: 'idle' });
		setCaptured(null);
	}

	// Build the NewMemberInput + encryption-key Sui address from current state.
	const built = React.useMemo<{
		member: NewMemberInput | null;
		encKeyAddress: string;
		error: string | null;
	}>(() => {
		if (memberType === 'approver') {
			const trimmed = addressInput.trim();
			if (!trimmed) return { member: null, encKeyAddress: ZERO_ADDR, error: null };
			if (!isValidSuiAddress(trimmed)) {
				return {
					member: null,
					encKeyAddress: ZERO_ADDR,
					error: 'Doesn’t look like a valid Sui address.',
				};
			}
			return {
				member: {
					scheme: 'sender_address',
					address: normalizeSuiAddress(trimmed),
				},
				encKeyAddress: ZERO_ADDR,
				error: null,
			};
		}

		if (!captured) return { member: null, encKeyAddress: ZERO_ADDR, error: null };

		if (captured.kind === 'wallet-approver') {
			// Wallet without a stable signing key (zkLogin / MultiSig / passkey-as-
			// sender). Falls through as approver-only with the wallet's address.
			return {
				member: {
					scheme: 'sender_address',
					address: normalizeSuiAddress(captured.address),
				},
				encKeyAddress: ZERO_ADDR,
				error: null,
			};
		}

		if (captured.kind === 'passkey') {
			return {
				member: {
					scheme: 'webauthn',
					publicKey: hexToBytes(captured.publicKeyHex),
				},
				encKeyAddress: normalizeSuiAddress(captured.encryptionAddress),
				error: null,
			};
		}

		return {
			member: {
				scheme: captured.scheme,
				publicKey: hexToBytes(captured.publicKeyHex),
			},
			encKeyAddress: normalizeSuiAddress(captured.encryptionAddress),
			error: null,
		};
	}, [memberType, addressInput, captured]);

	const alreadyMember = React.useMemo(() => {
		if (!vault.data || !built.member) return false;
		if (built.member.scheme === 'sender_address') {
			return !!findMember(
				vault.data,
				'sender_address',
				fromHex(normalizeSuiAddress(built.member.address).slice(2)),
			);
		}
		return !!findMember(vault.data, built.member.scheme, built.member.publicKey);
	}, [vault.data, built]);

	const inputError = built.error ?? (alreadyMember ? 'This identity is already a member.' : null);

	async function handleSubmit() {
		if (!session || !suiClient || !vault.data || !built.member) return;
		if (!signerState.state.ready || !signerState.state.active || !signerState.state.gasPayer) {
			setSubmitState({
				stage: 'error',
				message: 'Pick a signer and a gas payer first.',
			});
			return;
		}
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;

		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});

			// For key-holder enrollments (passkey / wallet), the new device's
			// class-groups encryption key has to live on Ika before execute can
			// re-encrypt the share to it. Idempotent: a no-op when already
			// registered. Approver-only members skip — there's no encryption key.
			if (captured && (captured.kind === 'passkey' || captured.kind === 'wallet')) {
				// Persist the captured keys before any tx — if the register tx fails
				// partway, the executor can still recover by replaying register +
				// execute from the stash.
				await saveEnrollmentStash({
					recoveryId,
					encryptionAddress: captured.encryptionAddress,
					encryptionKeysBytesHex: captured.encryptionKeysBytesHex,
				});
				setSubmitState({ stage: 'submitting', phase: 'registering-key' });
				await session.runRegisterDeviceEncryptionKey({
					walletAddress: gasPayer.address,
					signAndExecute,
					newDeviceKeyBytes: hexToBytes(captured.encryptionKeysBytesHex),
				});
			}

			setSubmitState({ stage: 'submitting', phase: 'proposing' });
			const result = await session.runProposeEnrollment({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				newMember: built.member,
				newEncryptionKeyAddress: built.encKeyAddress,
				authIdentity: signerOptionToIdentity(active),
			});
			await queryClient.invalidateQueries({ queryKey: ['vault', recoveryId] });
			router.push(`/vault/${recoveryId}/enroll/${result.enrollmentId}`);
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
				<span className="smallcaps text-text-3">Enrollment</span>
				<h1 className="mt-2 font-display text-[34px] sm:text-[40px] leading-[1.04] text-text">
					Add a member
				</h1>
				<p className="mt-3 text-[14px] text-text-2 leading-[1.6] max-w-[640px]">
					Enroll a passkey, connect a wallet, or paste a Sui address. Passkey / wallet members can
					hold a share and execute recoveries; approver-only members vote on proposals via{' '}
					<span className="font-mono text-[12.5px]">ctx.sender</span> match.
				</p>
			</header>

			<div className="grid grid-cols-3 gap-2 mb-4">
				<TypeTab
					active={memberType === 'passkey'}
					onClick={() => pickType('passkey')}
					icon={<Fingerprint className="h-3.5 w-3.5" />}
					label="Passkey"
					hint="WebAuthn ceremony · key-holder"
				/>
				<TypeTab
					active={memberType === 'wallet'}
					onClick={() => pickType('wallet')}
					icon={<Wallet className="h-3.5 w-3.5" />}
					label="Wallet"
					hint="Connect & sign · key-holder"
				/>
				<TypeTab
					active={memberType === 'approver'}
					onClick={() => pickType('approver')}
					icon={<ShieldCheck className="h-3.5 w-3.5" />}
					label="Approver only"
					hint="Sui address · vote-only"
				/>
			</div>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border">
					<span className="smallcaps text-text-3">New member</span>
				</div>
				<div className="px-5 sm:px-8 py-5 space-y-4">
					{memberType === 'passkey' && (
						<PasskeyCapture captured={captured} onCaptured={setCaptured} />
					)}
					{memberType === 'wallet' && (
						<WalletCapture wallets={wallets} captured={captured} onCaptured={setCaptured} />
					)}
					{memberType === 'approver' && (
						<ApproverFields addressInput={addressInput} setAddressInput={setAddressInput} />
					)}

					{inputError && (
						<p className="text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
							<AlertCircle className="h-3 w-3" />
							{inputError}
						</p>
					)}

					{memberType !== 'approver' && captured?.kind !== 'wallet-approver' && captured && (
						<p className="text-[12px] text-text-3 leading-[1.55]">
							Submit will run two transactions: first register this identity&apos;s class-groups
							encryption key on Ika, then post the enrollment proposal.
						</p>
					)}
				</div>
			</Card>

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
						!built.member ||
						alreadyMember ||
						!signerState.state.ready ||
						submitState.stage === 'submitting'
					}
					onClick={handleSubmit}
				>
					{submitState.stage === 'submitting' ? (
						<>
							<Loader2 className="h-4 w-4 animate-spin" />
							{submitState.phase === 'registering-key'
								? 'Registering encryption key…'
								: 'Proposing enrollment…'}
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

// ===== sub-components =====

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

function ApproverFields({
	addressInput,
	setAddressInput,
}: {
	addressInput: string;
	setAddressInput: (v: string) => void;
}) {
	return (
		<div>
			<label className="smallcaps text-text-3 block mb-2">Sui address</label>
			<input
				type="text"
				inputMode="text"
				autoComplete="off"
				spellCheck={false}
				placeholder="0x…"
				value={addressInput}
				onChange={(e) => setAddressInput(e.target.value)}
				className="w-full font-mono text-[13px] tabular bg-surface-2 border border-border rounded-md px-3 py-2.5 focus:outline-none focus:border-clay/60"
			/>
			<p className="mt-2 text-[12px] text-text-3 leading-[1.55]">
				Any Sui address — including zkLogin / Sign-in-with-Google. Approver-only members can vote on
				proposals but cannot execute recoveries.
			</p>
		</div>
	);
}

function PasskeyCapture({
	captured,
	onCaptured,
}: {
	captured: Captured | null;
	onCaptured: (c: Captured | null) => void;
}) {
	const [busy, setBusy] = React.useState(false);
	const [error, setError] = React.useState<string | null>(null);
	const isReady = captured?.kind === 'passkey';

	async function handle() {
		setBusy(true);
		setError(null);
		try {
			const m = await capturePasskeyMember('recovery-member');
			onCaptured({
				kind: 'passkey',
				publicKeyHex: m.publicKeyHex,
				credentialIdHex: m.credentialIdHex,
				encryptionKeysBytesHex: m.encryptionKeysBytesHex,
				encryptionAddress: m.encryptionAddress,
			});
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			if (
				!msg.toLowerCase().includes('cancel') &&
				!msg.toLowerCase().includes('reject') &&
				!msg.toLowerCase().includes('aborted')
			) {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}

	if (isReady && captured.kind === 'passkey') {
		return (
			<CapturedReadout
				title="Passkey ready"
				rows={[
					{ label: 'pubkey', value: captured.publicKeyHex },
					{ label: 'encryption', value: captured.encryptionAddress },
				]}
				onReset={() => onCaptured(null)}
			/>
		);
	}

	return (
		<div>
			<p className="text-[13px] text-text-2 leading-[1.55] mb-3">
				Run a WebAuthn ceremony on this device. The browser creates a new passkey bound to{' '}
				<span className="font-mono text-[12px]">{env.rpId}</span>; we extract the PRF output, derive
				an Ika encryption identity from it, and propose the resulting{' '}
				<span className="font-mono text-[12px]">webauthn</span> public key + encryption-key Sui
				address as the new member.
			</p>
			{error && (
				<p className="mb-3 text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
					<AlertCircle className="h-3 w-3" />
					{error}
				</p>
			)}
			<Button variant="primary" size="lg" onClick={handle} disabled={busy}>
				{busy ? (
					<>
						<Loader2 className="h-4 w-4 animate-spin" />
						Waiting for authenticator…
					</>
				) : (
					<>
						<Fingerprint className="h-4 w-4" />
						Use a passkey
					</>
				)}
			</Button>
		</div>
	);
}

function WalletCapture({
	wallets,
	captured,
	onCaptured,
}: {
	wallets: readonly UiWallet[];
	captured: Captured | null;
	onCaptured: (c: Captured | null) => void;
}) {
	const [busy, setBusy] = React.useState(false);
	const [pickerOpen, setPickerOpen] = React.useState(false);
	const [error, setError] = React.useState<string | null>(null);
	const isReady = captured?.kind === 'wallet' || captured?.kind === 'wallet-approver';

	const compatible = React.useMemo(
		() => wallets.filter((w) => w.features.includes('sui:signPersonalMessage')),
		[wallets],
	);

	async function handlePick(wallet: UiWallet) {
		setBusy(true);
		setError(null);
		try {
			if (isEnokiWallet(wallet) && wallet.accounts.length > 0) {
				await dAppKit.disconnectWallet();
			}
			let accounts = wallet.accounts;
			if (accounts.length === 0) {
				// dApp Kit 2 drives the wallet-standard features itself; reaching into
				// `wallet.features` is no longer possible, since a UiWallet only names
				// them.
				const res = await dAppKit.connectWallet({ wallet });
				accounts = res.accounts;
			}
			const account: UiWalletAccount | undefined = accounts[0];
			if (!account) {
				throw new Error(`${wallet.name} did not return any accounts.`);
			}
			const m = await captureWalletMember(wallet, account);
			if (m.kind === 'wallet') {
				onCaptured({
					kind: 'wallet',
					walletName: m.walletName,
					address: m.address,
					scheme: m.scheme,
					publicKeyHex: m.publicKeyHex,
					encryptionKeysBytesHex: m.encryptionKeysBytesHex,
					encryptionAddress: m.encryptionAddress,
				});
			} else {
				onCaptured({
					kind: 'wallet-approver',
					walletName: m.walletName,
					address: m.address,
					origin: m.origin,
				});
			}
			setPickerOpen(false);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			if (!msg.toLowerCase().includes('cancel') && !msg.toLowerCase().includes('reject')) {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}

	if (isReady && captured.kind === 'wallet') {
		return (
			<CapturedReadout
				title={captured.walletName ? `Wallet · ${captured.walletName}` : 'Wallet ready'}
				rows={[
					{ label: 'address', value: captured.address },
					{ label: 'scheme', value: captured.scheme },
					{ label: 'pubkey', value: captured.publicKeyHex },
					{ label: 'encryption', value: captured.encryptionAddress },
				]}
				onReset={() => onCaptured(null)}
			/>
		);
	}
	if (isReady && captured.kind === 'wallet-approver') {
		return (
			<CapturedReadout
				title={`Approver-only wallet · ${captured.walletName ?? captured.origin}`}
				note={`This wallet is ${captured.origin} — no stable signing key, so it'll be added as an approver-only member (vote, no execute).`}
				rows={[{ label: 'address', value: captured.address }]}
				onReset={() => onCaptured(null)}
			/>
		);
	}

	if (!pickerOpen) {
		return (
			<div>
				<p className="text-[13px] text-text-2 leading-[1.55] mb-3">
					Connect any Sui wallet that supports{' '}
					<span className="font-mono text-[12px]">signPersonalMessage</span>. The wallet signs a
					fixed app-scoped message, we hash that signature into a 32-byte seed, and derive an Ika
					encryption identity. The same wallet always derives the same identity.
				</p>
				{error && (
					<p className="mb-3 text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
						<AlertCircle className="h-3 w-3" />
						{error}
					</p>
				)}
				<Button variant="primary" size="lg" onClick={() => setPickerOpen(true)} disabled={busy}>
					<Wallet className="h-4 w-4" />
					Use a wallet
				</Button>
			</div>
		);
	}

	return (
		<div className="surface p-2 space-y-1">
			{error && (
				<p className="px-3 py-2 text-[12.5px] text-clay leading-[1.5] inline-flex items-center gap-1.5">
					<AlertCircle className="h-3 w-3" />
					{error}
				</p>
			)}
			{compatible.length === 0 ? (
				<p className="px-3 py-4 text-[12.5px] text-text-3">
					No Sui wallets detected. Install Slush, Sui Wallet, Phantom, or any Sui-compatible wallet,
					then refresh this page.
				</p>
			) : (
				compatible.map((w) => (
					<button
						key={w.name}
						type="button"
						onClick={() => handlePick(w)}
						disabled={busy}
						className="w-full text-left flex items-center gap-3 px-3 py-2 rounded-md hover:bg-surface-3 transition-colors disabled:opacity-50"
					>
						{w.icon && (
							// eslint-disable-next-line @next/next/no-img-element
							<img src={w.icon} alt="" className="h-5 w-5 rounded-sm flex-none" />
						)}
						<span className="text-[13px] text-text">{w.name}</span>
						<span className="ml-auto smallcaps text-text-4">
							{isEnokiWallet(w)
								? 'connect'
								: w.accounts[0]
									? `${w.accounts[0].address.slice(0, 6)}…${w.accounts[0].address.slice(-4)}`
									: 'connect'}
						</span>
					</button>
				))
			)}
			<button
				type="button"
				onClick={() => setPickerOpen(false)}
				disabled={busy}
				className="mt-1 w-full text-center smallcaps text-text-4 hover:text-text py-2"
			>
				Cancel
			</button>
			{busy && (
				<div className="px-3 py-2 inline-flex items-center gap-2 smallcaps text-text-3">
					<Loader2 className="h-3 w-3 animate-spin" />
					Waiting for wallet…
				</div>
			)}
		</div>
	);
}

function CapturedReadout({
	title,
	rows,
	note,
	onReset,
}: {
	title: string;
	rows: { label: string; value: string }[];
	note?: string;
	onReset: () => void;
}) {
	return (
		<div className="surface px-4 py-4 space-y-3">
			<div className="flex items-center justify-between">
				<span className="smallcaps text-sage inline-flex items-center gap-1.5">
					<CheckCircle2 className="h-3 w-3" />
					{title}
				</span>
				<button
					type="button"
					onClick={onReset}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
				>
					<RotateCcw className="h-3 w-3" />
					Reset
				</button>
			</div>
			<ul className="space-y-1.5">
				{rows.map((r) => (
					<li
						key={r.label}
						className="flex flex-col sm:flex-row sm:items-baseline gap-x-3 gap-y-0.5"
					>
						<span className="smallcaps text-text-3 sm:w-24 flex-none">{r.label}</span>
						<span className="font-mono text-[12px] tabular text-text break-all">{r.value}</span>
					</li>
				))}
			</ul>
			{note && (
				<p className="text-[12px] text-text-3 leading-[1.55] inline-flex items-start gap-1.5">
					<X className="h-3 w-3 mt-0.5 text-clay" />
					{note}
				</p>
			)}
		</div>
	);
}
