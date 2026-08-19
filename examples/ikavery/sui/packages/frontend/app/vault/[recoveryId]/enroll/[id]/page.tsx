'use client';

import { Button, Card, ProposalDetailSkeleton } from '@fesal-packages/ikavery-frontend-ui';
import { readEnrollment, type EnrollmentSnapshot } from '@fesal-packages/ikavery-sui-sdk';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { normalizeSuiAddress } from '@mysten/sui/utils';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	CheckCircle2,
	Loader2,
	Send,
	Signature,
	UserPlus,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { findMyEncryptedShareId } from '@/lib/encrypted-share-discovery';
import { env } from '@/lib/env';
import { bytesToHex } from '@/lib/format';
import { ESTIMATE_APPROVE, ESTIMATE_ENROLL_EXECUTE } from '@/lib/gas-preflight';
import { buildIkaClient, buildRecoveryClient } from '@/lib/recovery-client';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { bytesEq } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import {
	appendSavedVault,
	hexToBytes,
	loadActiveImporter,
	loadEnrollmentStash,
	loadSavedVaults,
	type CachedImporter,
	type SavedVault,
} from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

type ActionState =
	| { stage: 'idle' }
	| { stage: 'approving' }
	| { stage: 'executing' }
	| { stage: 'done' }
	| { stage: 'error'; message: string };

export default function EnrollmentDetailPage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const enrollmentIdStr = params.id;
	const enrollmentId = React.useMemo(() => {
		try {
			return BigInt(enrollmentIdStr);
		} catch {
			return null;
		}
	}, [enrollmentIdStr]);

	const { suiClient, session } = useRecoveryClient();
	const wallets = useWallets();
	const { wallet: currentWallet } = useWalletConnection();
	const walletSign = dAppKit.signTransaction;
	const queryClient = useQueryClient();

	const vault = useVaultQuery(recoveryId);

	const snapshot = useQuery({
		queryKey: ['enrollment', recoveryId, enrollmentIdStr, suiClient ? 'ready' : '_'],
		queryFn: async (): Promise<EnrollmentSnapshot> => {
			const recClient = buildRecoveryClient(suiClient!, recoveryId);
			return await readEnrollment(recClient, enrollmentId!);
		},
		enabled: !!suiClient && enrollmentId !== null,
		refetchInterval: 4_000,
	});

	const signerState = useSignerState(vault.data);

	const [actionState, setActionState] = React.useState<ActionState>({
		stage: 'idle',
	});
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	const [savedVault, setSavedVault] = React.useState<SavedVault | null>(null);
	React.useEffect(() => {
		void (async () => {
			setCachedImporter(await loadActiveImporter());
			const vaults = await loadSavedVaults();
			setSavedVault(vaults.find((v) => v.recoveryId === recoveryId) ?? null);
		})();
	}, [recoveryId]);

	async function handleApprove() {
		if (!session || !suiClient || !snapshot.data || enrollmentId === null) return;
		if (!signerState.state.ready || !signerState.state.active || !signerState.state.gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a signer and a gas payer first.',
			});
			return;
		}
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;
		setActionState({ stage: 'approving' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			await session.runApproveEnrollment({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				enrollmentId: enrollmentIdStr,
				authIdentity: signerOptionToIdentity(active),
			});
			setActionState({ stage: 'idle' });
			await queryClient.invalidateQueries({
				queryKey: ['enrollment', recoveryId, enrollmentIdStr],
			});
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	async function handleExecute() {
		if (!session || !suiClient || !snapshot.data || !vault.data || enrollmentId === null) return;
		if (!signerState.state.ready || !signerState.state.gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a gas payer first.',
			});
			return;
		}
		const gasPayer = signerState.state.gasPayer;
		setActionState({ stage: 'executing' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			if (snapshot.data.approverOnly) {
				await session.runExecuteApproverEnrollment({
					walletAddress: gasPayer.address,
					signAndExecute,
					recoveryId,
					enrollmentId: enrollmentIdStr,
				});
			} else {
				if (!cachedImporter) {
					throw new Error(
						'No importer cached on this device — key-holder execute needs the same passkey/wallet that holds a share for this vault.',
					);
				}

				// Pre-flight: confirm the new member's encryption key is registered
				// on Ika. If not, try to register it from the stash (when this is
				// the same browser that ran propose). Otherwise surface a clear
				// error — re-proposing is the only path forward.
				const ikaClient = buildIkaClient(suiClient);
				const destAddress = normalizeSuiAddress(snapshot.data.newEncryptionKeyAddress);
				let registered = false;
				try {
					await ikaClient.getActiveEncryptionKey(destAddress);
					registered = true;
				} catch {
					/* not registered yet */
				}
				if (!registered) {
					const stash = await loadEnrollmentStash(recoveryId, destAddress);
					if (!stash) {
						throw new Error(
							"The new member's encryption key isn't registered on Ika and we don't have its keys cached on this device. Re-propose the enrollment from the device that captured the passkey/wallet.",
						);
					}
					await session.runRegisterDeviceEncryptionKey({
						walletAddress: gasPayer.address,
						signAndExecute,
						newDeviceKeyBytes: hexToBytes(stash.encryptionKeysBytesHex),
					});
				}

				const importerKeyBytes = hexToBytes(cachedImporter.encryptionKeysBytesHex);
				let encryptedUserShareId = savedVault?.myEncryptedUserShareId ?? null;
				if (!encryptedUserShareId) {
					encryptedUserShareId = await findMyEncryptedShareId(
						suiClient,
						vault.data.dwalletId,
						cachedImporter.encryptionAddress,
					);
					if (!encryptedUserShareId) {
						throw new Error(
							"Couldn't find this device's encrypted share on the dWallet. Are you sure this device is a key-holder member of this vault?",
						);
					}
					// Cache it for next time so we skip the scan.
					await appendSavedVault({
						recoveryId,
						dwalletId: vault.data.dwalletId,
						threshold: vault.data.threshold,
						totalMembers: vault.data.members.length,
						createdAt: savedVault?.createdAt ?? Date.now(),
						myEncryptedUserShareId: encryptedUserShareId,
					});
				}
				await session.runExecuteKeyHolderEnrollment({
					walletAddress: gasPayer.address,
					signAndExecute,
					recoveryId,
					enrollmentId: enrollmentIdStr,
					importerKeyBytes,
					encryptedUserShareId,
					newEncryptionKeyAddress: snapshot.data.newEncryptionKeyAddress,
				});
			}
			setActionState({ stage: 'done' });
			await queryClient.invalidateQueries({
				queryKey: ['enrollment', recoveryId, enrollmentIdStr],
			});
			await queryClient.invalidateQueries({
				queryKey: ['vault', recoveryId],
			});
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	if (enrollmentId === null) {
		return <ErrorShell recoveryId={recoveryId} message="Invalid enrollment id." />;
	}

	if (snapshot.isLoading || !snapshot.data || !vault.data) {
		return (
			<ProposalDetailSkeleton
				recoveryId={recoveryId}
				idStr={enrollmentIdStr}
				kindLabel="Enrollment"
				kindAccent="text-text-3"
				Icon={UserPlus}
			/>
		);
	}

	const snap = snapshot.data;
	const threshold = vault.data.threshold;
	const approvalsNum = Number(snap.approvals);
	const reachedThreshold = approvalsNum >= threshold;
	const memberRendered = renderNewMember(snap);

	const myMemberId = signerState.state.active?.member.id ?? null;
	const alreadyVoted = myMemberId ? snap.voters.some((v) => bytesEq(v, myMemberId)) : false;

	return (
		<div className="max-w-[820px] mx-auto py-10">
			<button
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<UserPlus className="h-3 w-3" />
					Enrollment #{enrollmentIdStr}
				</div>
				<h1 className="mt-2 font-display text-[32px] sm:text-[38px] leading-[1.05] text-text">
					{snap.executed ? 'Enrollment complete' : 'Add a new member'}
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
					{snap.approverOnly && (
						<p className="mt-3 text-[12.5px] text-text-3 leading-[1.55]">
							Approver-only — auth via <span className="font-mono text-[12px]">ctx.sender</span>{' '}
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
						{approvalsNum} / {threshold}
					</span>
				</div>
			</Card>

			{/* Signer + gas-payer.
          Once quorum's reached the next click is Execute — for key-holder
          enrollments the executor's wallet has to front the ~500M IKA fee
          for `request_re_encrypt_user_share_for`. Approver-only execute
          stays cheap (no Ika operation), so we keep the cheaper estimate
          there. */}
			{!snap.executed && (
				<div className="mt-4">
					<SignerGasPayerCard
						vault={vault.data}
						state={signerState.state}
						onPickSigner={signerState.pickSigner}
						onPickGas={signerState.pickGas}
						estimate={
							reachedThreshold && !snap.approverOnly ? ESTIMATE_ENROLL_EXECUTE : ESTIMATE_APPROVE
						}
					/>
				</div>
			)}

			{/* Action footer */}
			{!snap.executed && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{actionState.stage === 'error' && (
						<p className="flex-1 text-[12.5px] text-clay leading-[1.5]">{actionState.message}</p>
					)}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!signerState.state.ready ||
							alreadyVoted ||
							reachedThreshold ||
							actionState.stage === 'approving' ||
							actionState.stage === 'executing'
						}
						onClick={handleApprove}
					>
						{actionState.stage === 'approving' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Approving…
							</>
						) : alreadyVoted ? (
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
						disabled={
							!reachedThreshold ||
							!signerState.state.gasPayer ||
							actionState.stage === 'executing' ||
							actionState.stage === 'approving'
						}
						onClick={handleExecute}
					>
						{actionState.stage === 'executing' ? (
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

			{!snap.approverOnly && !snap.executed && (
				<Card tone="raised" className="mt-4 px-6 py-4 border-border">
					<p className="text-[12.5px] text-text-3 leading-[1.55] inline-flex items-start gap-2">
						<AlertCircle className="h-3.5 w-3.5 text-text-3 flex-none mt-0.5" />
						<span>
							Key-holder execute decrypts this device&apos;s share locally and re-encrypts it to the
							new member. This device must already be a key-holder member of the vault (carries an
							encrypted share).
						</span>
					</p>
				</Card>
			)}

			{snap.executed && (
				<Card tone="raised" className="mt-6 px-6 py-5 border-sage/40">
					<div className="flex items-start gap-3">
						<CheckCircle2 className="h-4 w-4 text-sage mt-0.5 flex-none" />
						<div>
							<div className="smallcaps text-sage">Member added</div>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55]">
								The new member is in the roster and can vote on future proposals.
							</p>
						</div>
					</div>
				</Card>
			)}
		</div>
	);
}

// ===== helpers =====

function renderNewMember(snap: EnrollmentSnapshot): {
	kindLabel: string;
	identity: string;
} {
	switch (snap.newMember.kind) {
		case 'ed25519':
			return {
				kindLabel: 'Wallet · ed25519',
				identity: bytesToHex(snap.newMember.publicKey),
			};
		case 'secp256k1':
			return {
				kindLabel: 'Wallet · secp256k1',
				identity: bytesToHex(snap.newMember.publicKey),
			};
		case 'secp256r1':
			return {
				kindLabel: 'Wallet · secp256r1',
				identity: bytesToHex(snap.newMember.publicKey),
			};
		case 'webauthn':
			return {
				kindLabel: 'Passkey',
				identity: bytesToHex(snap.newMember.publicKey),
			};
		case 'sender_address':
			return {
				kindLabel: 'Approver-only · Sui address',
				identity: snap.newMember.address,
			};
	}
}
