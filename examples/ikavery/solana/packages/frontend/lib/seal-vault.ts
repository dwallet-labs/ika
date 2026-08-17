'use client';

import type { Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import {
	buildCreateRecoveryIx,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	packMemberSlot,
	packSolanaMember,
	SCHEME_WEBAUTHN,
} from '@fesal-packages/ikavery-solana-sdk';
import {
	Connection,
	Keypair,
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
} from '@solana/web3.js';

import { SOLANA_RPC } from '@/lib/env';
import { ikaDkgWeb } from '@/lib/ika-web';
import type { SealedResult, SealPhase, StoredMember } from '@/store/setup';

import { hexToBytes, saveDkgBundle } from './storage';

const {
	CURVE_CURVE25519,
	buildTransferDwalletAuthorityIx,
	cpiAuthorityPda,
	dwalletPda,
	DWALLET_DISC,
} = ikaDwallet;

interface SealVaultParams {
	/** Connected Solana wallet; pays gas + signs the dWallet authority transfer. */
	primaryWallet: Wallet;
	/** The identity that authorises the on-chain create — passkey or wallet. */
	importer: StoredMember;
	members: StoredMember[];
	threshold: number;
	/** Discarded on pre-alpha (DKG generates fresh) — kept for future import. */
	solanaSecretKey: Uint8Array;
	onProgress?: (phase: SealPhase, detail?: string) => void;
}

function packMember(m: StoredMember): Uint8Array {
	if (m.kind === 'passkey') {
		return packMemberSlot(SCHEME_WEBAUTHN, hexToBytes(m.publicKeyHex));
	}
	return packSolanaMember(new PublicKey(m.address));
}

/**
 * Drives the four-step seal:
 *   1. browser-side gRPC-Web DKG → dWallet pubkey + attestation
 *   2. wait for the dWallet PDA to materialise on-chain
 *   3. transferAuthority(dWallet → ikavery CPI PDA) signed by importer
 *   4. create_recovery, signed by importer + ephemeral recoveryId keypair
 *
 * Two on-chain transactions; both signed via Dynamic's Solana signer. The
 * DKG bundle is persisted to IndexedDB so the recovery flow can reuse it
 * without rerunning DKG.
 */
export async function sealVault(params: SealVaultParams): Promise<SealedResult> {
	const { primaryWallet, importer, members, threshold, onProgress } = params;
	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer. Reconnect to continue.");
	}
	if (members.length < 1) {
		throw new Error('members must contain at least the importer');
	}
	// Member 0 is always the importer; the connect step enforces this.
	// The wallet that pays for setup gas may differ from the importer (when
	// the importer is a passkey).
	const gasPayer = new PublicKey(primaryWallet.address);

	const connection = new Connection(SOLANA_RPC, 'confirmed');

	// ── 1. DKG via gRPC-Web (browser → ika tonic gateway) ───────────────────
	// The pre-alpha mock signer wants a Solana pubkey to bind the session to;
	// we use the connected wallet here. (The on-chain `Recovery` is gated on
	// the importer's credential, not on this sender pubkey.)
	onProgress?.('dkg');
	const dkg = await ikaDkgWeb(gasPayer.toBytes());
	const dwalletSolPubkey = new PublicKey(dkg.publicKey);
	const dwalletPubkeyBytes = dwalletSolPubkey.toBytes();
	const { pda: dwalletAccount } = dwalletPda(CURVE_CURVE25519, dwalletPubkeyBytes);

	// ── 2. Wait for the dWallet PDA on-chain ────────────────────────────────
	onProgress?.('awaiting-pda');
	await pollForPda(connection, dwalletAccount, 30_000);

	const signer = await primaryWallet.getSigner();

	// ── 3. transferAuthority(dWallet → ikavery CPI authority) ───────────────
	onProgress?.('transfer-authority');
	const { pda: cpiAuthority } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
	const transferIx = buildTransferDwalletAuthorityIx({
		currentAuthority: gasPayer,
		dwallet: dwalletAccount,
		newAuthority: cpiAuthority,
	});
	const tx1 = await buildVersionedTx(connection, gasPayer, [transferIx]);
	const signed1 = await signer.signTransaction(tx1);
	await sendAndConfirm(connection, signed1);

	// ── 4. create_recovery (creator + ephemeral recoveryId nonce keypair) ───
	onProgress?.('create-recovery');
	const recoveryIdKp = Keypair.generate();
	const memberSlots = members.map(packMember);
	const { ix: createIx, recovery } = buildCreateRecoveryIx({
		creator: gasPayer,
		recoveryId: recoveryIdKp.publicKey,
		dwallet: dwalletPubkeyBytes,
		dwalletCurve: CURVE_CURVE25519,
		threshold,
		members: memberSlots,
	});
	const tx2 = await buildVersionedTx(connection, gasPayer, [createIx]);
	// recoveryId keypair signs locally — it's an ephemeral nonce we never
	// surface again. Then the wallet adds its signature.
	tx2.sign([recoveryIdKp]);
	const signed2 = await signer.signTransaction(tx2);
	const sig2 = await sendAndConfirm(connection, signed2);

	// Persist the DKG bundle so the recovery flow can reach the same dWallet
	// (Phase 4) without re-running DKG. Keyed by recovery PDA.
	await saveDkgBundle({
		recovery: recovery.toBase58(),
		recoveryId: recoveryIdKp.publicKey.toBase58(),
		dwalletPubkey: dwalletSolPubkey.toBase58(),
		dwalletAccount: dwalletAccount.toBase58(),
		senderPubkey: gasPayer.toBase58(),
		attestationDataHex: bytesToHex(dkg.attestationData),
		networkSignatureHex: bytesToHex(dkg.networkSignature),
		networkPubkeyHex: bytesToHex(dkg.networkPubkey),
		sealedAt: Date.now(),
	});
	// Reference: importer is preserved in the persisted setup store so any
	// later flow knows whether to drive a WebAuthn assertion.
	void importer;

	onProgress?.('done');
	return {
		recovery: recovery.toBase58(),
		recoveryId: recoveryIdKp.publicKey.toBase58(),
		dwalletPubkey: dwalletSolPubkey.toBase58(),
		dwalletAccount: dwalletAccount.toBase58(),
		signature: sig2,
		recommendedFundingLamports: 50_000_000,
	};
}

async function buildVersionedTx(
	connection: Connection,
	payer: PublicKey,
	instructions: import('@solana/web3.js').TransactionInstruction[],
): Promise<VersionedTransaction> {
	const { blockhash } = await connection.getLatestBlockhash('confirmed');
	const message = new TransactionMessage({
		payerKey: payer,
		recentBlockhash: blockhash,
		instructions,
	}).compileToV0Message();
	return new VersionedTransaction(message);
}

async function sendAndConfirm(connection: Connection, tx: VersionedTransaction): Promise<string> {
	const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
	const sig = await connection.sendRawTransaction(tx.serialize(), {
		skipPreflight: false,
		preflightCommitment: 'confirmed',
	});
	await connection.confirmTransaction(
		{ signature: sig, blockhash, lastValidBlockHeight },
		'confirmed',
	);
	return sig;
}

async function pollForPda(
	connection: Connection,
	pda: PublicKey,
	timeoutMs: number,
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		const info = await connection.getAccountInfo(pda, 'confirmed');
		if (info && info.data.length > 2 && info.data[0] === DWALLET_DISC) return;
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(
		`dWallet PDA ${pda.toBase58()} did not materialize within ${timeoutMs / 1000}s — Ika network may be slow, retry`,
	);
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
