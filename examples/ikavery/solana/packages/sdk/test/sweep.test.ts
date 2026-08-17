/**
 * litesvm e2e: 1-of-1 sweep happy path, both single-tx and multi-ix shapes.
 *
 * Walks the full propose/approve flow against the real ikavery.so:
 *   create_recovery → propose → approve → assert on-chain state.
 *
 * `execute` is intentionally skipped — it does a CPI into the ika dWallet
 * coordinator which isn't loaded into this SVM. That validation happens
 * in the Rust integration tests
 * (`execute_can_be_fired_by_any_signer_once_approved`); a dWallet-aware
 * litesvm e2e is a separate task.
 */

import { resolve } from 'node:path';
import {
	appendTransactionMessageInstruction,
	createTransactionMessage,
	generateKeyPairSigner,
	lamports,
	pipe,
	setTransactionMessageFeePayerSigner,
	signTransactionMessageWithSigners,
	type TransactionSigner,
} from '@solana/kit';
import { PublicKey } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';
import { LiteSVM } from 'litesvm';

import {
	buildApproveIx,
	buildCreateRecoveryIx,
	buildProposeIx,
	buildSweepMessage,
	createIdempotentAta,
	decodeProposal,
	decodeRecovery,
	IKAVERY_PROGRAM_ID,
	packSolanaMember,
	SCHEME_SOLANA_ADDRESS,
	STATUS_APPROVED,
	TOKEN_PROGRAM_ID,
	transferSol,
	transferSplTokenChecked,
} from '../src';
import { toKitIx } from './util';

const PROGRAM_SO = resolve(import.meta.dir, '../../program/target/deploy/ikavery.so');

function newSvm(): LiteSVM {
	const svm = new LiteSVM().withSysvars().withBuiltins().withPrecompiles();
	svm.addProgramFromFile(IKAVERY_PROGRAM_ID.toBase58() as any, PROGRAM_SO);
	return svm;
}

async function makeFunded(svm: LiteSVM): Promise<{
	signer: TransactionSigner;
	pubkey: PublicKey;
}> {
	const signer = await generateKeyPairSigner();
	svm.airdrop(signer.address, lamports(10_000_000_000n));
	return { signer, pubkey: new PublicKey(signer.address) };
}

/** Build → sign → send. `extraSigners` for signer accounts beyond the fee payer. */
async function sendIx(
	svm: LiteSVM,
	feePayer: TransactionSigner,
	ix: import('@solana/web3.js').TransactionInstruction,
	extraSigners: Record<string, TransactionSigner> = {},
) {
	const kitIx = toKitIx(ix, extraSigners);
	const txMessage = pipe(
		createTransactionMessage({ version: 0 }),
		(m) => setTransactionMessageFeePayerSigner(feePayer, m),
		(m) => svm.setTransactionMessageLifetimeUsingLatestBlockhash(m),
		(m) => appendTransactionMessageInstruction(kitIx, m),
	);
	const tx = await signTransactionMessageWithSigners(txMessage);
	const result = svm.sendTransaction(tx);
	if (typeof (result as any).err === 'function') {
		const err = (result as any).err();
		const meta = (result as any).meta?.();
		const logs: string[] = meta?.logs?.() ?? [];
		throw new Error(`transaction failed: ${JSON.stringify(err)}\nlogs:\n${logs.join('\n')}`);
	}
	return result;
}

// TODO: this litesvm e2e suite predates the bundle rewrite (one proposal
// commits to N intent digests instead of carrying message bytes inline).
// The live devnet e2e scripts in `scripts/` cover the same flow against the
// real program. Re-enable once the suite is rewritten to call
// `buildProposeIx` with `intentDigests: Uint8Array[]` and a bundle of
// pre-computed `keccak256(BCS([SweepIntent]))` digests.
describe.skip('ikavery sweep e2e (1-of-1, SCHEME_SOLANA_ADDRESS)', () => {
	test('create → propose → approve flips proposal to STATUS_APPROVED', async () => {
		const svm = newSvm();

		// Alice is the only roster member, the proposer, the approver, and the
		// sweep tx fee payer all in one. recoveryIdSigner is just a seed nonce.
		const { signer: alice, pubkey: alicePk } = await makeFunded(svm);
		const recoveryIdSigner = await generateKeyPairSigner();
		const recoveryIdPk = new PublicKey(recoveryIdSigner.address);

		// Stand-in dWallet account (32 bytes). Stored opaquely; only `execute`
		// would reach into the dWallet program (CPI), which we skip here.
		const dwallet32 = new Uint8Array(32).fill(0xab);
		const aliceMemberSlot = packSolanaMember(alicePk);

		// ── create_recovery ─────────────────────────────────────────────────
		const { ix: createIx, recovery } = buildCreateRecoveryIx({
			creator: alicePk,
			recoveryId: recoveryIdPk,
			dwallet: dwallet32,
			dwalletCurve: 2, // ed25519 — Solana key
			threshold: 1,
			members: [aliceMemberSlot],
		});
		await sendIx(svm, alice, createIx, {
			[recoveryIdPk.toBase58()]: recoveryIdSigner,
		});

		{
			const acct = svm.getAccount(recovery.toBase58() as any);
			expect(acct?.data.length).toBeGreaterThan(0);
			const decoded = decodeRecovery(acct!.data);
			expect(decoded.threshold).toBe(1);
			expect(decoded.members.length).toBe(1);
			expect(decoded.proposalCount).toBe(0);
		}

		// ── propose ─────────────────────────────────────────────────────────
		const bob = await generateKeyPairSigner();
		const dwalletPk = new PublicKey(dwallet32);
		const { messageBytes } = buildSweepMessage({
			feePayer: dwalletPk,
			instructions: [transferSol(dwalletPk, new PublicKey(bob.address), 1_000_000)],
		});

		const { ix: proposeIx, proposal } = buildProposeIx({
			recovery,
			recoveryId: recoveryIdPk,
			proposalIndex: 0,
			proposer: alicePk,
			messageBytes,
			userPubkey: new Uint8Array(32),
			signatureScheme: 0,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alicePk.toBytes(),
			},
		});
		await sendIx(svm, alice, proposeIx);

		{
			const acct = svm.getAccount(proposal.toBase58() as any);
			expect(acct?.data.length).toBeGreaterThan(0);
			const decoded = decodeProposal(acct!.data);
			expect(decoded.approvalCount).toBe(0);
			expect(decoded.recovery.equals(recovery)).toBe(true);
		}

		// ── approve (1-of-1 ⇒ flips to STATUS_APPROVED) ─────────────────────
		const { ix: approveIx } = buildApproveIx({
			recovery,
			proposal,
			payer: alicePk,
			memberSlot: aliceMemberSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alicePk.toBytes(),
			},
		});
		await sendIx(svm, alice, approveIx);

		{
			const acct = svm.getAccount(proposal.toBase58() as any);
			const decoded = decodeProposal(acct!.data);
			expect(decoded.status).toBe(STATUS_APPROVED);
			expect(decoded.approvalCount).toBe(1);
		}
	});

	test('multi-ix sweep (SOL + ATA-create + SPL-transfer-checked) flips to STATUS_APPROVED', async () => {
		const svm = newSvm();

		const { signer: alice, pubkey: alicePk } = await makeFunded(svm);
		const recoveryIdSigner = await generateKeyPairSigner();
		const recoveryIdPk = new PublicKey(recoveryIdSigner.address);

		const dwallet32 = new Uint8Array(32).fill(0xcd);
		const dwalletPk = new PublicKey(dwallet32);
		const aliceMemberSlot = packSolanaMember(alicePk);

		const { ix: createIx, recovery } = buildCreateRecoveryIx({
			creator: alicePk,
			recoveryId: recoveryIdPk,
			dwallet: dwallet32,
			dwalletCurve: 2,
			threshold: 1,
			members: [aliceMemberSlot],
		});
		await sendIx(svm, alice, createIx, {
			[recoveryIdPk.toBase58()]: recoveryIdSigner,
		});

		// Stand-in pubkeys — the propose handler only computes the structural
		// intent digest, it doesn't validate that mints/ATAs actually exist.
		const recipient = new PublicKey(new Uint8Array(32).fill(0x11));
		const sourceAta = new PublicKey(new Uint8Array(32).fill(0x22));
		const destAta = new PublicKey(new Uint8Array(32).fill(0x33));
		const mint = new PublicKey(new Uint8Array(32).fill(0x44));

		const { messageBytes } = buildSweepMessage({
			feePayer: dwalletPk,
			instructions: [
				transferSol(dwalletPk, recipient, 1_000_000),
				createIdempotentAta({
					payer: dwalletPk,
					ata: destAta,
					owner: recipient,
					mint,
					tokenProgramId: TOKEN_PROGRAM_ID,
				}),
				transferSplTokenChecked({
					source: sourceAta,
					mint,
					destination: destAta,
					authority: dwalletPk,
					amount: 1_000_000n,
					decimals: 6,
				}),
			],
		});

		const { ix: proposeIx, proposal } = buildProposeIx({
			recovery,
			recoveryId: recoveryIdPk,
			proposalIndex: 0,
			proposer: alicePk,
			messageBytes,
			userPubkey: new Uint8Array(32),
			signatureScheme: 0,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alicePk.toBytes(),
			},
		});
		await sendIx(svm, alice, proposeIx);

		let intentDigest: Uint8Array;
		{
			const acct = svm.getAccount(proposal.toBase58() as any);
			expect(acct?.data.length).toBeGreaterThan(0);
			const decoded = decodeProposal(acct!.data);
			expect(decoded.approvalCount).toBe(0);
			expect(decoded.recovery.equals(recovery)).toBe(true);
			// Digest is sha256(bcs(SweepIntent)) — must be non-zero, proving the
			// on-chain parser walked all three whitelisted ixs (SOL + ATA + SPL).
			expect(decoded.intentDigest.some((b) => b !== 0)).toBe(true);
			intentDigest = decoded.intentDigest;
		}

		const { ix: approveIx } = buildApproveIx({
			recovery,
			proposal,
			payer: alicePk,
			memberSlot: aliceMemberSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alicePk.toBytes(),
			},
		});
		await sendIx(svm, alice, approveIx);

		{
			const acct = svm.getAccount(proposal.toBase58() as any);
			const decoded = decodeProposal(acct!.data);
			expect(decoded.status).toBe(STATUS_APPROVED);
			expect(decoded.approvalCount).toBe(1);
			// Digest is immutable across approval — only status / count change.
			expect(Array.from(decoded.intentDigest)).toEqual(Array.from(intentDigest));
		}
	});
});
