import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import { IKAVERY_PROGRAM_ID, IX_EXECUTE, MAX_MESSAGE_BYTES } from '../constants';
import { padInto, writeU8, writeU16le } from './encode';

export interface ExecuteParams {
	/** Recovery PDA (read-only). */
	recovery: PublicKey;
	/** Proposal PDA (the executed_bitmap bit at `txIndex` flips on success). */
	proposal: PublicKey;
	/**
	 * Anyone can fire `execute` once the proposal is `STATUS_APPROVED` and
	 * the rebuilt intent digest matches. The signer is just a sponsor — no
	 * roster membership required.
	 */
	payer: PublicKey;
	/**
	 * Index of the bundle tx being executed (0..bundle_len). The on-chain
	 * handler validates `tx_index < intent_digests.len()` and that the
	 * corresponding bit in `executed_bitmap` isn't already set.
	 */
	txIndex: number;
	/**
	 * Freshly-rebuilt sweep message for `txIndex` — the program re-parses
	 * these bytes and checks their structural digest matches
	 * `proposal.intent_digests[tx_index]`. Lets the executor refresh the
	 * recent blockhash without redirecting funds.
	 */
	messageBytes: Uint8Array;

	/**
	 * ika dWallet 2pc-mpc coordinator program account. The CPI target.
	 */
	coordinator: PublicKey;
	/** PDA where the dWallet writes its `MessageApproval` record. */
	messageApproval: PublicKey;
	/** Pre-existing `DWallet` account on the dWallet program. */
	dwallet: PublicKey;
	/** Caller program (this program's id, but passed explicitly). */
	callerProgram: PublicKey;
	/** PDA owned by this program that the dWallet treats as the CPI authority. */
	cpiAuthority: PublicKey;
	/** ika dWallet program executable account. */
	dwalletProgram: PublicKey;

	/** Bumps the dWallet uses to derive the MessageApproval / cpi-authority PDAs. */
	messageApprovalBump: number;
	cpiAuthorityBump: number;
}

export function buildExecuteIx(params: ExecuteParams): TransactionInstruction {
	if (params.messageBytes.length > MAX_MESSAGE_BYTES) {
		throw new Error(`message ${params.messageBytes.length}b exceeds ${MAX_MESSAGE_BYTES}b cap`);
	}

	if (params.txIndex < 0 || params.txIndex > 0xff) {
		throw new Error(`txIndex must fit in u8, got ${params.txIndex}`);
	}
	// disc(1) + tx_index(1) + message_bytes(512) + message_len(2) + bumps(1+1)
	const dataLen = 1 + 1 + MAX_MESSAGE_BYTES + 2 + 1 + 1;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_EXECUTE);
	off = writeU8(data, off, params.txIndex);
	off = padInto(data, off, params.messageBytes, MAX_MESSAGE_BYTES);
	off = writeU16le(data, off, params.messageBytes.length);
	off = writeU8(data, off, params.messageApprovalBump);
	off = writeU8(data, off, params.cpiAuthorityBump);

	return new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: false },
			{ pubkey: params.proposal, isSigner: false, isWritable: true },
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{ pubkey: params.coordinator, isSigner: false, isWritable: false },
			{ pubkey: params.messageApproval, isSigner: false, isWritable: true },
			{ pubkey: params.dwallet, isSigner: false, isWritable: false },
			{ pubkey: params.callerProgram, isSigner: false, isWritable: false },
			{ pubkey: params.cpiAuthority, isSigner: false, isWritable: false },
			{ pubkey: params.dwalletProgram, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});
}
