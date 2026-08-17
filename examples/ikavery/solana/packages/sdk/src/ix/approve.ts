import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_APPROVE,
	MAX_CLIENT_DATA_JSON_BYTES,
	SYSVAR_INSTRUCTIONS_ID,
	SYSVAR_RENT_ID,
} from '../constants';
import { approvalPda, memberIdHash } from '../pda';
import { writeBytes, writeU8, writeU16le } from './encode';
import { credentialArgs, type AuthCredential } from './types';

export interface ApproveParams {
	/** Recovery PDA. */
	recovery: PublicKey;
	/** Proposal PDA being approved. */
	proposal: PublicKey;
	/**
	 * Pays rent for the new Approval PDA. Decoupled from the auth identity:
	 * any wallet can sponsor the vote.
	 */
	payer: PublicKey;
	/**
	 * Member-id slot of the approver (the canonical `[scheme, pubkey]` form
	 * — `packMemberSlot` / `packSolanaMember` produce these). Used to
	 * compute the `member_id_hash` UncheckedAccount address that the program
	 * uses as the Approval PDA's per-credential discriminator seed.
	 */
	memberSlot: Uint8Array;
	/** Credential authorising the vote. Must resolve to `memberSlot`. */
	credential: AuthCredential;
}

export interface ApproveIx {
	ix: TransactionInstruction;
	approval: PublicKey;
	memberIdHashAddress: PublicKey;
}

export function buildApproveIx(params: ApproveParams): ApproveIx {
	const memberIdHashAddress = memberIdHash(params.memberSlot);
	const approval = approvalPda(params.proposal, memberIdHashAddress);
	const cred = credentialArgs(params.credential);

	const dataLen = 1 + 1 + AUTH_PUBKEY_BYTES + MAX_CLIENT_DATA_JSON_BYTES + 2 + AUTH_SIGNATURE_BYTES;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_APPROVE);
	off = writeU8(data, off, cred.authScheme);
	off = writeBytes(data, off, cred.authPubkey, AUTH_PUBKEY_BYTES);
	off = writeBytes(data, off, cred.clientDataJson, MAX_CLIENT_DATA_JSON_BYTES);
	off = writeU16le(data, off, cred.clientDataJsonLen);
	off = writeBytes(data, off, cred.authSignature, AUTH_SIGNATURE_BYTES);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: false },
			{ pubkey: params.proposal, isSigner: false, isWritable: true },
			{ pubkey: memberIdHashAddress, isSigner: false, isWritable: false },
			{ pubkey: approval, isSigner: false, isWritable: true },
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{
				pubkey: SYSVAR_INSTRUCTIONS_ID,
				isSigner: false,
				isWritable: false,
			},
			{ pubkey: SYSVAR_RENT_ID, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});

	return { ix, approval, memberIdHashAddress };
}
