import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_APPROVE_ROSTER_CHANGE,
	MAX_CLIENT_DATA_JSON_BYTES,
	SYSVAR_INSTRUCTIONS_ID,
	SYSVAR_RENT_ID,
} from '../constants';
import { memberIdHash, rosterChangeApprovalPda } from '../pda';
import { writeBytes, writeU8, writeU16le } from './encode';
import { credentialArgs, type AuthCredential } from './types';

export interface ApproveRosterChangeParams {
	recovery: PublicKey;
	rosterChange: PublicKey;
	payer: PublicKey;
	memberSlot: Uint8Array;
	credential: AuthCredential;
}

export interface ApproveRosterChangeIx {
	ix: TransactionInstruction;
	approval: PublicKey;
	memberIdHashAddress: PublicKey;
}

export function buildApproveRosterChangeIx(
	params: ApproveRosterChangeParams,
): ApproveRosterChangeIx {
	const memberIdHashAddress = memberIdHash(params.memberSlot);
	const approval = rosterChangeApprovalPda(params.rosterChange, memberIdHashAddress);
	const cred = credentialArgs(params.credential);

	const dataLen = 1 + 1 + AUTH_PUBKEY_BYTES + MAX_CLIENT_DATA_JSON_BYTES + 2 + AUTH_SIGNATURE_BYTES;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_APPROVE_ROSTER_CHANGE);
	off = writeU8(data, off, cred.authScheme);
	off = writeBytes(data, off, cred.authPubkey, AUTH_PUBKEY_BYTES);
	off = writeBytes(data, off, cred.clientDataJson, MAX_CLIENT_DATA_JSON_BYTES);
	off = writeU16le(data, off, cred.clientDataJsonLen);
	off = writeBytes(data, off, cred.authSignature, AUTH_SIGNATURE_BYTES);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: false },
			{ pubkey: params.rosterChange, isSigner: false, isWritable: true },
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
