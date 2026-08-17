import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_PROPOSE_ENROLLMENT,
	MAX_CLIENT_DATA_JSON_BYTES,
	MEMBER_SLOT_LEN,
	SYSVAR_INSTRUCTIONS_ID,
	SYSVAR_RENT_ID,
} from '../constants';
import { enrollmentPda } from '../pda';
import { writeBytes, writeU8, writeU16le, writeU32le } from './encode';
import { credentialArgs, type AuthCredential } from './types';

export interface ProposeEnrollmentParams {
	recovery: PublicKey;
	recoveryId: PublicKey;
	/** Must equal the on-chain `Recovery.enrollment_count`. */
	enrollmentIndex: number;
	payer: PublicKey;
	/** New member's `MemberSlot`. Pre-packed via `packMemberSlot`. */
	newMember: Uint8Array;
	/**
	 * 32-byte encryption-key address — opaque on Solana ika pre-alpha (no
	 * re-encrypt CPI yet). Stored on the EnrollmentProposal so the future
	 * mainnet path can fire CPI from the same data.
	 */
	newEncryptionKeyAddress: Uint8Array;
	/** 1 ⇔ approver-only; 0 ⇔ key-holding. */
	additionApproverOnly: 0 | 1;
	/** Existing-member credential authorising the proposal. */
	credential: AuthCredential;
}

export interface ProposeEnrollmentIx {
	ix: TransactionInstruction;
	enrollment: PublicKey;
}

export function buildProposeEnrollmentIx(params: ProposeEnrollmentParams): ProposeEnrollmentIx {
	if (params.newMember.length !== MEMBER_SLOT_LEN) {
		throw new Error(`new_member must be ${MEMBER_SLOT_LEN} bytes, got ${params.newMember.length}`);
	}
	if (params.newEncryptionKeyAddress.length !== 32) {
		throw new Error(
			`new_encryption_key_address must be 32 bytes, got ${params.newEncryptionKeyAddress.length}`,
		);
	}

	const enrollment = enrollmentPda(params.recovery, params.enrollmentIndex);
	const cred = credentialArgs(params.credential);

	// 1 (disc) + 4 (idx) + 34 (new_member) + 32 (enc_key_addr) +
	// 1 (approver_only) + 1 + 33 + 256 + 2 + 65
	const dataLen =
		1 +
		4 +
		MEMBER_SLOT_LEN +
		32 +
		1 +
		1 +
		AUTH_PUBKEY_BYTES +
		MAX_CLIENT_DATA_JSON_BYTES +
		2 +
		AUTH_SIGNATURE_BYTES;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_PROPOSE_ENROLLMENT);
	off = writeU32le(data, off, params.enrollmentIndex);
	off = writeBytes(data, off, params.newMember, MEMBER_SLOT_LEN);
	off = writeBytes(data, off, params.newEncryptionKeyAddress, 32);
	off = writeU8(data, off, params.additionApproverOnly);
	off = writeU8(data, off, cred.authScheme);
	off = writeBytes(data, off, cred.authPubkey, AUTH_PUBKEY_BYTES);
	off = writeBytes(data, off, cred.clientDataJson, MAX_CLIENT_DATA_JSON_BYTES);
	off = writeU16le(data, off, cred.clientDataJsonLen);
	off = writeBytes(data, off, cred.authSignature, AUTH_SIGNATURE_BYTES);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: true },
			{ pubkey: params.recoveryId, isSigner: false, isWritable: false },
			{ pubkey: enrollment, isSigner: false, isWritable: true },
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

	return { ix, enrollment };
}
