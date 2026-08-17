import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_PROPOSE_ROSTER_CHANGE,
	MAX_CLIENT_DATA_JSON_BYTES,
	SYSVAR_INSTRUCTIONS_ID,
	SYSVAR_RENT_ID,
} from '../constants';
import { rosterChangePda, rosterChangeStagingPda } from '../pda';
import { padInto, writeBytes, writeU8, writeU16le, writeU32le } from './encode';
import { credentialArgs, type AuthCredential } from './types';

export interface ProposeRosterChangeParams {
	recovery: PublicKey;
	recoveryId: PublicKey;
	/** Must equal the on-chain `Recovery.roster_change_count`. */
	rosterChangeIndex: number;
	/**
	 * Pays rent for the new RosterChangeProposal PDA AND receives the
	 * staging-account rent refund when `staging` closes on success.
	 */
	payer: PublicKey;
	/**
	 * Free-form 32-byte digest the credential is expected to have signed.
	 * Must equal the `payload_hash` recomputed by the staging ix; otherwise
	 * the program rejects with IntentDigestMismatch.
	 */
	payloadHash: Uint8Array;
	/** Credential authorising the proposal. */
	credential: AuthCredential;
}

export interface ProposeRosterChangeIx {
	ix: TransactionInstruction;
	rosterChange: PublicKey;
	staging: PublicKey;
}

export function buildProposeRosterChangeIx(
	params: ProposeRosterChangeParams,
): ProposeRosterChangeIx {
	if (params.payloadHash.length !== 32) {
		throw new Error(`payload_hash must be 32 bytes, got ${params.payloadHash.length}`);
	}

	const rosterChange = rosterChangePda(params.recovery, params.rosterChangeIndex);
	const staging = rosterChangeStagingPda(params.recovery, params.rosterChangeIndex);
	const cred = credentialArgs(params.credential);

	// 1 (disc) + 4 (idx) + 32 (payload_hash) +
	// 1 (auth_scheme) + 33 (auth_pubkey) + 256 (cdj) + 2 (cdj_len) + 65 (sig)
	const dataLen =
		1 + 4 + 32 + 1 + AUTH_PUBKEY_BYTES + MAX_CLIENT_DATA_JSON_BYTES + 2 + AUTH_SIGNATURE_BYTES;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_PROPOSE_ROSTER_CHANGE);
	off = writeU32le(data, off, params.rosterChangeIndex);
	off = writeBytes(data, off, params.payloadHash, 32);
	off = writeU8(data, off, cred.authScheme);
	off = writeBytes(data, off, cred.authPubkey, AUTH_PUBKEY_BYTES);
	off = padInto(data, off, cred.clientDataJson, MAX_CLIENT_DATA_JSON_BYTES);
	off = writeU16le(data, off, cred.clientDataJsonLen);
	off = writeBytes(data, off, cred.authSignature, AUTH_SIGNATURE_BYTES);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: true },
			{ pubkey: params.recoveryId, isSigner: false, isWritable: false },
			{ pubkey: rosterChange, isSigner: false, isWritable: true },
			{ pubkey: staging, isSigner: false, isWritable: true },
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

	return { ix, rosterChange, staging };
}
