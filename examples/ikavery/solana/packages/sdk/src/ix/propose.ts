import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_PROPOSE,
	MAX_BUNDLE_PER_PROPOSAL,
	MAX_CLIENT_DATA_JSON_BYTES,
	PROPOSE_DIGESTS_BYTES,
	SYSVAR_INSTRUCTIONS_ID,
	SYSVAR_RENT_ID,
} from '../constants';
import { proposalPda } from '../pda';
import { writeBytes, writeU8, writeU16le, writeU32le } from './encode';
import { credentialArgs, type AuthCredential } from './types';

export interface ProposeParams {
	/** Recovery PDA (derived from the original `recoveryId`). */
	recovery: PublicKey;
	/** The original `recoveryId` keypair's public address — needed for PDA derivation. */
	recoveryId: PublicKey;
	/**
	 * Monotonically-increasing index. Must equal the current
	 * `Recovery.proposal_count` on-chain or the program rejects with
	 * `WrongIndex`.
	 */
	proposalIndex: number;
	/** Pays rent for the new Proposal PDA + signs the tx. */
	proposer: PublicKey;
	/**
	 * Per-tx intent digests (Solana-flavoured: `keccak256(BCS([SweepIntent]))`)
	 * for each tx in the proposal's sweep bundle. Length must be in
	 * `1..=MAX_BUNDLE_PER_PROPOSAL`. The on-chain handler hashes these
	 * digests into the per-op challenge so the credential commits to the
	 * full bundle in one signature.
	 */
	intentDigests: Uint8Array[];
	/**
	 * 32-byte dWallet user pubkey passed to the `approve_message` CPI later.
	 * Stored on the Proposal account so `execute` can pull it back out.
	 */
	userPubkey: Uint8Array;
	/**
	 * Sui `Curve`-style signature scheme tag passed through to the dWallet
	 * CPI at execute-time.
	 */
	signatureScheme: number;
	/** Credential authorising the proposer's vote over the bundle. */
	credential: AuthCredential;
}

export interface ProposeIx {
	ix: TransactionInstruction;
	proposal: PublicKey;
}

export function buildProposeIx(params: ProposeParams): ProposeIx {
	if (params.userPubkey.length !== 32) {
		throw new Error(`user_pubkey must be 32 bytes, got ${params.userPubkey.length}`);
	}
	const n = params.intentDigests.length;
	if (n === 0) {
		throw new Error('buildProposeIx: bundle must contain at least one digest');
	}
	if (n > MAX_BUNDLE_PER_PROPOSAL) {
		throw new Error(
			`buildProposeIx: bundle of ${n} > MAX_BUNDLE_PER_PROPOSAL=${MAX_BUNDLE_PER_PROPOSAL}`,
		);
	}
	for (let i = 0; i < n; i++) {
		const d = params.intentDigests[i] as Uint8Array;
		if (d.length !== 32) {
			throw new Error(`intentDigests[${i}] must be 32 bytes, got ${d.length}`);
		}
	}

	const proposal = proposalPda(params.recovery, params.proposalIndex);
	const cred = credentialArgs(params.credential);

	// disc(1) + proposal_index(4) + digests_packed(256) + digest_count(1) +
	// user_pubkey(32) + signature_scheme(2) + auth_scheme(1) + auth_pubkey(33)
	// + client_data_json(256) + client_data_json_len(2) + auth_signature(65)
	const dataLen =
		1 +
		4 +
		PROPOSE_DIGESTS_BYTES +
		1 +
		32 +
		2 +
		1 +
		AUTH_PUBKEY_BYTES +
		MAX_CLIENT_DATA_JSON_BYTES +
		2 +
		AUTH_SIGNATURE_BYTES;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_PROPOSE);
	off = writeU32le(data, off, params.proposalIndex);
	// Packed digests: [d_0 || d_1 || ... || d_{n-1} || zero-pad to 256]
	for (let i = 0; i < n; i++) {
		off = writeBytes(data, off, params.intentDigests[i] as Uint8Array, 32);
	}
	// Skip the unused tail (already zero-initialized).
	off += (MAX_BUNDLE_PER_PROPOSAL - n) * 32;
	off = writeU8(data, off, n);
	off = writeBytes(data, off, params.userPubkey, 32);
	off = writeU16le(data, off, params.signatureScheme);
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
			{ pubkey: proposal, isSigner: false, isWritable: true },
			{ pubkey: params.proposer, isSigner: true, isWritable: true },
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

	return { ix, proposal };
}
