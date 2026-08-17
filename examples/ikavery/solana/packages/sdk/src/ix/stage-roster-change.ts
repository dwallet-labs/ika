import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import {
	CREATE_MEMBERS_BYTES,
	IKAVERY_PROGRAM_ID,
	IX_STAGE_ROSTER_CHANGE_PAYLOAD,
	SYSVAR_RENT_ID,
} from '../constants';
import { packMembers } from '../credential';
import { rosterChangeStagingPda } from '../pda';
import { padInto, writeU8, writeU16le, writeU32le } from './encode';

export interface StageRosterChangePayloadParams {
	recovery: PublicKey;
	recoveryId: PublicKey;
	/** Must equal the on-chain `Recovery.roster_change_count`. */
	rosterChangeIndex: number;
	/** Pays rent for the new staging PDA; receives the refund on propose success. */
	payer: PublicKey;
	/** Members to add. Pre-packed via `packMemberSlot`. */
	additions: Uint8Array[];
	/** Members to remove. Must each currently be on the roster. */
	removals: Uint8Array[];
	/**
	 * Per-addition flag (bit `i` ⇔ `additions[i]` is approver-only). Bits
	 * past `additions.length` must be zero.
	 */
	additionApproverOnlyBitmap?: number;
	/** New threshold for the roster after the change applies. Optional. */
	newThreshold?: number;
}

export interface StageRosterChangePayloadIx {
	ix: TransactionInstruction;
	staging: PublicKey;
}

/**
 * Build the `stage_roster_change_payload` ix. Buffers the additions/
 * removals/threshold into a per-index PDA so the credential-bearing
 * `propose_roster_change` tx can stay under Solana's 1232-byte packet
 * cap. No auth on this ix; trust gating happens at propose time when the
 * signed `payload_hash` is matched against the staging account.
 */
export function buildStageRosterChangePayloadIx(
	params: StageRosterChangePayloadParams,
): StageRosterChangePayloadIx {
	const staging = rosterChangeStagingPda(params.recovery, params.rosterChangeIndex);
	const additions = packMembers(params.additions, CREATE_MEMBERS_BYTES);
	const removals = packMembers(params.removals, CREATE_MEMBERS_BYTES);

	// 1 (disc) + 4 (idx) +
	// 272 (additions) + 1 (n_add) + 2 (bitmap) +
	// 272 (removals) + 1 (n_rem) +
	// 2 (new_threshold) + 1 (has_new_threshold)
	const dataLen = 1 + 4 + CREATE_MEMBERS_BYTES + 1 + 2 + CREATE_MEMBERS_BYTES + 1 + 2 + 1;
	const data = new Uint8Array(dataLen);
	let off = 0;
	off = writeU8(data, off, IX_STAGE_ROSTER_CHANGE_PAYLOAD);
	off = writeU32le(data, off, params.rosterChangeIndex);
	off = padInto(data, off, additions.packed, CREATE_MEMBERS_BYTES);
	off = writeU8(data, off, additions.count);
	off = writeU16le(data, off, params.additionApproverOnlyBitmap ?? 0);
	off = padInto(data, off, removals.packed, CREATE_MEMBERS_BYTES);
	off = writeU8(data, off, removals.count);
	off = writeU16le(data, off, params.newThreshold ?? 0);
	off = writeU8(data, off, params.newThreshold != null ? 1 : 0);

	const ix = new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: false },
			{ pubkey: params.recoveryId, isSigner: false, isWritable: false },
			{ pubkey: staging, isSigner: false, isWritable: true },
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{ pubkey: SYSVAR_RENT_ID, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});

	return { ix, staging };
}
