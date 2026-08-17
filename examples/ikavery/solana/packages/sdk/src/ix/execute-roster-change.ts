import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import { IKAVERY_PROGRAM_ID, IX_EXECUTE_ROSTER_CHANGE, SYSVAR_RENT_ID } from '../constants';
import { writeU8 } from './encode';

export interface ExecuteRosterChangeParams {
	recovery: PublicKey;
	rosterChange: PublicKey;
	/**
	 * Sponsor that pays for any account-data resize when the roster grows.
	 * Anyone can fire `execute_roster_change` once threshold is met.
	 */
	payer: PublicKey;
}

export function buildExecuteRosterChangeIx(
	params: ExecuteRosterChangeParams,
): TransactionInstruction {
	const data = new Uint8Array(1);
	writeU8(data, 0, IX_EXECUTE_ROSTER_CHANGE);

	return new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: true },
			{ pubkey: params.rosterChange, isSigner: false, isWritable: true },
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{ pubkey: SYSVAR_RENT_ID, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});
}
