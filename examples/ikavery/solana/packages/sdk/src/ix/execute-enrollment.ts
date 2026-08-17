import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import { IKAVERY_PROGRAM_ID, IX_EXECUTE_ENROLLMENT, SYSVAR_RENT_ID } from '../constants';
import { writeU8 } from './encode';

export interface ExecuteEnrollmentParams {
	recovery: PublicKey;
	enrollment: PublicKey;
	payer: PublicKey;
}

export function buildExecuteEnrollmentIx(params: ExecuteEnrollmentParams): TransactionInstruction {
	const data = new Uint8Array(1);
	writeU8(data, 0, IX_EXECUTE_ENROLLMENT);

	return new TransactionInstruction({
		programId: IKAVERY_PROGRAM_ID,
		keys: [
			{ pubkey: params.recovery, isSigner: false, isWritable: true },
			{ pubkey: params.enrollment, isSigner: false, isWritable: true },
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{ pubkey: SYSVAR_RENT_ID, isSigner: false, isWritable: false },
			{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
		],
		data: Buffer.from(data),
	});
}
