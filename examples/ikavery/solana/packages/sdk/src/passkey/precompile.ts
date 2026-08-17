/**
 * Build a single-record secp256r1 SigVerify precompile instruction.
 *
 * Layout (matches Solana's `Secp256r1Program` and the on-chain parser in
 * `solana/packages/program/src/auth/precompile.rs`):
 *
 *   u8  num_signatures (= 1)
 *   u8  padding        (= 0)
 *   --- offsets table (14 bytes) ---
 *   u16 signature_offset
 *   u16 signature_instruction_index   (= 0xFFFF, "same instruction")
 *   u16 public_key_offset
 *   u16 public_key_instruction_index  (= 0xFFFF)
 *   u16 message_data_offset
 *   u16 message_data_size
 *   u16 message_instruction_index     (= 0xFFFF)
 *   --- payload ---
 *   signature (64 bytes, raw r||s)
 *   public_key (33 bytes, compressed)
 *   message
 */

import { TransactionInstruction, type PublicKey } from '@solana/web3.js';

import { SECP256R1_PRECOMPILE_ID } from '../constants';

const SAME_INSTRUCTION = 0xffff;
const SECP256R1_PUBKEY_LEN = 33;
const SECP256R1_SIGNATURE_LEN = 64;
const OFFSETS_LEN = 14;

export interface BuildSecp256r1IxParams {
	/** Raw 64-byte r||s signature emitted by the WebAuthn assertion. */
	signature: Uint8Array;
	/** Compressed P-256 public key (33 bytes). */
	publicKey: Uint8Array;
	/** Message that was signed: `authenticatorData || sha256(clientDataJSON)`. */
	message: Uint8Array;
}

export function buildSecp256r1VerifyIx(params: BuildSecp256r1IxParams): TransactionInstruction {
	const { signature, publicKey, message } = params;
	if (signature.length !== SECP256R1_SIGNATURE_LEN) {
		throw new Error(
			`secp256r1 signature must be ${SECP256R1_SIGNATURE_LEN} bytes (raw r||s), got ${signature.length}`,
		);
	}
	if (publicKey.length !== SECP256R1_PUBKEY_LEN) {
		throw new Error(
			`secp256r1 public key must be ${SECP256R1_PUBKEY_LEN} bytes compressed, got ${publicKey.length}`,
		);
	}

	const headerLen = 2 + OFFSETS_LEN;
	const sigOff = headerLen;
	const pkOff = sigOff + SECP256R1_SIGNATURE_LEN;
	const msgOff = pkOff + SECP256R1_PUBKEY_LEN;
	const totalLen = msgOff + message.length;

	const data = new Uint8Array(totalLen);
	const dv = new DataView(data.buffer);

	// Header
	data[0] = 1; // num_signatures
	data[1] = 0; // padding

	// Offsets table
	let p = 2;
	dv.setUint16(p, sigOff, true);
	p += 2;
	dv.setUint16(p, SAME_INSTRUCTION, true);
	p += 2;
	dv.setUint16(p, pkOff, true);
	p += 2;
	dv.setUint16(p, SAME_INSTRUCTION, true);
	p += 2;
	dv.setUint16(p, msgOff, true);
	p += 2;
	dv.setUint16(p, message.length, true);
	p += 2;
	dv.setUint16(p, SAME_INSTRUCTION, true);
	p += 2;

	// Payload
	data.set(signature, sigOff);
	data.set(publicKey, pkOff);
	data.set(message, msgOff);

	return new TransactionInstruction({
		programId: SECP256R1_PRECOMPILE_ID,
		keys: [],
		data: Buffer.from(data),
	});
}

export const SECP256R1_PRECOMPILE_PROGRAM: PublicKey = SECP256R1_PRECOMPILE_ID;
