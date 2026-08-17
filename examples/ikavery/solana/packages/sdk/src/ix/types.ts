import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	MAX_CLIENT_DATA_JSON_BYTES,
	SCHEME_SECP256K1,
	SCHEME_WEBAUTHN,
} from '../constants';

/**
 * On-the-wire credential bundle. The on-chain handler verifies it covers a
 * specific per-op challenge digest:
 *
 * - `SCHEME_ED25519` / `SCHEME_SECP256R1` — signature lives in a precompile
 *   ix earlier in the same tx; the program reads it via the instructions
 *   sysvar. `signature` here is unused (zero-padded on the wire).
 * - `SCHEME_SECP256K1` — inline 65-byte (r||s||recovery_id) ECDSA signature
 *   over `keccak256(eth-prefix(challenge))`; the program runs the
 *   `secp256k1_recover` syscall to pull the pubkey out.
 * - `SCHEME_WEBAUTHN` — `clientDataJson` carries the assertion's JSON; the
 *   precompile ix earlier in the same tx covers
 *   `authenticator_data || sha256(client_data_json)`.
 * - `SCHEME_SOLANA_ADDRESS` — no precompile needed; the program checks that
 *   the credential's pubkey matches a Solana Signer in the same tx.
 */
export interface AuthCredential {
	scheme: number;
	/** Per-scheme raw pubkey or address. Length is enforced per scheme. */
	pubkey: Uint8Array;
	/** WebAuthn-only `client_data_json` payload. Empty for other schemes. */
	clientDataJson?: Uint8Array;
	/** SCHEME_SECP256K1 only: 65-byte r||s||v signature. Empty otherwise. */
	signature?: Uint8Array;
}

export interface CredentialArgs {
	authScheme: number;
	authPubkey: Uint8Array;
	clientDataJson: Uint8Array;
	clientDataJsonLen: number;
	authSignature: Uint8Array;
}

const EMPTY_PUBKEY = new Uint8Array(AUTH_PUBKEY_BYTES);
const EMPTY_CDJ = new Uint8Array(MAX_CLIENT_DATA_JSON_BYTES);
const EMPTY_SIG = new Uint8Array(AUTH_SIGNATURE_BYTES);

/**
 * Pad a credential into the fixed-size wire-format tuple. The program
 * always reads `AUTH_PUBKEY_BYTES` / `MAX_CLIENT_DATA_JSON_BYTES` /
 * `AUTH_SIGNATURE_BYTES` even when a scheme doesn't use them.
 */
export function credentialArgs(cred: AuthCredential): CredentialArgs {
	const authPubkey = padFixed(cred.pubkey, AUTH_PUBKEY_BYTES, EMPTY_PUBKEY);

	const cdj = cred.clientDataJson ?? new Uint8Array(0);
	if (cdj.length > MAX_CLIENT_DATA_JSON_BYTES) {
		throw new Error(`client_data_json ${cdj.length}b exceeds ${MAX_CLIENT_DATA_JSON_BYTES}b cap`);
	}
	const clientDataJson = padFixed(cdj, MAX_CLIENT_DATA_JSON_BYTES, EMPTY_CDJ);

	const sig = cred.signature ?? new Uint8Array(0);
	if (sig.length !== 0 && sig.length !== AUTH_SIGNATURE_BYTES) {
		throw new Error(
			`auth_signature must be 0 or ${AUTH_SIGNATURE_BYTES} bytes, got ${sig.length}b`,
		);
	}
	if (cred.scheme === SCHEME_SECP256K1 && sig.length !== AUTH_SIGNATURE_BYTES) {
		throw new Error('SCHEME_SECP256K1 requires a 65-byte auth_signature');
	}
	if (cred.scheme === SCHEME_WEBAUTHN && cdj.length === 0) {
		throw new Error('SCHEME_WEBAUTHN requires a non-empty client_data_json');
	}
	const authSignature = padFixed(sig, AUTH_SIGNATURE_BYTES, EMPTY_SIG);

	return {
		authScheme: cred.scheme,
		authPubkey,
		clientDataJson,
		clientDataJsonLen: cdj.length,
		authSignature,
	};
}

function padFixed(src: Uint8Array, len: number, empty: Uint8Array): Uint8Array {
	if (src.length === 0) return empty;
	if (src.length > len) {
		throw new Error(`${src.length}b exceeds ${len}b buffer`);
	}
	const out = new Uint8Array(len);
	out.set(src, 0);
	return out;
}
