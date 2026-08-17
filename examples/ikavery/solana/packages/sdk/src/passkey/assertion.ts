/**
 * WebAuthn assertion driver — runs `navigator.credentials.get` for a per-op
 * challenge and packages the result into the secp256r1 precompile ix +
 * `AuthCredential` the on-chain program expects.
 *
 * The on-chain side (`auth/webauthn.rs`) reads the signed payload
 * `authenticatorData || sha256(clientDataJSON)` from the runtime-verified
 * secp256r1 precompile invocation, then substring-checks
 * `"challenge":"<base64url(challenge)>"` inside `clientDataJSON`. So this
 * driver:
 *   1. invokes the authenticator with `challenge`,
 *   2. parses the response (sig, authData, cdj),
 *   3. builds the precompile ix that the program will look up,
 *   4. returns the `AuthCredential` + `precompileIx` for the caller to
 *      prepend to the recovery instruction.
 */

import { derSigToCompactRaw64 } from '@fesal-packages/ikavery-core';
import { sha256 } from '@noble/hashes/sha256';
import type { TransactionInstruction } from '@solana/web3.js';

import { SCHEME_WEBAUTHN } from '../constants';
import type { AuthCredential } from '../ix/types';
import { buildSecp256r1VerifyIx } from './precompile';

export interface RunAssertionParams {
	/** Credential id stored at enrollment time. */
	credentialId: Uint8Array;
	/** Compressed P-256 public key (33 bytes) captured at enrollment. */
	publicKey: Uint8Array;
	/** 32-byte per-op challenge built via the `challenges` module. */
	challenge: Uint8Array;
	/** RP id the credential was bound to. Optional — browser defaults to origin. */
	rpId?: string;
	/** Forwarded to `navigator.credentials.get` to allow async cancellation. */
	signal?: AbortSignal;
	/** Defaults to `"required"`. */
	userVerification?: AuthenticatorAttachmentRequirement;
}

type AuthenticatorAttachmentRequirement = 'required' | 'preferred' | 'discouraged';

export interface AssertionResult {
	/** secp256r1 precompile ix to prepend to the recovery tx. */
	precompileIx: TransactionInstruction;
	/** Credential bundle to pass into the recovery ix builder. */
	credential: AuthCredential;
	/** Raw `clientDataJSON` (utf8). Useful for logging. */
	clientDataJson: Uint8Array;
	/** Raw `authenticatorData`. */
	authenticatorData: Uint8Array;
}

/**
 * Run a WebAuthn assertion for `challenge` and produce the precompile ix +
 * credential bundle the on-chain program will pair with it.
 *
 * Browser-only — throws if `navigator.credentials` is unavailable.
 */
export async function runWebAuthnAssertion(params: RunAssertionParams): Promise<AssertionResult> {
	if (
		typeof navigator === 'undefined' ||
		!navigator.credentials ||
		typeof navigator.credentials.get !== 'function'
	) {
		throw new Error(
			'WebAuthn is not available in this environment — passkey flows require a browser with PublicKeyCredential support.',
		);
	}
	if (params.challenge.length !== 32) {
		throw new Error(`WebAuthn challenge must be 32 bytes, got ${params.challenge.length}`);
	}
	if (params.publicKey.length !== 33) {
		throw new Error(
			`Stored credential public key must be 33-byte compressed P-256, got ${params.publicKey.length}`,
		);
	}

	const cred = (await navigator.credentials.get({
		publicKey: {
			challenge: toArrayBuffer(params.challenge),
			allowCredentials: [
				{
					id: toArrayBuffer(params.credentialId),
					type: 'public-key',
					transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
				},
			],
			userVerification: params.userVerification ?? 'required',
			rpId: params.rpId,
			timeout: 60_000,
		},
		signal: params.signal,
	})) as PublicKeyCredential | null;
	if (!cred) {
		throw new Error('WebAuthn assertion was cancelled.');
	}
	const response = cred.response as AuthenticatorAssertionResponse;
	const clientDataJson = new Uint8Array(response.clientDataJSON);
	const authenticatorData = new Uint8Array(response.authenticatorData);
	const derSignature = new Uint8Array(response.signature);

	// Sanity check — the browser embeds the challenge into clientDataJSON,
	// and the on-chain webauthn parser does a substring match for the same
	// `"challenge":"<b64url>"` we're about to send. If those disagree the
	// tx will fail; better to catch it here.
	expectChallengeInClientData(clientDataJson, params.challenge);

	const rawSignature = derSigToCompactRaw64(derSignature);
	const cdjHash = sha256(clientDataJson);
	const signedMessage = new Uint8Array(authenticatorData.length + cdjHash.length);
	signedMessage.set(authenticatorData, 0);
	signedMessage.set(cdjHash, authenticatorData.length);

	const precompileIx = buildSecp256r1VerifyIx({
		signature: rawSignature,
		publicKey: params.publicKey,
		message: signedMessage,
	});

	return {
		precompileIx,
		credential: {
			scheme: SCHEME_WEBAUTHN,
			pubkey: params.publicKey,
			clientDataJson,
		},
		clientDataJson,
		authenticatorData,
	};
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
	if (view.byteOffset === 0 && view.byteLength === view.buffer.byteLength) {
		return view.buffer as ArrayBuffer;
	}
	const out = new ArrayBuffer(view.byteLength);
	new Uint8Array(out).set(view);
	return out;
}

function base64UrlEncode32(bytes: Uint8Array): string {
	const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	if (bytes.length !== 32) {
		throw new Error(`base64UrlEncode32: expected 32 bytes, got ${bytes.length}`);
	}
	let out = '';
	for (let i = 0; i < 30; i += 3) {
		const n =
			((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
		out += ALPHA[(n >> 18) & 0x3f];
		out += ALPHA[(n >> 12) & 0x3f];
		out += ALPHA[(n >> 6) & 0x3f];
		out += ALPHA[n & 0x3f];
	}
	const b0 = bytes[30] as number;
	const b1 = bytes[31] as number;
	out += ALPHA[(b0 >> 2) & 0x3f];
	out += ALPHA[((b0 & 0x03) << 4) | (b1 >> 4)];
	out += ALPHA[(b1 & 0x0f) << 2];
	return out;
}

function expectChallengeInClientData(clientDataJson: Uint8Array, challenge: Uint8Array): void {
	const text = new TextDecoder().decode(clientDataJson);
	const needle = `"challenge":"${base64UrlEncode32(challenge)}"`;
	if (!text.includes(needle)) {
		throw new Error(
			'WebAuthn clientDataJSON did not embed the requested challenge — assertion would fail on-chain.',
		);
	}
}
