import {
	base64URLStringToBuffer,
	bufferToBase64URLString,
	startAuthentication,
	startRegistration,
} from '@simplewebauthn/browser';

import { PRF_SALT } from '../constants';
import type { PasskeyAssertionResult, PasskeyCredential, WebAuthnAssertion } from '../types';
import { extractEs256PubkeyFromAttestationObject } from './cose';
import { derSigToCompactRaw64, spkiToCompressedP256 } from './spki';

const encoder = new TextEncoder();

/**
 * Create a new passkey credential bound to the given relying-party id, with
 * the WebAuthn `prf` extension enabled so the same credential can later
 * deterministically derive Ika's UserShareEncryptionKeys seed.
 *
 * Constrains the credential to ES256 (alg=-7 / secp256r1) so the on-chain
 * verifier only needs `sui::ecdsa_r1::secp256r1_verify`.
 */
export async function registerPasskey(opts: {
	rpId: string;
	rpName?: string;
	userId: Uint8Array;
	userName: string;
	userDisplayName?: string;
	challenge?: Uint8Array;
}): Promise<PasskeyCredential> {
	const challenge = opts.challenge ?? crypto.getRandomValues(new Uint8Array(32));
	const result = await startRegistration({
		optionsJSON: {
			rp: { id: opts.rpId, name: opts.rpName ?? opts.rpId },
			user: {
				id: bufferToBase64URLString(opts.userId.buffer as ArrayBuffer),
				name: opts.userName,
				displayName: opts.userDisplayName ?? opts.userName,
			},
			challenge: bufferToBase64URLString(challenge.buffer as ArrayBuffer),
			pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
			authenticatorSelection: {
				residentKey: 'required',
				userVerification: 'required',
			},
			extensions: { prf: {} } as Record<string, unknown>,
			timeout: 60_000,
		},
	});

	// Prefer the SPKI from `getPublicKey()`; fall back to parsing the
	// attestationObject directly. Firefox + 1Password ships ES256 credentials
	// but `getPublicKey()` returns null, so without this fallback the flow
	// dead-ends at registration.
	let publicKey: Uint8Array;
	if (result.response.publicKey) {
		const spki = new Uint8Array(base64URLStringToBuffer(result.response.publicKey));
		publicKey = spkiToCompressedP256(spki);
	} else if (result.response.attestationObject) {
		const attobj = new Uint8Array(base64URLStringToBuffer(result.response.attestationObject));
		publicKey = extractEs256PubkeyFromAttestationObject(attobj);
	} else {
		throw new Error(
			'passkey registration: response is missing both publicKey and attestationObject',
		);
	}
	return {
		credentialId: new Uint8Array(base64URLStringToBuffer(result.rawId)),
		publicKey,
	};
}

/**
 * Authenticate against an existing credential with a specific 32-byte
 * challenge. Returns the WebAuthn assertion shaped for `recovery::assertion`
 * + the PRF output if the authenticator supports the prf extension.
 *
 * The PRF salt is `ika-recovery-prf-v1`, fixed across all devices using this
 * SDK so all enrolled passkeys derive distinct (but stable per-credential)
 * UserShareEncryptionKeys seeds.
 */
export async function authenticate(opts: {
	credentialId: Uint8Array;
	publicKey: Uint8Array;
	challenge: Uint8Array;
	rpId: string;
}): Promise<PasskeyAssertionResult> {
	if (opts.challenge.length !== 32) {
		throw new Error(`authenticate: expected 32-byte challenge, got ${opts.challenge.length}`);
	}
	const prfSalt = encoder.encode(PRF_SALT);
	// simplewebauthn v11 spreads optionsJSON.extensions verbatim into
	// navigator.credentials.get(); the prf.eval.first slot must already be a
	// real ArrayBuffer/View, not a base64url string. Pass the raw bytes.
	const expectedCredId = bufferToBase64URLString(opts.credentialId.buffer as ArrayBuffer);
	const result = await startAuthentication({
		optionsJSON: {
			challenge: bufferToBase64URLString(opts.challenge.buffer as ArrayBuffer),
			rpId: opts.rpId,
			allowCredentials: [
				{
					type: 'public-key',
					id: expectedCredId,
				},
			],
			userVerification: 'required',
			extensions: {
				prf: { eval: { first: prfSalt } },
			} as Record<string, unknown>,
			timeout: 60_000,
		},
	});

	// Some platforms (notably Apple iCloud Keychain) ignore allowCredentials
	// and let the user pick any passkey for this rpId. If they pick a
	// *different* one, the signature is over a different keypair than the
	// caller's cached `opts.publicKey` — verification on chain would fail
	// with an opaque assertion-invalid abort. Fail here with a clear message
	// so the user knows which credential to pick next time.
	if (result.id !== expectedCredId) {
		throw new Error(
			'Passkey mismatch — the OS used a different credential than the one ' +
				'tied to this member. On the next prompt, pick the passkey labeled ' +
				'for this site / member. (got ' +
				result.id.slice(0, 12) +
				'…, expected ' +
				expectedCredId.slice(0, 12) +
				'…)',
		);
	}

	const assertion: WebAuthnAssertion = {
		publicKey: opts.publicKey,
		authenticatorData: new Uint8Array(base64URLStringToBuffer(result.response.authenticatorData)),
		clientDataJSON: new Uint8Array(base64URLStringToBuffer(result.response.clientDataJSON)),
		signature: derSigToCompactRaw64(
			new Uint8Array(base64URLStringToBuffer(result.response.signature)),
		),
	};

	const exts = result.clientExtensionResults as {
		prf?: { results?: { first?: string | ArrayBuffer } };
	};
	const first = exts.prf?.results?.first;
	let prfOutput: Uint8Array | undefined;
	if (typeof first === 'string') {
		prfOutput = new Uint8Array(base64URLStringToBuffer(first));
	} else if (first instanceof ArrayBuffer) {
		prfOutput = new Uint8Array(first);
	}

	return { assertion, prfOutput };
}
