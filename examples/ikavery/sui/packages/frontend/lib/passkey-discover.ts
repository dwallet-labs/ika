'use client';

import { PRF_SALT } from '@fesal-packages/ikavery-core';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { startAuthentication } from '@simplewebauthn/browser';

import { listRecoveriesForMember, memberIdFor } from './registry';
import { bytesToHex, hexToBytes } from './storage';

function base64UrlToBytes(s: string): Uint8Array {
	const pad = '='.repeat((4 - (s.length % 4)) % 4);
	const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export interface PasskeyDiscovery {
	recoveryIds: string[];
	/** 33-byte compressed P-256 pubkey, hex. */
	publicKeyHex: string;
	credentialIdHex: string;
	prfOutput: Uint8Array;
}

/**
 * Trigger the OS passkey picker (no `allowCredentials`), recover both
 * candidate public keys via ECDSA pubkey-recovery, and find which one is
 * registered as a member of any on-chain recovery. Returns the matching
 * recoveries plus the credential metadata so the caller can repopulate
 * IndexedDB without a re-enrollment.
 */
export async function discoverViaPasskey(
	suiClient: ClientWithCoreApi,
	rpId: string,
): Promise<PasskeyDiscovery> {
	const challenge = crypto.getRandomValues(new Uint8Array(32));
	const prfSalt = new TextEncoder().encode(PRF_SALT);

	const result = await startAuthentication({
		optionsJSON: {
			challenge: bytesToBase64Url(challenge),
			rpId,
			// Empty allowCredentials → OS shows every passkey for this RP.
			allowCredentials: [],
			userVerification: 'required',
			extensions: {
				prf: { eval: { first: prfSalt } },
			} as Record<string, unknown>,
			timeout: 60_000,
		},
	});

	const credentialId = base64UrlToBytes(result.id);
	const authenticatorData = base64UrlToBytes(result.response.authenticatorData);
	const clientDataJSON = base64UrlToBytes(result.response.clientDataJSON);
	const sigDer = base64UrlToBytes(result.response.signature);

	// Pull PRF output, same shape as @fesal-packages/ikavery-sui-sdk's authenticate helper.
	const exts = result.clientExtensionResults as {
		prf?: { results?: { first?: string | ArrayBuffer } };
	};
	const first = exts.prf?.results?.first;
	let prfOutput: Uint8Array;
	if (typeof first === 'string') {
		prfOutput = base64UrlToBytes(first);
	} else if (first instanceof ArrayBuffer) {
		prfOutput = new Uint8Array(first);
	} else {
		throw new Error(
			'Selected passkey did not return a PRF output. The original enrollment must have used a PRF-capable authenticator.',
		);
	}

	// WebAuthn assertion message = authenticatorData || sha256(clientDataJSON).
	const cdHash = sha256(clientDataJSON);
	const signedMessage = new Uint8Array(authenticatorData.length + cdHash.length);
	signedMessage.set(authenticatorData, 0);
	signedMessage.set(cdHash, authenticatorData.length);
	const msgHash = sha256(signedMessage);

	// ECDSA pubkey recovery: 2 candidates from any (r, s) signature.
	const sig = p256.Signature.fromBytes(sigDer, 'der');
	const candidates: Uint8Array[] = [];
	for (const recBit of [0, 1] as const) {
		try {
			const point = sig.addRecoveryBit(recBit).recoverPublicKey(msgHash);
			candidates.push(point.toBytes(true));
		} catch {
			// Recovery bit invalid for this signature — skip.
		}
	}
	if (candidates.length === 0) {
		throw new Error('Failed to recover any candidate public key from the assertion.');
	}

	// Try each candidate against the registry. The first one with a non-empty
	// member-id entry is the user's actual passkey (the other is mathematical
	// garbage). Even if both happen to exist as members of *something*, the
	// PRF-derived encryption address could disambiguate; we keep the first hit
	// for now since collisions are astronomically unlikely.
	let matched: { pub: Uint8Array; recoveryIds: string[] } | null = null;
	for (const pub of candidates) {
		const ids = await listRecoveriesForMember(suiClient, memberIdFor('webauthn', pub));
		if (ids.length > 0) {
			matched = { pub, recoveryIds: ids };
			break;
		}
	}
	if (!matched) {
		throw new Error(
			'This passkey is not a member of any recovery on-chain. ' +
				'If you expected to find a vault here, verify you picked the right passkey.',
		);
	}

	return {
		recoveryIds: matched.recoveryIds,
		publicKeyHex: bytesToHex(matched.pub),
		credentialIdHex: bytesToHex(credentialId),
		prfOutput,
	};
}

function bytesToBase64Url(b: Uint8Array): string {
	let s = '';
	for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Re-export so callers can repopulate the cached importer.
export { hexToBytes };
