'use client';

import { derSigToCompactRaw64 } from '@fesal-packages/ikavery-core';
import {
	listAllRecoveries,
	listRecoveriesForMember,
	packMemberSlot,
	SCHEME_WEBAUTHN,
	type DecodedRecovery,
} from '@fesal-packages/ikavery-solana-sdk';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import type { Connection } from '@solana/web3.js';

import { bytesToHex } from '@/lib/storage';

export interface PasskeyDiscovery {
	/** Recovery PDAs (base58) whose roster includes this passkey. */
	recoveryIds: string[];
	/** 33-byte compressed P-256 pubkey, hex-encoded. */
	publicKeyHex: string;
	/** Credential id captured at enrollment, hex-encoded. */
	credentialIdHex: string;
}

/**
 * Trigger the OS passkey picker (no `allowCredentials` → every passkey for
 * this RP is shown), recover both candidate ECDSA public keys from the
 * assertion signature, then look each up in the on-chain registry. Returns
 * the recoveries the matching passkey is enrolled in, plus enough metadata
 * to repopulate IndexedDB without re-enrollment.
 *
 * Mirrors the Sui flow but skips the PRF step — Solana's pre-alpha doesn't
 * keep encryption keys per device, so the credential id + pubkey are all we
 * need to resume.
 */
export async function discoverViaPasskey(
	connection: Connection,
	rpId: string,
	/**
	 * Pre-fetched recovery list — pass it to skip a redundant
	 * `getProgramAccounts` if the caller already cached one (e.g. from React
	 * Query). When omitted we fetch on demand.
	 */
	recoveries?: DecodedRecovery[],
): Promise<PasskeyDiscovery> {
	if (
		typeof navigator === 'undefined' ||
		!navigator.credentials ||
		typeof navigator.credentials.get !== 'function'
	) {
		throw new Error(
			"WebAuthn isn't available in this environment — discovery needs a browser with PublicKeyCredential support.",
		);
	}

	const challenge = crypto.getRandomValues(new Uint8Array(32));
	const cred = (await navigator.credentials.get({
		publicKey: {
			challenge: toArrayBuffer(challenge),
			rpId,
			allowCredentials: [],
			userVerification: 'required',
			timeout: 60_000,
		},
	})) as PublicKeyCredential | null;
	if (!cred) {
		throw new Error('Passkey selection was cancelled.');
	}
	const response = cred.response as AuthenticatorAssertionResponse;
	const authenticatorData = new Uint8Array(response.authenticatorData);
	const clientDataJSON = new Uint8Array(response.clientDataJSON);
	const derSignature = new Uint8Array(response.signature);
	const credentialId = new Uint8Array(cred.rawId);

	// WebAuthn signs `authenticatorData || sha256(clientDataJSON)`.
	const cdHash = sha256(clientDataJSON);
	const signedMessage = new Uint8Array(authenticatorData.length + cdHash.length);
	signedMessage.set(authenticatorData, 0);
	signedMessage.set(cdHash, authenticatorData.length);
	const msgHash = sha256(signedMessage);

	const rawSig = derSigToCompactRaw64(derSignature);
	const sig = p256.Signature.fromCompact(rawSig);

	// ECDSA pubkey-recovery yields up to 2 candidates per (r, s); try each
	// against the registry and keep the one with a non-empty match. The
	// unrecovered candidate is mathematical garbage and won't match anything.
	const candidates: Uint8Array[] = [];
	for (const recBit of [0, 1] as const) {
		try {
			const point = sig.addRecoveryBit(recBit).recoverPublicKey(msgHash);
			candidates.push(point.toRawBytes(true));
		} catch {
			/* recovery bit invalid for this signature — skip */
		}
	}
	if (candidates.length === 0) {
		throw new Error('Failed to recover any candidate public key from the assertion.');
	}

	// Both candidates run against the same recovery list — fetch once
	// (or reuse the cached one), then scan client-side.
	const list = recoveries ?? (await listAllRecoveries(connection));
	let matched: { pub: Uint8Array; recoveryIds: string[] } | null = null;
	for (const pub of candidates) {
		const slot = packMemberSlot(SCHEME_WEBAUTHN, pub);
		const hits = await listRecoveriesForMember(connection, slot, {
			recoveries: list,
		});
		if (hits.length > 0) {
			matched = {
				pub,
				recoveryIds: hits.map((h) => h.recovery.toBase58()),
			};
			break;
		}
	}
	if (!matched) {
		throw new Error(
			"This passkey isn't a member of any recovery on-chain. " +
				'If you expected to find a vault here, verify you picked the right passkey.',
		);
	}

	return {
		recoveryIds: matched.recoveryIds,
		publicKeyHex: bytesToHex(matched.pub),
		credentialIdHex: bytesToHex(credentialId),
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
