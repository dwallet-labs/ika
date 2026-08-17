'use client';

import { authenticate, registerPasskey } from '@fesal-packages/ikavery-core';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';
import { parseSerializedSignature } from '@mysten/sui/cryptography';

import type { StoredMember } from '@/store/setup';

import { dAppKit } from './dapp-kit';
import { deriveIdentity } from './derive';
import { env } from './env';
import { bytesToHex } from './storage';

/**
 * Capture a passkey member by registering a new WebAuthn credential on this
 * device, then immediately authenticating to extract the PRF output. The PRF
 * seed deterministically derives Ika's `UserShareEncryptionKeys`, so the same
 * physical passkey always produces the same encryption identity.
 *
 * The new credential is rooted in this browser; cross-device passkeys (phone
 * via QR, hardware key) work too because the WebAuthn UI handles the dance.
 */
export async function capturePasskeyMember(
	label?: string,
): Promise<StoredMember & { kind: 'passkey' }> {
	const userId = crypto.getRandomValues(new Uint8Array(16));
	// Stable label — same across enrollments so the passkey manager surfaces a
	// recognizable "Recovery member" entry instead of a date-stamped mystery.
	// Each call still mints a fresh credential (random userId), so multiple
	// members coexist; the entries simply share a clean display name.
	const cred = await registerPasskey({
		rpId: env.rpId,
		rpName: env.rpName,
		userId,
		userName: label ?? 'recovery-member',
		userDisplayName: label ?? 'Recovery member',
	});
	const challenge = crypto.getRandomValues(new Uint8Array(32));
	const auth = await authenticate({
		credentialId: cred.credentialId,
		publicKey: cred.publicKey,
		challenge,
		rpId: env.rpId,
	});
	if (!auth.prfOutput || auth.prfOutput.length !== 32) {
		throw new Error(
			'This authenticator does not support the WebAuthn PRF extension. Try a different device or browser.',
		);
	}
	const identity = await deriveIdentity(auth.prfOutput);
	return {
		kind: 'passkey',
		publicKeyHex: bytesToHex(cred.publicKey),
		credentialIdHex: bytesToHex(cred.credentialId),
		encryptionKeysBytesHex: bytesToHex(identity.keysBytes),
		encryptionAddress: identity.encryptionAddress,
	};
}

const ALL_WALLET_SCHEMES = ['ed25519', 'secp256k1', 'secp256r1'] as const;
type WalletScheme = (typeof ALL_WALLET_SCHEMES)[number];

const SUI_SCHEME_TO_WALLET: Record<string, WalletScheme | undefined> = {
	ED25519: 'ed25519',
	Secp256k1: 'secp256k1',
	Secp256r1: 'secp256r1',
};

const SUI_SCHEME_TO_APPROVER_ORIGIN: Record<
	string,
	'zklogin' | 'multisig' | 'passkey' | 'unknown' | undefined
> = {
	ZkLogin: 'zklogin',
	MultiSig: 'multisig',
	Passkey: 'passkey',
};

/**
 * Capture a wallet member by asking the wallet to sign a fixed personal
 * message, then deriving a deterministic 32-byte seed from that signature.
 * Same wallet + same message ⇒ same seed ⇒ same encryption identity, so the
 * member can re-derive their keys on any later device by signing the message
 * again.
 *
 * The wallet's signature scheme + raw public key (parsed out of the wrapped
 * `signPersonalMessage` output) is what gets registered as the canonical
 * member identity. Authorization at propose/approve/execute time is a fresh
 * `signPersonalMessage` over the operation challenge — never `ctx.sender()` —
 * so the gas-paying wallet can be anyone (typically the same wallet, in
 * sponsor mode).
 *
 * The encryption key is owned by a *separate* Sui address derived from the
 * seed; we hold the keypair locally and re-derive from the wallet's
 * deterministic signature on any later device.
 */
export const MEMBER_ENCRYPTION_SEED_MESSAGE = `recovery-encryption-seed:v1:${env.recoveryPackageId}`;

export async function captureWalletMember(
	wallet: UiWallet,
	account: UiWalletAccount,
): Promise<StoredMember & { kind: 'wallet' | 'approver' }> {
	const message = new TextEncoder().encode(MEMBER_ENCRYPTION_SEED_MESSAGE);
	// dApp Kit pins the chain identifier from its current network, which is the
	// same chain the gas-payer wallet is connected to. Some wallets (notably
	// Slush) reject a request without one.
	const { signature } = await dAppKit.signPersonalMessage({
		account,
		message,
	});

	// Parse the wrapped serialized signature to learn the scheme + the raw
	// pubkey. The wallet's `account.publicKey` doesn't carry scheme info, so we
	// round-trip through one signature to be sure.
	const parsed = parseSerializedSignature(signature);
	const rawScheme = SUI_SCHEME_TO_WALLET[parsed.signatureScheme];

	// Non-raw schemes (zkLogin, MultiSig, Passkey-as-sender) don't produce a
	// deterministic signature for our seed message — the ephemeral key /
	// composition rotates per session. We can't derive a stable encryption
	// identity from such a signature, so we register the wallet as an
	// approver-only `sender_address` member: auth via `ctx.sender()` (which
	// Sui validators have already verified), no share, can vote but cannot
	// execute. Caller surfaces this trade-off in the UI.
	if (
		!rawScheme ||
		parsed.signatureScheme === 'MultiSig' ||
		!parsed.signature ||
		!('publicKey' in parsed)
	) {
		return {
			kind: 'approver',
			address: account.address,
			walletName: wallet.name,
			origin: SUI_SCHEME_TO_APPROVER_ORIGIN[parsed.signatureScheme] ?? 'unknown',
		};
	}

	// Hash the wallet signature bytes (the raw 64-byte sig, sans flag/pk) to a
	// 32-byte seed. Same signature on later runs ⇒ same seed.
	const sigCopy = new Uint8Array(parsed.signature);
	const seedBuffer = await crypto.subtle.digest('SHA-256', sigCopy);
	const seed = new Uint8Array(seedBuffer);
	const identity = await deriveIdentity(seed);
	return {
		kind: 'wallet',
		address: account.address,
		walletName: wallet.name,
		scheme: rawScheme,
		publicKeyHex: bytesToHex(new Uint8Array(parsed.publicKey)),
		encryptionKeysBytesHex: bytesToHex(identity.keysBytes),
		encryptionAddress: identity.encryptionAddress,
	};
}
