'use client';

import { authenticate } from '@fesal-packages/ikavery-core';
import {
	credentialFromSerializedSignature,
	type CredentialInput,
} from '@fesal-packages/ikavery-sui-sdk';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';

import type { SignerOption } from '@/components/vault/signer-gas-payer';
import type { AuthIdentity } from '@/workers/session.worker';

import { dAppKit } from './dapp-kit';
import { env } from './env';
import { hexToBytes } from './storage';

/** Translate a UI `SignerOption` into the worker's transport-safe identity. */
export function signerOptionToIdentity(option: SignerOption): AuthIdentity {
	if (option.kind === 'passkey') {
		return {
			kind: 'passkey',
			credentialIdHex: option.importer.credentialIdHex,
			publicKeyHex: option.importer.publicKeyHex,
		};
	}
	if (option.kind === 'approver') {
		return { kind: 'approver', address: option.address };
	}
	return { kind: 'wallet', address: option.address };
}

/**
 * Resolve a worker `credentialRequest` into a `CredentialInput` by routing the
 * challenge through the browser-side primitive that matches the identity:
 *   - passkey  → WebAuthn ceremony (`@fesal-packages/ikavery-sui-sdk` authenticate())
 *   - wallet   → wallet's `signPersonalMessage`, then unwrap the serialized
 *                signature into Move's raw scheme + sig + pubkey.
 */
export async function resolveCredentialRequest(
	challenge: Uint8Array,
	identity: AuthIdentity,
	opts: {
		/** All wallets `useWallets()` returned — used only for the wallet path. */
		wallets: readonly UiWallet[];
	},
): Promise<CredentialInput> {
	if (identity.kind === 'passkey') {
		const { assertion } = await authenticate({
			credentialId: hexToBytes(identity.credentialIdHex),
			publicKey: hexToBytes(identity.publicKeyHex),
			challenge,
			rpId: env.rpId,
		});
		return { scheme: 'webauthn', assertion };
	}

	if (identity.kind === 'approver') {
		return { scheme: 'sender_address', address: identity.address };
	}

	const wallet = opts.wallets.find((w) =>
		w.accounts.some((a) => a.address.toLowerCase() === identity.address.toLowerCase()),
	);
	if (!wallet) {
		throw new Error(
			`Auth wallet for ${identity.address.slice(0, 10)}… isn't connected. ` +
				'Reconnect it before signing.',
		);
	}
	const account = wallet.accounts.find(
		(a) => a.address.toLowerCase() === identity.address.toLowerCase(),
	);
	if (!account) {
		throw new Error(`Wallet "${wallet.name}" no longer exposes ${identity.address.slice(0, 10)}…`);
	}
	const { signature } = await dAppKit.signPersonalMessage({
		account,
		message: challenge,
	});
	return credentialFromSerializedSignature(signature);
}
