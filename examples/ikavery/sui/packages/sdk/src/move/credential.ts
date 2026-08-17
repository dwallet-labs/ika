import { authenticate, type WebAuthnAssertion } from '@fesal-packages/ikavery-core';
import type { Signer } from '@mysten/sui/cryptography';
import { parseSerializedSignature } from '@mysten/sui/cryptography';
import type { Transaction, TransactionArgument } from '@mysten/sui/transactions';

import * as moveAssertion from '../generated/recovery/assertion';
import * as moveAuth from '../generated/recovery/auth';

/**
 * A ready-to-use credential the SDK turns into a Move-side `auth::Credential`.
 *
 * Each variant maps to one of the five schemes encoded in `auth::Credential`.
 * The Move side derives `[scheme_byte, ...pubkey_or_address]` from the
 * variant and looks the resulting voter id up in the unified members set.
 *
 * For raw schemes (ed25519/secp256k1/secp256r1), `signature` is the Move-ready
 * raw signature: ed25519 = 64 bytes, secp256k1/r1 = 64-byte compact (no
 * recovery byte). All three are signed over Sui's personal-message digest of
 * the challenge — the same digest a wallet's `signPersonalMessage` produces.
 * Use {@link credentialFromSerializedSignature} to peel a wallet's wrapped
 * output (flag byte || sig || pubkey) back into this raw shape.
 *
 * `sender_address` is the approver-only variant: no signature, no pubkey;
 * authorization is `ctx.sender() == address`. Use this for zkLogin / MultiSig
 * / Passkey-as-sender wallets — Sui validators verify those signatures on
 * the way in, and we just check the sender is in the members set. These
 * members can propose + approve but cannot execute (no encrypted share).
 */
export type CredentialInput =
	| {
			scheme: 'ed25519';
			/** 32 bytes. */
			publicKey: Uint8Array;
			/** 64 bytes. */
			signature: Uint8Array;
	  }
	| {
			scheme: 'secp256k1';
			/** 33 bytes (compressed). */
			publicKey: Uint8Array;
			/** 64 bytes (compact, no recovery). */
			signature: Uint8Array;
	  }
	| {
			scheme: 'secp256r1';
			/** 33 bytes (compressed). */
			publicKey: Uint8Array;
			/** 64 bytes (compact, no recovery). */
			signature: Uint8Array;
	  }
	| {
			scheme: 'webauthn';
			/**
			 * Full WebAuthn assertion envelope. The 32-byte operation challenge must
			 * already be base64url-encoded into `clientDataJSON.challenge`.
			 */
			assertion: WebAuthnAssertion;
	  }
	| {
			/**
			 * Approver-only. Authorization comes from `ctx.sender() == address`,
			 * which is what Sui's validators have already enforced for the calling
			 * tx. No signature args are passed — the Move builder reads the sender
			 * out of the PTB context.
			 */
			scheme: 'sender_address';
			/** Sui address of the member (matches whatever signs the calling tx). */
			address: string;
	  };

export function buildCredential(
	tx: Transaction,
	packageId: string,
	input: CredentialInput,
): TransactionArgument {
	switch (input.scheme) {
		case 'ed25519':
			return moveAuth.ed25519Credential({
				package: packageId,
				arguments: [Array.from(input.signature), Array.from(input.publicKey)],
			})(tx);
		case 'secp256k1':
			return moveAuth.secp256k1Credential({
				package: packageId,
				arguments: [Array.from(input.signature), Array.from(input.publicKey)],
			})(tx);
		case 'secp256r1':
			return moveAuth.secp256r1Credential({
				package: packageId,
				arguments: [Array.from(input.signature), Array.from(input.publicKey)],
			})(tx);
		case 'webauthn': {
			const a = moveAssertion._new({
				package: packageId,
				arguments: [
					Array.from(input.assertion.publicKey),
					Array.from(input.assertion.authenticatorData),
					Array.from(input.assertion.clientDataJSON),
					Array.from(input.assertion.signature),
				],
			})(tx);
			return moveAuth.webauthnCredential({
				package: packageId,
				arguments: [a],
			})(tx);
		}
		case 'sender_address':
			// No args — the Move builder reads `ctx.sender()` itself. The address
			// on the input is informational; auth gate is enforced inside `verify`.
			return moveAuth.senderCredential({ package: packageId })(tx);
	}
}

/**
 * Caller-supplied credential producer: takes the operation challenge (32 bytes)
 * and returns a `CredentialInput` ready for `buildCredential`. CLI scripts
 * wrap a Keypair (see {@link authSignerFromKeypair}); browser wallets wrap
 * their `signPersonalMessage` feature and unwrap with
 * {@link credentialFromSerializedSignature}; passkey integrations wrap
 * WebAuthn (see {@link authSignerFromPasskey}).
 */
export interface AuthSigner {
	sign(challenge: Uint8Array): Promise<CredentialInput>;
}

const SUI_SCHEME_TO_CRED = {
	ED25519: 'ed25519',
	Secp256k1: 'secp256k1',
	Secp256r1: 'secp256r1',
} as const;

/**
 * Decode a Sui-wallet `signPersonalMessage` output into a `CredentialInput`.
 * Strips the flag byte + trailing public key and emits the 64-byte raw
 * signature Move expects. Throws on Passkey / ZkLogin / MultiSig — those have
 * their own credential paths.
 */
export function credentialFromSerializedSignature(serializedSignature: string): CredentialInput {
	const parsed = parseSerializedSignature(serializedSignature);
	const scheme = SUI_SCHEME_TO_CRED[parsed.signatureScheme as keyof typeof SUI_SCHEME_TO_CRED];
	if (!scheme) {
		throw new Error(
			`credentialFromSerializedSignature: unsupported scheme ${parsed.signatureScheme}`,
		);
	}
	if (!parsed.signature || !parsed.publicKey) {
		throw new Error('credentialFromSerializedSignature: missing signature or pubkey');
	}
	return {
		scheme,
		publicKey: parsed.publicKey,
		signature: parsed.signature,
	} as CredentialInput;
}

/**
 * Wrap a Sui `Signer` (Keypair) as an `AuthSigner` via `signPersonalMessage`.
 * The keypair's signature scheme determines which `Credential` variant is
 * produced. WebAuthn passkeys are not Sui keypairs — use
 * {@link authSignerFromPasskey} instead.
 */
export function authSignerFromKeypair(signer: Signer): AuthSigner {
	return {
		async sign(challenge: Uint8Array) {
			const { signature } = await signer.signPersonalMessage(challenge);
			return credentialFromSerializedSignature(signature);
		},
	};
}

/**
 * Wrap a WebAuthn passkey credential as an `AuthSigner`. Each `sign` call
 * triggers a fresh authenticator ceremony with the operation challenge baked
 * into `clientDataJSON`.
 */
export function authSignerFromPasskey(opts: {
	credentialId: Uint8Array;
	/** Compressed P-256 public key (33 bytes). */
	publicKey: Uint8Array;
	rpId: string;
}): AuthSigner {
	return {
		async sign(challenge: Uint8Array) {
			const { assertion } = await authenticate({
				credentialId: opts.credentialId,
				publicKey: opts.publicKey,
				challenge,
				rpId: opts.rpId,
			});
			return { scheme: 'webauthn', assertion };
		},
	};
}
