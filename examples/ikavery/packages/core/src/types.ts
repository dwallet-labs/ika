/** Chain-agnostic types shared by the Sui and Solana ikavery SDKs. */

/** A WebAuthn assertion shaped for verification on either chain. */
export interface WebAuthnAssertion {
	/** Compressed secp256r1 (33 bytes). */
	publicKey: Uint8Array;
	authenticatorData: Uint8Array;
	clientDataJSON: Uint8Array;
	/** Raw r||s ECDSA secp256r1 signature, 64 bytes. */
	signature: Uint8Array;
}

/**
 * Per-device passkey credential. Stored on the device the credential lives on
 * (cloud-synced or platform-bound, depending on the authenticator).
 */
export interface PasskeyCredential {
	credentialId: Uint8Array;
	/** Compressed secp256r1 public key (33 bytes), suitable for on-chain use. */
	publicKey: Uint8Array;
}

/** Output of an authenticator assertion that returned both a signature and a PRF eval. */
export interface PasskeyAssertionResult {
	assertion: WebAuthnAssertion;
	/** 32-byte PRF output; only present when the credential supports the prf extension. */
	prfOutput?: Uint8Array;
}
