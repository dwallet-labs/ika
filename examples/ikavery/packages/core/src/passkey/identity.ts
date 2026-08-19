import { Curve, UserShareEncryptionKeys } from '@ika.xyz/sdk';

/**
 * Derive Ika's encryption-layer identity from a WebAuthn-PRF seed.
 *
 * `UserShareEncryptionKeys` carries the class-groups encryption key and the
 * ed25519 signer Ika uses to verify "I own this encryption key" on-chain. The
 * Sui address it exposes (`getSuiAddress`) is the one Ika binds the encryption
 * key to. Any Sui address can pay gas for the Ika-internal PTBs that register
 * or accept encrypted shares — the encryption-key proof is signed inside the
 * `UserShareEncryptionKeys` instance itself.
 *
 * The derived address is **not** the recovery-authorization identity. That is
 * the WebAuthn passkey's public key; see `recovery::assertion`.
 */
export interface DeviceIdentity {
	userShareEncryptionKeys: UserShareEncryptionKeys;
	/** Equals `userShareEncryptionKeys.getSuiAddress()`. */
	encryptionKeySuiAddress: string;
}

export async function deriveDeviceIdentity(prfSeed: Uint8Array): Promise<DeviceIdentity> {
	if (prfSeed.length !== 32) {
		throw new Error(`deriveDeviceIdentity: expected 32-byte PRF seed, got ${prfSeed.length}`);
	}
	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		prfSeed,
		Curve.ED25519,
	);
	return {
		userShareEncryptionKeys,
		encryptionKeySuiAddress: userShareEncryptionKeys.getSuiAddress(),
	};
}
