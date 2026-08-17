import { bytesToHex } from '@fesal-packages/ikavery-frontend-ui';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1PublicKey } from '@mysten/sui/keypairs/secp256k1';
import { Secp256r1PublicKey } from '@mysten/sui/keypairs/secp256r1';

import type { Scheme, VaultMember } from './recovery-state';

export { bytesToHex, hexToBytes, truncateAddress } from '@fesal-packages/ikavery-frontend-ui';

export function schemeLabel(scheme: Scheme): string {
	if (scheme === 'webauthn') return 'Passkey';
	if (scheme === 'sender_address') return 'Approver-only';
	return `Wallet · ${scheme}`;
}

/**
 * Render a member's user-facing identity. For wallet schemes that map onto a
 * Sui address (ed25519/secp256k1/secp256r1) we derive the address rather than
 * showing the raw pubkey hex, since the address is what users recognize from
 * their wallet UI. Passkeys keep the hex pubkey since they have no chain
 * address. `sender_address` is already an address.
 */
export function renderMemberIdentity(m: VaultMember): string {
	switch (m.scheme) {
		case 'ed25519':
			return new Ed25519PublicKey(m.publicKey).toSuiAddress();
		case 'secp256k1':
			return new Secp256k1PublicKey(m.publicKey).toSuiAddress();
		case 'secp256r1':
			return new Secp256r1PublicKey(m.publicKey).toSuiAddress();
		case 'sender_address':
			return `0x${bytesToHex(m.publicKey)}`;
		default:
			return bytesToHex(m.publicKey);
	}
}
