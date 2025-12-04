import { fromHex } from '@mysten/bcs';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import dotenv from 'dotenv';

import { IkaClient } from '../../../src/client/ika-client';
import { getNetworkConfig } from '../../../src/client/network-configs';

dotenv.config();

const aliceKeypair =
	process.env.ALICE_KEYPAIR ?? 'a3ec6784c3d6ad4badb3d7642eed0ee2fb99f9981d180526f204a8f8a947b3d3';
const bobKeypair =
	process.env.BOB_KEYPAIR ?? '9888d648407bfd7b560e8770d8c36b5c2f362409be008c6def03fa32ecd30bc7';

// Alice (Signer 1)
export const alice = Ed25519Keypair.fromSecretKey(fromHex(aliceKeypair));
export const aliceAddress = alice.getPublicKey().toSuiAddress();

// Bob (Signer 2)
export const bob = Ed25519Keypair.fromSecretKey(fromHex(bobKeypair));
export const bobAddress = bob.getPublicKey().toSuiAddress();

export const signer = alice;
export const signer2 = bob;
export const signerAddress = aliceAddress;
export const signerAddress2 = bobAddress;

// IKA Coin IDs
export const ALICE_IKA_COIN_ID =
	process.env.ALICE_IKA_COIN_ID ??
	'0xdef91825eb9393bfa66f7929c5c62bfa0639f51fba3a670eef7a5f63f0b11aa6';
export const BOB_IKA_COIN_ID =
	process.env.BOB_IKA_COIN_ID ??
	'0xa55b12fc3100344bc40dffc166c65aa41100589d35dbc36a8f9b08ee89857689';

export const suiClient = new SuiClient({ url: 'https://sui-rpc.publicnode.com' });

export const ikaClient = new IkaClient({
	suiClient,
	config: getNetworkConfig('mainnet'),
});
