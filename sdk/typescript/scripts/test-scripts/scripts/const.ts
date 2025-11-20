import { fromHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import dotenv from 'dotenv';

dotenv.config();

const aliceKeypair = process.env.ALICE_KEYPAIR ?? '';
const bobKeypair = process.env.BOB_KEYPAIR ?? '';

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
export const ALICE_IKA_COIN_ID = process.env.ALICE_IKA_COIN_ID ?? '';
export const BOB_IKA_COIN_ID = process.env.BOB_IKA_COIN_ID ?? '';
