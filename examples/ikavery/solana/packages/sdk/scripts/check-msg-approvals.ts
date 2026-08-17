import {
	buildSweepBundle,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
	solanaIntentDigest,
	type SourceTokenAccount,
} from '@fesal-packages/ikavery-core';
import { keccak_256 } from '@noble/hashes/sha3';
import { Connection, PublicKey } from '@solana/web3.js';

import {
	decodeProposal,
	decodeRecovery,
	discoverTokenAccounts,
	ikaDwallet,
	MAX_MESSAGE_BYTES,
	proposalPda,
} from '../src';

const { CURVE_CURVE25519, SIG_SCHEME_EDDSA_SHA512, messageApprovalPda } = ikaDwallet;

const recovery = new PublicKey('FeL8d3dsiPP4Do1yTL9quyQncfuztExq3yqwyNT1dygu');
const destination = new PublicKey(
	'DGVY3W6Ghs2PiG3T2new6duEZV8ihRBYdEnD2jS1zqXK', // best guess; if wrong we re-derive from saved bundle
);
const conn = new Connection('https://api.devnet.solana.com', 'confirmed');

const recInfo = await conn.getAccountInfo(recovery, 'confirmed');
const rec = decodeRecovery(new Uint8Array(recInfo!.data));
const dwallet = new PublicKey(rec.dwallet);
console.log('dwallet:', dwallet.toBase58());

const propPda = proposalPda(recovery, 0);
const propInfo = await conn.getAccountInfo(propPda, 'confirmed');
const prop = decodeProposal(new Uint8Array(propInfo!.data));

for (let i = 0; i < prop.intentDigests.length; i++) {
	const digest = prop.intentDigests[i] as Uint8Array;
	console.log(`tx ${i}: digest=${Buffer.from(digest).toString('hex').slice(0, 24)}…`);
}

// Check whether MessageApprovals exist on chain for each digest. We don't
// know the message bytes (they're sweep msgs from prior bundle build) but
// we can compute the expected MessageApproval PDA for any digest by
// supplying the keccak256 of the actual message bytes — which we don't
// have stored here. So instead, just confirm whether ANY MessageApproval
// PDA exists for the dWallet.
console.log('(MessageApproval PDA verification needs the original messageBytes)');
