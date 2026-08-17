import { Connection, PublicKey } from '@solana/web3.js';

import { decodeRecovery, discoverTokenAccounts } from '../src';

const recovery = new PublicKey('FeL8d3dsiPP4Do1yTL9quyQncfuztExq3yqwyNT1dygu');
const conn = new Connection('https://api.devnet.solana.com', 'confirmed');
const info = await conn.getAccountInfo(recovery, 'confirmed');
if (!info) {
	console.log('recovery not found');
	process.exit(0);
}
const rec = decodeRecovery(new Uint8Array(info.data));
const dwallet = new PublicKey(rec.dwallet);
console.log('dwallet pubkey:', dwallet.toBase58());
const bal = await conn.getBalance(dwallet, 'confirmed');
console.log('dwallet SOL balance:', bal, `(${(bal / 1e9).toFixed(6)} SOL)`);
const toks = await discoverTokenAccounts(conn, dwallet);
console.log('token holdings remaining:', toks.length);
for (const t of toks) {
	console.log(`  mint=${t.mint.toBase58()} amount=${t.amount} decimals=${t.decimals}`);
}
