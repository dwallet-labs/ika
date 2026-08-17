import { Connection, PublicKey } from '@solana/web3.js';

import { decodeProposal, proposalPda } from '../src';

const recovery = new PublicKey('FeL8d3dsiPP4Do1yTL9quyQncfuztExq3yqwyNT1dygu');
const conn = new Connection('https://api.devnet.solana.com', 'confirmed');
const pda = proposalPda(recovery, 0);
console.log('proposal pda:', pda.toBase58());
const info = await conn.getAccountInfo(pda, 'confirmed');
if (!info) {
	console.log('not found');
	process.exit(0);
}
const acct = decodeProposal(new Uint8Array(info.data));
console.log('status:', acct.status);
console.log('approvalCount:', acct.approvalCount);
console.log('executedBitmap: 0b' + acct.executedBitmap.toString(2).padStart(8, '0'));
console.log('intentDigests.length:', acct.intentDigests.length);
acct.intentDigests.forEach((d: Uint8Array, i: number) => {
	const bit = (acct.executedBitmap >> i) & 1;
	console.log(
		`  [${i}] ${Buffer.from(d).toString('hex').slice(0, 24)}…  ${bit ? 'DONE' : 'pending'}`,
	);
});
const n = acct.intentDigests.length;
const fullMask = n >= 8 ? 0xff : (1 << n) - 1;
console.log('fullMask:', fullMask, 'complete:', acct.executedBitmap === fullMask);
