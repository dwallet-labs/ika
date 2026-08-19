/**
 * One-off Solana setup helper. Funds `SOLANA_SOURCE_PATH` with a small SOL
 * allowance and mints `SPL_MINT_COUNT` fresh SPL tokens into source ATAs so
 * the existing `e2e-retry-spl.ts` can sweep them. Useful when the source has
 * already been swept clean and we want to re-test the recovery flow without
 * doing a fresh import.
 *
 * Required env: SOLANA_SOURCE_PATH, SOLANA_ADMIN_PATH, SOLANA_RPC, SPL_MINT_COUNT.
 */

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { createMint, getOrCreateAssociatedTokenAccount, mintTo } from '@solana/spl-token';
import { Connection, Keypair, LAMPORTS_PER_SOL, SystemProgram, Transaction } from '@solana/web3.js';

function env(k: string, fallback?: string): string {
	const v = process.env[k] ?? fallback;
	if (!v) throw new Error(`missing env ${k}`);
	return v;
}
function loadKp(p: string): Keypair {
	return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p, 'utf-8'))));
}

async function main() {
	const conn = new Connection(env('SOLANA_RPC', 'https://api.devnet.solana.com'), 'confirmed');
	const admin = loadKp(
		env('SOLANA_ADMIN_PATH', path.join(homedir(), '.config/solana/devnet-admin.json')),
	);
	const source = loadKp(env('SOLANA_SOURCE_PATH'));
	const mintCount = parseInt(env('SPL_MINT_COUNT', '8'), 10);
	const fundLamports = BigInt(0.05 * LAMPORTS_PER_SOL);
	const amountPerMint = 1_000_000n;

	console.log('admin       :', admin.publicKey.toBase58());
	console.log('source      :', source.publicKey.toBase58());
	console.log('mint count  :', mintCount);

	const adminBal = BigInt(await conn.getBalance(admin.publicKey, 'confirmed'));
	console.log('admin SOL   :', Number(adminBal) / LAMPORTS_PER_SOL);
	if (adminBal < BigInt(0.3 * LAMPORTS_PER_SOL)) throw new Error('admin needs >=0.3 SOL');

	// Top up source if it's below threshold (rent-exempt + sweep buffer).
	const srcBal = BigInt(await conn.getBalance(source.publicKey, 'confirmed'));
	console.log('source SOL  :', Number(srcBal) / LAMPORTS_PER_SOL);
	if (srcBal < BigInt(0.02 * LAMPORTS_PER_SOL)) {
		const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
		const tx = new Transaction({
			blockhash,
			lastValidBlockHeight,
			feePayer: admin.publicKey,
		});
		tx.add(
			SystemProgram.transfer({
				fromPubkey: admin.publicKey,
				toPubkey: source.publicKey,
				lamports: fundLamports,
			}),
		);
		tx.sign(admin);
		const sig = await conn.sendRawTransaction(tx.serialize());
		await conn.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, 'confirmed');
		console.log(`  funded source with ${Number(fundLamports) / LAMPORTS_PER_SOL} SOL: ${sig}`);
	}

	for (let i = 0; i < mintCount; i++) {
		const decimals = 6;
		const mint = await createMint(conn, admin, admin.publicKey, null, decimals);
		const ata = await getOrCreateAssociatedTokenAccount(conn, admin, mint, source.publicKey, false);
		await mintTo(conn, admin, mint, ata.address, admin, amountPerMint);
		console.log(
			`  [mint ${i + 1}/${mintCount}] mint=${mint.toBase58()} ata=${ata.address.toBase58()} amt=${amountPerMint}`,
		);
	}
	console.log('\n✓ SPL setup complete');
}

main().catch((e) => {
	console.error('\nspl-setup failed:', e);
	process.exit(1);
});
