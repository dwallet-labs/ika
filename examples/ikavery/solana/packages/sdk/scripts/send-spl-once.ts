/**
 * One-off helper — mint a fresh devnet SPL token + send some to a recipient.
 *
 * Usage (from solana/packages/sdk/):
 *   bun run scripts/send-spl-once.ts <recipient_pubkey> [amount=10] [decimals=6]
 *
 * Env:
 *   SOLANA_RPC      defaults to https://api.devnet.solana.com
 *   SOLANA_KEYPAIR  defaults to ~/.config/solana/id.json
 *
 * The recipient address is allowed to be off-curve (e.g. a dWallet pubkey)
 * because we pass `allowOwnerOffCurve: true` to `getOrCreateAssociatedTokenAccount`.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
	createMint,
	getAssociatedTokenAddressSync,
	getOrCreateAssociatedTokenAccount,
	mintTo,
} from '@solana/spl-token';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';

async function main() {
	const recipientArg = process.argv[2];
	if (!recipientArg) {
		console.error(
			'usage: bun run scripts/send-spl-once.ts <recipient_pubkey> [amount=10] [decimals=6]',
		);
		process.exit(1);
	}
	const recipient = new PublicKey(recipientArg);
	const decimals = Number.parseInt(process.argv[4] ?? '6', 10);
	const amountUi = Number.parseFloat(process.argv[3] ?? '10');
	const amountBase = BigInt(Math.round(amountUi * 10 ** decimals));

	const rpc = process.env.SOLANA_RPC ?? 'https://api.devnet.solana.com';
	const keypairPath =
		process.env.SOLANA_KEYPAIR ?? path.join(os.homedir(), '.config/solana/id.json');
	const payer = Keypair.fromSecretKey(
		Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, 'utf8'))),
	);
	const connection = new Connection(rpc, 'confirmed');

	const balance = await connection.getBalance(payer.publicKey);
	console.log('rpc:        ', rpc);
	console.log('payer:      ', payer.publicKey.toBase58(), `(${balance / 1e9} SOL)`);
	console.log('recipient:  ', recipient.toBase58());
	console.log('amount:     ', `${amountUi} (= ${amountBase} base units)`);
	console.log('decimals:   ', decimals);
	if (balance < 50_000_000) {
		console.error('payer has < 0.05 SOL; mint rent + ATA rent will fail.');
		process.exit(1);
	}

	console.log('\n[1/3] creating fresh SPL mint…');
	const mint = await createMint(
		connection,
		payer,
		payer.publicKey,
		null, // no freeze authority
		decimals,
	);
	console.log('  mint:      ', mint.toBase58());

	console.log('\n[2/3] creating recipient ATA (off-curve allowed)…');
	const ata = await getOrCreateAssociatedTokenAccount(
		connection,
		payer,
		mint,
		recipient,
		true, // allowOwnerOffCurve — dWallet pubkeys are off-curve
	);
	console.log('  ata:       ', ata.address.toBase58());
	// Verify deterministic ATA derivation matches.
	const expected = getAssociatedTokenAddressSync(mint, recipient, true);
	if (!expected.equals(ata.address)) {
		throw new Error(
			`ATA derivation mismatch: expected ${expected.toBase58()}, got ${ata.address.toBase58()}`,
		);
	}

	console.log('\n[3/3] minting tokens to recipient ATA…');
	const sig = await mintTo(connection, payer, mint, ata.address, payer, amountBase);
	console.log('  mint sig:  ', sig);

	console.log('\nDone.');
	console.log('recipient:  ', recipient.toBase58());
	console.log('mint:       ', mint.toBase58());
	console.log('ata:        ', ata.address.toBase58());
	console.log(`solscan:    https://solscan.io/account/${ata.address.toBase58()}?cluster=devnet`);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
