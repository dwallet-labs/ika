/**
 * Retry only the recovery half of the prior failed e2e (multi-tx SPL).
 *
 * Reuses the Recovery + dWallet + minted SPL tokens left over from
 * `e2e-enrollment-spl.ts`'s second run, which timed out at execute because of
 * a presign-pairing bug (swap_remove(0) order in Move). The SDK now mirrors
 * that order in `proposeRecovery`, so we just need to:
 *   1. Replenish 2 fresh presigns (1 leftover from prior propose).
 *   2. Build the SOL+SPL sweep against the existing source-4 wallet.
 *   3. Propose (signer1 sender-cred), approve (signer2), execute, broadcast.
 *
 * Required env (most reuse the prior e2e):
 *   SUI_KEYPAIR_1, SUI_KEYPAIR_2, RECOVERY_PACKAGE_ID, RECOVERY_REGISTRY_ID,
 *   SOLANA_SOURCE_PATH, SOLANA_DESTINATION, SOLANA_RPC, SUI_RPC_URL,
 *   RECOVERY_ID — shared `Recovery` object id from the prior run.
 */

import { readFileSync } from 'node:fs';
import { Curve, getNetworkConfig, IkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { getAccount, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { Connection, LAMPORTS_PER_SOL, PublicKey, Keypair as SolKeypair } from '@solana/web3.js';

import { RecoveryClient } from '../src/client';
import {
	approveRecovery,
	executeRecovery,
	previewProposal,
	proposeRecovery,
} from '../src/flows/recover';
import { readRecoveryState } from '../src/flows/state';
import * as moveRecovery from '../src/generated/recovery/recovery';
import { authSignerFromKeypair } from '../src/move/credential';
import { broadcastSignedTransactions } from '../src/solana/broadcast';
import {
	buildSweepBundle,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
	type SourceTokenAccount,
} from '../src/solana/build-sweep';

function env(k: string, fallback?: string): string {
	const v = process.env[k] ?? fallback;
	if (!v) throw new Error(`missing env ${k}`);
	return v;
}
function loadSuiKeypair(b: string): Ed25519Keypair {
	const d = decodeSuiPrivateKey(b);
	if (d.scheme !== 'ED25519') throw new Error(`expected ED25519, got ${d.scheme}`);
	return Ed25519Keypair.fromSecretKey(d.secretKey);
}
function loadSolanaKeypair(p: string): SolKeypair {
	return SolKeypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p, 'utf-8'))));
}

async function replenishPresigns(
	client: RecoveryClient,
	signer: Ed25519Keypair,
	count: number,
	perCallIka: bigint,
	perCallSui: bigint,
) {
	const tx = new Transaction();
	const totalIka = perCallIka * BigInt(count);
	const totalSui = perCallSui * BigInt(count);
	const ikaCoin = coinWithBalance({
		balance: totalIka,
		type: client.ikaCoinType,
	});
	const suiCoin = coinWithBalance({ balance: totalSui });
	tx.add(
		moveRecovery.replenishPresigns({
			package: client.ref.packageId,
			arguments: [
				client.ref.recoveryId,
				client.ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				BigInt(count),
				ikaCoin,
				suiCoin,
			],
		}),
	);
	tx.transferObjects([ikaCoin, suiCoin], signer.toSuiAddress());
	const r = await client.suiClient.core.signAndExecuteTransaction({
		transaction: tx,
		signer,
	});
	if (r.$kind !== 'Transaction')
		throw new Error(`replenishPresigns: ${JSON.stringify(r.FailedTransaction.status)}`);
	return r.Transaction.digest;
}

async function waitForPresigns(client: RecoveryClient, expected: number, timeoutMs = 600_000) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const state = await readRecoveryState(client);
		let completed = 0;
		for (const id of state.presignIds) {
			try {
				await client.ikaClient.getPresignInParticularState(id, 'Completed', {
					timeout: 1500,
					interval: 500,
				});
				completed++;
			} catch {}
		}
		process.stdout.write(`\r  presigns completed: ${completed}/${expected}    `);
		if (completed >= expected) {
			process.stdout.write('\n');
			return;
		}
		await new Promise((r) => setTimeout(r, 2000));
	}
	throw new Error(`timed out waiting for ${expected} presigns`);
}

async function discoverSourceTokenAccounts(
	conn: Connection,
	source: PublicKey,
): Promise<SourceTokenAccount[]> {
	const resp = await conn.getParsedTokenAccountsByOwner(source, {
		programId: TOKEN_PROGRAM_ID,
	});
	const out: SourceTokenAccount[] = [];
	for (const a of resp.value) {
		const info = a.account.data.parsed.info;
		const amt = BigInt(info.tokenAmount.amount);
		if (amt === 0n) continue;
		out.push({
			mint: new PublicKey(info.mint),
			tokenAccount: a.pubkey,
			amount: amt,
			decimals: info.tokenAmount.decimals,
			programId: TOKEN_PROGRAM_ID,
		});
	}
	return out;
}

async function main() {
	const network = env('SUI_NETWORK', 'testnet') as 'testnet' | 'mainnet';
	const sui = new SuiGrpcClient({
		baseUrl: env('SUI_RPC_URL', getGrpcFullnodeUrl(network)),
		network,
	});
	const ikaClient = new IkaClient({
		suiClient: sui,
		config: getNetworkConfig(network),
		cache: true,
	});
	await ikaClient.initialize();

	const signer1 = loadSuiKeypair(env('SUI_KEYPAIR_1'));
	const signer2 = loadSuiKeypair(env('SUI_KEYPAIR_2'));
	const packageId = env('RECOVERY_PACKAGE_ID');
	const registryId = env('RECOVERY_REGISTRY_ID');
	const recoveryId = env('RECOVERY_ID');

	const conn = new Connection(env('SOLANA_RPC', 'https://api.devnet.solana.com'), 'confirmed');
	const sourceKp = loadSolanaKeypair(env('SOLANA_SOURCE_PATH'));
	const destination = new PublicKey(env('SOLANA_DESTINATION'));

	console.log('recoveryId :', recoveryId);
	console.log('source     :', sourceKp.publicKey.toBase58());
	console.log('destination:', destination.toBase58());

	// Importer's encryption identity (constant 0x42 seed) — has a decryptable share.
	const seed = new Uint8Array(32).fill(0x42);
	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		seed,
		Curve.ED25519,
	);
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: { packageId, recoveryId, registryId },
		rpId: 'recovery.test',
		gasSigner: signer1,
	});

	// Discover the source's existing SPL token accounts (left over from prior run).
	console.log('\n[A] discovering source SPL token accounts …');
	const tokenAccounts = await discoverSourceTokenAccounts(conn, sourceKp.publicKey);
	console.log(`  found ${tokenAccounts.length} non-zero token accounts`);
	for (const t of tokenAccounts) {
		console.log(`    ${t.mint.toBase58().slice(0, 6)}… amount=${t.amount} dec=${t.decimals}`);
	}
	const srcLamports = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	console.log(`  source SOL: ${Number(srcLamports) / LAMPORTS_PER_SOL}`);

	// ── Build sweep ──
	console.log('\n[B] building SOL+SPL sweep bundle …');
	const { blockhash } = await conn.getLatestBlockhash('confirmed');
	const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + BigInt(tokenAccounts.length * 5_000);
	const sweepMessages = buildSweepBundle({
		source: sourceKp.publicKey,
		destination,
		solBalance: srcLamports,
		feeReserveLamports: feeReserve,
		tokenAccounts,
		recentBlockhash: blockhash,
	});
	console.log(`  bundle size: ${sweepMessages.length} tx(s)`);
	for (let i = 0; i < sweepMessages.length; i++) {
		console.log(`    tx[${i}] = ${sweepMessages[i]!.length} bytes`);
	}

	// ── Replenish presigns (need n total; pool has some leftover) ──
	console.log('\n[C] checking presign pool …');
	const stateBefore = await readRecoveryState(client);
	console.log(`  presigns currently: ${stateBefore.presignCount}`);
	const need = sweepMessages.length;
	if (stateBefore.presignCount < BigInt(need)) {
		const toAdd = need - Number(stateBefore.presignCount);
		console.log(`  replenishing ${toAdd} presign(s) …`);
		await replenishPresigns(client, signer1, toAdd, 500_000_000n, 20_000_000n);
		await waitForPresigns(client, need);
	} else {
		// Even if we have enough total, we still need to confirm they're Completed.
		await waitForPresigns(client, need);
	}

	// ── Need an encrypted share to decrypt and produce the centralized signatures ──
	// Use the importer's original encrypted share (0x42 seed), which is bound to
	// the dWallet that imported the source key.
	const stateNow = await readRecoveryState(client);
	console.log(`  dWallet id: ${stateNow.importedKeyDwalletId}`);
	// The original importer's enc-share id is in the dWallet's first share
	// event, but we don't have a clean accessor — fall back to walking owned
	// EncryptedUserSecretKeyShare objects keyed to userShareEncryptionKeys's
	// address. Quickest path: query Sui events filtered by dWallet+encryption-key
	// address. For brevity, we accept it as env (the prior run logged it).
	const encShareId = env('ENCRYPTED_USER_SHARE_ID');
	const encShare = await ikaClient.getEncryptedUserSecretKeyShare(encShareId);

	// ── Propose (sender-cred as signer1) ──
	console.log('\n[D] proposing recovery …');
	const prop = await proposeRecovery(client, {
		sweepMessages,
		authSigner: authSignerFromKeypair(signer1),
		gasSigner: signer1,
	});
	console.log(`  proposalId: ${prop.proposalId}, digest: ${prop.digest}`);

	// ── Preview ──
	const snap = await previewProposal(client, prop.proposalId);
	console.log(
		`\n[E] preview: approvals/threshold = ${snap.approvals}/${snap.threshold}, txCount=${snap.preview.txCount}`,
	);

	// ── Approve as signer2 ──
	console.log('\n[F] approving as signer2 …');
	const apr = await approveRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer2),
		gasSigner: signer2,
	});
	console.log(`  digest: ${apr.digest}`);

	// ── Execute + broadcast ──
	console.log('\n[G] executing + broadcasting …');
	const exec = await executeRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer1),
		userShareEncryptionKeys,
		encryptedUserShare: encShare,
		solanaConnection: conn,
		gasSigner: signer1,
		ikaFeePerMessage: 500_000_000n,
		suiFeePerMessage: 20_000_000n,
	});
	console.log(`  digest: ${exec.digest}, signedTxs: ${exec.signedTransactions.length}`);

	const broadcast = await broadcastSignedTransactions(conn, exec.signedTransactions, {
		skipPreflight: false,
		maxRetries: 5,
	});
	for (const r of broadcast) {
		if (r.signature) console.log(`  [tx ${r.txIndex}] sent: ${r.signature}`);
		else console.log(`  [tx ${r.txIndex}] FAILED:`, r.error);
	}

	// ── Verify destination ──
	console.log('\n[H] verifying destination …');
	const start = Date.now();
	let destLamports = 0n;
	while (Date.now() - start < 90_000) {
		destLamports = BigInt(await conn.getBalance(destination, 'confirmed'));
		if (destLamports > 0n) break;
		await new Promise((r) => setTimeout(r, 3_000));
	}
	console.log(`  destination SOL: ${Number(destLamports) / LAMPORTS_PER_SOL}`);
	let okMints = 0;
	for (const t of tokenAccounts) {
		const destAta = getAssociatedTokenAddressSync(t.mint, destination, true, TOKEN_PROGRAM_ID);
		try {
			const acct = await getAccount(conn, destAta);
			if (acct.amount === t.amount) {
				okMints++;
				console.log(`  ✓ ${destAta.toBase58().slice(0, 6)}…: ${acct.amount}`);
			} else {
				console.log(
					`  ✗ ${destAta.toBase58().slice(0, 6)}…: ${acct.amount} (expected ${t.amount})`,
				);
			}
		} catch {
			console.log(`  ✗ ${destAta.toBase58().slice(0, 6)}…: NOT FOUND`);
		}
	}
	if (okMints !== tokenAccounts.length)
		throw new Error(`destination only got ${okMints}/${tokenAccounts.length} SPL balances`);

	console.log(`\n✓ multi-tx SPL retry complete (${sweepMessages.length} tx(s))`);
}

main().catch((e) => {
	console.error('\nretry failed:', e);
	process.exit(1);
});
