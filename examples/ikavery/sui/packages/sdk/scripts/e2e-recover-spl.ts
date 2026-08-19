/**
 * SPL multi-tx recovery e2e on Sui testnet + Solana devnet. Mirrors
 * `e2e-recover.ts` but adds an admin-driven SPL mint setup and a SOL+SPL
 * sweep bundle. Skips the enrollment dance — that's covered by
 * `e2e-enrollment-spl.ts` once the upstream Ika coordinator issue is gone.
 *
 * Required env:
 *   SUI_KEYPAIR_1            — bech32; member #1, owns IKA, pays gas
 *   SUI_KEYPAIR_2            — bech32; member #2, approves
 *   RECOVERY_PACKAGE_ID      — recently published `recovery` package
 *   RECOVERY_REGISTRY_ID     — Registry shared object from same publish
 *   SOLANA_SOURCE_PATH       — fresh Solana keypair (admin will fund it)
 *   SOLANA_DESTINATION       — base58 destination
 *   SOLANA_RPC               — default https://api.devnet.solana.com
 *   SOLANA_ADMIN_PATH        — Solana keypair with ≥0.3 SOL on devnet
 *                                (default: ~/.config/solana/devnet-admin.json)
 *   SPL_MINT_COUNT           — default 8 — picks a count that spills into ≥2 txs
 */

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { Curve, getNetworkConfig, IkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import {
	createMint,
	getAccount,
	getAssociatedTokenAddressSync,
	getOrCreateAssociatedTokenAccount,
	mintTo,
	TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import {
	Connection,
	LAMPORTS_PER_SOL,
	PublicKey,
	Keypair as SolKeypair,
	Transaction as SolTransaction,
	SystemProgram,
} from '@solana/web3.js';

import { RecoveryClient } from '../src/client';
import { importSolanaKey } from '../src/flows/import-key';
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

interface MintedToken {
	mint: PublicKey;
	sourceAta: PublicKey;
	amount: bigint;
	decimals: number;
}

async function setupSplMints(
	conn: Connection,
	admin: SolKeypair,
	source: SolKeypair,
	mintCount: number,
	amountPerMint: bigint,
	solFundLamports: bigint,
): Promise<MintedToken[]> {
	const fundIx = SystemProgram.transfer({
		fromPubkey: admin.publicKey,
		toPubkey: source.publicKey,
		lamports: solFundLamports,
	});
	const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
	const fundTx = new SolTransaction({
		blockhash,
		lastValidBlockHeight,
		feePayer: admin.publicKey,
	});
	fundTx.add(fundIx);
	fundTx.sign(admin);
	const fundSig = await conn.sendRawTransaction(fundTx.serialize());
	await conn.confirmTransaction(
		{ signature: fundSig, blockhash, lastValidBlockHeight },
		'confirmed',
	);
	console.log(
		`  funded source with ${Number(solFundLamports) / LAMPORTS_PER_SOL} SOL (${fundSig})`,
	);

	const out: MintedToken[] = [];
	for (let i = 0; i < mintCount; i++) {
		const decimals = 6;
		const mint = await createMint(conn, admin, admin.publicKey, null, decimals);
		const sourceAtaInfo = await getOrCreateAssociatedTokenAccount(
			conn,
			admin,
			mint,
			source.publicKey,
			false,
		);
		await mintTo(conn, admin, mint, sourceAtaInfo.address, admin, amountPerMint);
		out.push({
			mint,
			sourceAta: sourceAtaInfo.address,
			amount: amountPerMint,
			decimals,
		});
		console.log(
			`  [mint ${i + 1}/${mintCount}] mint=${mint.toBase58().slice(0, 6)}… ata=${sourceAtaInfo.address.toBase58().slice(0, 6)}… amount=${amountPerMint}`,
		);
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

	const conn = new Connection(env('SOLANA_RPC', 'https://api.devnet.solana.com'), 'confirmed');
	const sourceKp = loadSolanaKeypair(env('SOLANA_SOURCE_PATH'));
	const destination = new PublicKey(env('SOLANA_DESTINATION'));
	const adminKp = loadSolanaKeypair(
		env('SOLANA_ADMIN_PATH', path.join(homedir(), '.config/solana/devnet-admin.json')),
	);
	const splMintCount = parseInt(env('SPL_MINT_COUNT', '8'), 10);

	console.log('network        :', network);
	console.log('sui address #1 :', signer1.toSuiAddress());
	console.log('sui address #2 :', signer2.toSuiAddress());
	console.log('source         :', sourceKp.publicKey.toBase58());
	console.log('admin          :', adminKp.publicKey.toBase58());
	console.log('destination    :', destination.toBase58());
	console.log('spl mint count :', splMintCount);

	const adminLamports = BigInt(await conn.getBalance(adminKp.publicKey, 'confirmed'));
	console.log('admin SOL      :', Number(adminLamports) / LAMPORTS_PER_SOL);
	if (adminLamports < BigInt(0.3 * LAMPORTS_PER_SOL)) {
		throw new Error('admin needs ≥0.3 SOL on devnet');
	}

	// [A] SPL setup
	console.log('\n[A] setting up Solana mints + funding source …');
	const minted = await setupSplMints(
		conn,
		adminKp,
		sourceKp,
		splMintCount,
		1_000_000n,
		BigInt(0.05 * LAMPORTS_PER_SOL),
	);

	const srcAfterSetup = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	console.log(`  source SOL after setup: ${Number(srcAfterSetup) / LAMPORTS_PER_SOL}`);

	// [B] Import — create Recovery + dWallet
	console.log('\n[B] importing Solana key into Ika dWallet …');
	const seed = new Uint8Array(32).fill(0x42);
	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		seed,
		Curve.ED25519,
	);
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: { packageId, recoveryId: '0x0', registryId },
		rpId: 'recovery.test',
		gasSigner: signer1,
	});
	const imp = await importSolanaKey(client, {
		solanaSecretKey: sourceKp.secretKey,
		userShareEncryptionKeys,
		gasSigner: signer1,
		initialMembers: [
			{ scheme: 'ed25519', publicKey: signer1.getPublicKey().toRawBytes() },
			{ scheme: 'ed25519', publicKey: signer2.getPublicKey().toRawBytes() },
		],
		threshold: 2,
		verificationIkaFee: 5_000_000_000n,
		verificationSuiFee: 50_000_000n,
	});
	console.log('  recoveryId           :', imp.recoveryId);
	console.log('  dwalletId            :', imp.dwalletId);
	console.log('  encryptedUserShareId :', imp.encryptedUserShareId);
	client.ref.recoveryId = imp.recoveryId;

	// [C] Build sweep bundle (SOL + all SPL)
	console.log('\n[C] building SOL+SPL sweep bundle …');
	const srcLamports = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	const tokenAccounts: SourceTokenAccount[] = minted.map((m) => ({
		mint: m.mint,
		tokenAccount: m.sourceAta,
		amount: m.amount,
		decimals: m.decimals,
		programId: TOKEN_PROGRAM_ID,
	}));
	const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + BigInt(splMintCount * 5_000);
	const { blockhash } = await conn.getLatestBlockhash('confirmed');
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
	if (sweepMessages.length < 2) {
		console.warn('  ⚠ single-tx bundle; raise SPL_MINT_COUNT to exercise multi-tx path');
	}

	// [D] Replenish presigns (one per tx + buffer)
	console.log('\n[D] replenishing presigns …');
	const need = sweepMessages.length + 1;
	await replenishPresigns(client, signer1, need, 3_000_000_000n, 20_000_000n);
	await waitForPresigns(client, need);

	// [E] Propose
	console.log('\n[E] proposing recovery …');
	const prop = await proposeRecovery(client, {
		sweepMessages,
		authSigner: authSignerFromKeypair(signer1),
		gasSigner: signer1,
	});
	console.log(`  proposalId: ${prop.proposalId}, digest: ${prop.digest}`);

	// [F] Preview
	const snap = await previewProposal(client, prop.proposalId);
	console.log(
		`\n[F] preview: approvals/threshold = ${snap.approvals}/${snap.threshold}, txCount=${snap.preview.txCount}`,
	);
	for (const t of snap.preview.txs) {
		console.log(`  tx[${t.messageByteLength}B]:`);
		for (const ix of t.instructions) console.log(`    ${ix.kind}`);
	}

	// [G] Approve as signer2
	console.log('\n[G] approving as signer2 …');
	const apr = await approveRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer2),
		gasSigner: signer2,
	});
	console.log(`  digest: ${apr.digest}`);

	// [H] Execute + broadcast
	console.log('\n[H] executing + broadcasting …');
	const encShare = await ikaClient.getEncryptedUserSecretKeyShare(imp.encryptedUserShareId);
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

	// [I] Verify destination
	console.log('\n[I] verifying destination …');
	// Snapshot the destination's balance BEFORE waiting so we detect *this* run's
	// SOL transfer rather than just any pre-existing balance from earlier runs.
	const destLamportsBefore = BigInt(await conn.getBalance(destination, 'confirmed'));
	const start = Date.now();
	let destLamports = destLamportsBefore;
	while (Date.now() - start < 90_000) {
		destLamports = BigInt(await conn.getBalance(destination, 'confirmed'));
		if (destLamports > destLamportsBefore) break;
		await new Promise((r) => setTimeout(r, 3_000));
	}
	console.log(
		`  destination SOL: ${Number(destLamports) / LAMPORTS_PER_SOL} (Δ +${Number(destLamports - destLamportsBefore) / LAMPORTS_PER_SOL})`,
	);
	let okMints = 0;
	for (const m of minted) {
		const destAta = getAssociatedTokenAddressSync(m.mint, destination, true, TOKEN_PROGRAM_ID);
		try {
			const acct = await getAccount(conn, destAta);
			if (acct.amount === m.amount) {
				okMints++;
				console.log(`  ✓ ${destAta.toBase58().slice(0, 6)}…: ${acct.amount}`);
			} else {
				console.log(
					`  ✗ ${destAta.toBase58().slice(0, 6)}…: ${acct.amount} (expected ${m.amount})`,
				);
			}
		} catch {
			console.log(`  ✗ ${destAta.toBase58().slice(0, 6)}…: NOT FOUND`);
		}
	}
	if (okMints !== minted.length) {
		throw new Error(`destination only got ${okMints}/${minted.length} SPL balances`);
	}

	console.log(`\n✓ SPL e2e complete (${sweepMessages.length} tx(s), ${minted.length} mints)`);
}

main().catch((e) => {
	console.error('\nspl e2e failed:', e);
	process.exit(1);
});
