/**
 * Combined end-to-end test on Sui testnet + Solana devnet that exercises:
 *   1. The 4-step enrollment flow (register → propose → approve → execute → accept)
 *      adding a fresh 3rd device. Threshold stays 2 — signer1 proposes
 *      (auto-vote), signer2 approves → threshold met → execute, then the new
 *      device's gasSigner runs accept.
 *   2. A multi-tx SPL sweep. We mint N SPL tokens (admin mint authority) into
 *      source's ATAs, then drive the recovery flow to sweep both SOL and all
 *      SPL balances to a destination. With ~6+ mints the bundle packer spills
 *      across multiple Solana transactions, so the per-tx broadcast path runs.
 *
 * Required env (most reuse the prior e2e; new ones flagged):
 *   SUI_KEYPAIR_1            existing — signer1 (members + IKA coin owner)
 *   SUI_KEYPAIR_2            existing — signer2 (member, approves)
 *   RECOVERY_PACKAGE_ID      existing
 *   RECOVERY_REGISTRY_ID     existing — shared Registry created at publish time
 *   SOLANA_SOURCE_PATH       existing — fresh keypair for THIS run
 *   SOLANA_DESTINATION       existing — base58 destination
 *   SOLANA_RPC               default https://api.devnet.solana.com
 *   SUI_RPC_URL              default getGrpcFullnodeUrl(testnet)
 *   SOLANA_ADMIN_PATH        NEW — Solana keypair holding 1+ SOL to fund
 *                             source + create mints + mint tokens. Defaults to
 *                             ~/.config/solana/devnet-admin.json.
 *   SPL_MINT_COUNT           NEW — default 6. Pick high enough to spill into
 *                             >=2 packed Solana txs.
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
import {
	acceptEnrollment,
	approveEnrollment,
	executeEnrollment,
	proposeEnrollment,
	registerDeviceEncryptionKey,
} from '../src/flows/enroll-device';
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
import { memberIdBytes } from '../src/move/members';
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

function loadSuiKeypair(bech32: string): Ed25519Keypair {
	const decoded = decodeSuiPrivateKey(bech32);
	if (decoded.scheme !== 'ED25519') throw new Error(`expected ED25519, got ${decoded.scheme}`);
	return Ed25519Keypair.fromSecretKey(decoded.secretKey);
}

function loadSolanaKeypair(p: string): SolKeypair {
	const arr = JSON.parse(readFileSync(p, 'utf-8'));
	return SolKeypair.fromSecretKey(Uint8Array.from(arr));
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
	const result = await client.suiClient.core.signAndExecuteTransaction({
		transaction: tx,
		signer,
	});
	if (result.$kind !== 'Transaction') {
		throw new Error(`replenishPresigns failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}
	return result.Transaction.digest;
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
			} catch {
				/* not ready */
			}
		}
		process.stdout.write(`\r  presigns completed: ${completed}/${expected}    `);
		if (completed >= expected) {
			process.stdout.write('\n');
			return;
		}
		await new Promise((r) => setTimeout(r, 2000));
	}
	throw new Error(`timed out waiting for ${expected} presigns to complete`);
}

interface MintedToken {
	mint: PublicKey;
	sourceAta: PublicKey;
	amount: bigint;
	decimals: number;
}

/**
 * Setup: admin creates `mintCount` SPL mints, creates source's ATA per mint,
 * mints `amount` units to each. Also funds source with `solFundLamports` SOL.
 *
 * All txs are signed by admin and serialized so the script can be re-run with
 * different counts without colliding. Returns the per-mint details we feed
 * into `buildSweepBundle`.
 */
async function setupSplMints(
	conn: Connection,
	admin: SolKeypair,
	source: SolKeypair,
	mintCount: number,
	amountPerMint: bigint,
	solFundLamports: bigint,
): Promise<MintedToken[]> {
	// Fund source first so its ATA-rent + sweep fees are payable. Even though
	// admin pays for the ATA creation below, source still needs SOL for sweep.
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
			`  [mint ${i + 1}/${mintCount}] mint=${mint.toBase58()} ata=${sourceAtaInfo.address.toBase58()} amount=${amountPerMint}`,
		);
	}
	return out;
}

async function main() {
	const network = env('SUI_NETWORK', 'testnet') as 'testnet' | 'mainnet';
	const suiRpcUrl = env('SUI_RPC_URL', getGrpcFullnodeUrl(network));
	console.log('sui rpc        :', suiRpcUrl);

	const sui = new SuiGrpcClient({ baseUrl: suiRpcUrl, network });
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

	const solanaRpc = env('SOLANA_RPC', 'https://api.devnet.solana.com');
	const conn = new Connection(solanaRpc, 'confirmed');
	const sourceKp = loadSolanaKeypair(env('SOLANA_SOURCE_PATH'));
	const destination = new PublicKey(env('SOLANA_DESTINATION'));
	const adminKp = loadSolanaKeypair(
		env('SOLANA_ADMIN_PATH', path.join(homedir(), '.config/solana/devnet-admin.json')),
	);

	// 6 mints fit in a single ~996-byte tx; 8 mints reliably spill into 2 txs
	// (~1100 bytes per packed tx), exercising the multi-tx broadcast path.
	const splMintCount = parseInt(env('SPL_MINT_COUNT', '8'), 10);

	console.log('network        :', network);
	console.log('sui address #1 :', signer1.toSuiAddress());
	console.log('sui address #2 :', signer2.toSuiAddress());
	console.log('source solana  :', sourceKp.publicKey.toBase58());
	console.log('admin solana   :', adminKp.publicKey.toBase58());
	console.log('destination    :', destination.toBase58());
	console.log('spl mint count :', splMintCount);

	// Pre-check admin has SOL for setup.
	const adminLamports = BigInt(await conn.getBalance(adminKp.publicKey, 'confirmed'));
	console.log('admin SOL      :', Number(adminLamports) / LAMPORTS_PER_SOL);
	if (adminLamports < BigInt(0.3 * LAMPORTS_PER_SOL)) {
		throw new Error('admin needs >=0.3 SOL on devnet to fund source + setup mints');
	}

	// ── Step A: Solana setup — fund source, create mints + source ATAs, mint tokens ──
	console.log('\n[A] setting up Solana mints + funding source …');
	const minted = await setupSplMints(
		conn,
		adminKp,
		sourceKp,
		splMintCount,
		1_000_000n, // 1 token (decimals=6)
		BigInt(0.05 * LAMPORTS_PER_SOL),
	);

	// Verify source balances.
	const srcLamportsAfterSetup = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	console.log(`  source SOL after setup: ${Number(srcLamportsAfterSetup) / LAMPORTS_PER_SOL}`);
	for (const m of minted) {
		const acct = await getAccount(conn, m.sourceAta);
		console.log(
			`  source ATA ${m.sourceAta.toBase58().slice(0, 6)}…: ${acct.amount} of ${m.mint.toBase58().slice(0, 6)}…`,
		);
	}

	// ── Step B: import Solana key into Ika; create Recovery (signer1+signer2 members, threshold=2) ──
	console.log('\n[B] importing Solana key into Ika dWallet …');
	const seedDevice1 = new Uint8Array(32).fill(0x42);
	const userShareEncryptionKeysDev1 = await UserShareEncryptionKeys.fromRootSeedKey(
		seedDevice1,
		Curve.ED25519,
	);

	const refPlaceholder = { packageId, recoveryId: '0x0', registryId };
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: refPlaceholder,
		rpId: 'recovery.test',
		gasSigner: signer1,
	});

	const imp = await importSolanaKey(client, {
		solanaSecretKey: sourceKp.secretKey,
		userShareEncryptionKeys: userShareEncryptionKeysDev1,
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

	// ── Step C: enroll a 3rd device ──
	// Device 3 has:
	//   • a fresh PRF seed → UserShareEncryptionKeys (Sui address bound by Ika to encryption key)
	//   • a separate Sui keypair (signer3) that signs the new device's PTBs and is the
	//     `sender`-credential authorization identity registered as a member.
	console.log('\n[C] enrolling 3rd device …');
	const seedDevice3 = new Uint8Array(32).fill(0x99);
	const userShareEncryptionKeysDev3 = await UserShareEncryptionKeys.fromRootSeedKey(
		seedDevice3,
		Curve.ED25519,
	);
	// Fresh Sui keypair for device 3. Will be used as the sender-credential and
	// for paying gas on the new device's PTBs. Doesn't need testnet SUI for the
	// accept call alone if we sponsor via signer1 — but Sui requires the actual
	// signer to be funded for the gas budget. Send a small amount.
	const signer3 = new Ed25519Keypair();
	console.log('  device3 (signer3)  :', signer3.toSuiAddress());
	console.log('  device3 (enc-key)  :', userShareEncryptionKeysDev3.getSuiAddress());

	// Fund signer3 from signer1 so it can pay gas for register/accept.
	{
		const tx = new Transaction();
		const [coin] = tx.splitCoins(tx.gas, [50_000_000n]); // 0.05 SUI
		tx.transferObjects([coin], signer3.toSuiAddress());
		const r = await sui.core.signAndExecuteTransaction({
			transaction: tx,
			signer: signer1,
		});
		if (r.$kind !== 'Transaction') {
			throw new Error(`fund-signer3 failed: ${JSON.stringify(r.FailedTransaction.status)}`);
		}
		console.log('  funded signer3 with 0.05 SUI:', r.Transaction.digest);
	}

	// C.1 — register device 3's encryption key on Ika.
	console.log('  [C.1] register device3 encryption key');
	const regRes = await registerDeviceEncryptionKey(client, {
		userShareEncryptionKeys: userShareEncryptionKeysDev3,
		gasSigner: signer3,
	});
	console.log('    digest:', regRes.digest);

	// C.2 — propose enrollment as signer1 (member). New member: signer3 (sender variant).
	console.log('  [C.2] propose enrollment');
	const signer3Pubkey = signer3.getPublicKey().toRawBytes();
	const propEnroll = await proposeEnrollment(client, {
		newMember: { scheme: 'ed25519', publicKey: signer3Pubkey },
		newEncryptionKeyAddress: userShareEncryptionKeysDev3.getSuiAddress(),
		authSigner: authSignerFromKeypair(signer1),
		gasSigner: signer1,
	});
	console.log('    enrollmentId:', propEnroll.enrollmentId, 'digest:', propEnroll.digest);

	// C.3 — approve enrollment as signer2 → reaches threshold 2.
	console.log('  [C.3] approve enrollment as signer2');
	const aprEnroll = await approveEnrollment(client, {
		enrollmentId: propEnroll.enrollmentId,
		authSigner: authSignerFromKeypair(signer2),
		gasSigner: signer2,
	});
	console.log('    digest:', aprEnroll.digest);

	// C.4 — execute enrollment using signer1's decrypted share as the source.
	console.log('  [C.4] execute enrollment (re-encrypt share to device3)');
	const sourceEncShare = await ikaClient.getEncryptedUserSecretKeyShare(imp.encryptedUserShareId);
	const execEnroll = await executeEnrollment(client, {
		enrollmentId: propEnroll.enrollmentId,
		userShareEncryptionKeys: userShareEncryptionKeysDev1,
		sourceEncryptedUserShare: sourceEncShare,
		newEncryptionKeyAddress: userShareEncryptionKeysDev3.getSuiAddress(),
		gasSigner: signer1,
	});
	console.log('    digest:', execEnroll.digest);
	console.log('    destEncryptedUserShareId:', execEnroll.destEncryptedUserShareId);

	// C.5 — device 3 accepts the share (must be signed by signer3).
	console.log('  [C.5] device3 accepts share');
	const accEnroll = await acceptEnrollment(client, {
		userShareEncryptionKeys: userShareEncryptionKeysDev3,
		destEncryptedUserShareId: execEnroll.destEncryptedUserShareId,
		gasSigner: signer3,
	});
	console.log('    digest:', accEnroll.digest);

	// Sanity: re-read recovery state and confirm signer3 is now a member.
	const stateAfterEnroll = await readRecoveryState(client);
	const signer3MemberId = memberIdBytes({
		scheme: 'ed25519',
		publicKey: signer3Pubkey,
	});
	const enrolled = stateAfterEnroll.members.some((m) => byteEq(m, signer3MemberId));
	console.log(
		`  members after enrollment: ${stateAfterEnroll.members.length} total; signer3 enrolled=${enrolled}`,
	);
	if (!enrolled) throw new Error('enrollment did not add signer3 as a member');

	// ── Step D: build SOL+SPL multi-tx sweep bundle ──
	console.log('\n[D] building SOL+SPL sweep bundle …');
	const srcLamports = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	const { blockhash } = await conn.getLatestBlockhash('confirmed');
	const tokenAccounts: SourceTokenAccount[] = minted.map((m) => ({
		mint: m.mint,
		tokenAccount: m.sourceAta,
		amount: m.amount,
		decimals: m.decimals,
		programId: TOKEN_PROGRAM_ID,
	}));
	// Source must be left ≥ Solana's rent-exempt minimum (~890_880 lamports);
	// anything between 0 and that triggers "insufficient funds for rent" at
	// broadcast time. We add a buffer for tx fees on top.
	const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + BigInt(splMintCount * 5_000);
	const sweepMessages = buildSweepBundle({
		source: sourceKp.publicKey,
		destination,
		solBalance: srcLamports,
		feeReserveLamports: feeReserve,
		tokenAccounts,
		recentBlockhash: blockhash,
	});
	console.log(`  bundle size : ${sweepMessages.length} tx(s)`);
	for (let i = 0; i < sweepMessages.length; i++) {
		console.log(`    tx[${i}] = ${sweepMessages[i]!.length} bytes`);
	}
	if (sweepMessages.length < 2) {
		console.warn(`  ⚠ bundle is single-tx; bump SPL_MINT_COUNT to exercise multi-tx broadcast`);
	}

	// ── Step E: replenish presigns (one per sweep tx, plus a buffer) ──
	console.log('\n[E] replenishing presigns …');
	const presignsToWarm = sweepMessages.length + 1;
	await replenishPresigns(client, signer1, presignsToWarm, 3_000_000_000n, 20_000_000n);
	await waitForPresigns(client, presignsToWarm);

	// ── Step F: propose recovery (as device 3, proving the new share works) ──
	console.log('\n[F] proposing recovery (proposer = device 3, sender-cred) …');
	// Device 3 needs its own destination encrypted share to drive the proposal —
	// executeEnrollment created a brand-new EncryptedUserSecretKeyShare for it.
	const dev3EncShare = await ikaClient.getEncryptedUserSecretKeyShare(
		execEnroll.destEncryptedUserShareId,
	);

	{
		const tx = new Transaction();
		const totalIka = 3_000_000_000n * BigInt(sweepMessages.length) + 1_000_000_000n;
		const ikaForDev3 = coinWithBalance({
			balance: totalIka,
			type: client.ikaCoinType,
		});
		const suiForDev3 = coinWithBalance({ balance: 200_000_000n });
		tx.transferObjects([ikaForDev3, suiForDev3], signer3.toSuiAddress());
		const r = await sui.core.signAndExecuteTransaction({
			transaction: tx,
			signer: signer1,
		});
		if (r.$kind !== 'Transaction')
			throw new Error(`fund signer3 failed: ${JSON.stringify(r.FailedTransaction.status)}`);
		console.log('  funded signer3 with IKA + SUI:', r.Transaction.digest);
	}

	const prop = await proposeRecovery(client, {
		sweepMessages,
		authSigner: authSignerFromKeypair(signer3),
		gasSigner: signer3,
	});
	console.log('  proposalId :', prop.proposalId, 'digest:', prop.digest);

	// ── Step G: preview ──
	console.log('\n[G] preview from on-chain proposal:');
	const snap = await previewProposal(client, prop.proposalId);
	console.log(`  approvals/threshold: ${snap.approvals}/${snap.threshold}`);
	console.log(`  txCount            : ${snap.preview.txCount}`);
	console.log(`  totalLamports SOL  : ${snap.preview.totalLamportsTransferred}`);
	for (const t of snap.preview.txs) {
		console.log(`  tx[${t.messageByteLength}B] ixs=${t.instructions.length}:`);
		for (const ix of t.instructions) {
			if (ix.kind === 'system-transfer') {
				console.log(
					`    SystemTransfer ${ix.from.slice(0, 6)}… -> ${ix.to.slice(0, 6)}… : ${ix.lamports} lamports`,
				);
			} else {
				console.log(`    ${ix.kind}`);
			}
		}
	}

	// ── Step H: approve as signer2 (only need 1 more vote to reach threshold 2) ──
	console.log('\n[H] approving as signer2 …');
	const apr = await approveRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer2),
		gasSigner: signer2,
	});
	console.log('  digest :', apr.digest);

	// ── Step I: execute + broadcast each tx ──
	// dev3 (the new device) executes — proves a freshly-enrolled member can
	// both decrypt their share and produce sigs at execute time.
	console.log('\n[I] executing + broadcasting bundle …');
	const exec = await executeRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer3),
		userShareEncryptionKeys: userShareEncryptionKeysDev3,
		encryptedUserShare: dev3EncShare,
		solanaConnection: conn,
		gasSigner: signer3,
		ikaFeePerMessage: 3_000_000_000n,
		suiFeePerMessage: 20_000_000n,
	});
	console.log('  digest      :', exec.digest);
	console.log('  signIds     :', exec.signIds);
	console.log('  signedTxs   :', exec.signedTransactions.length);

	const broadcast = await broadcastSignedTransactions(conn, exec.signedTransactions, {
		skipPreflight: false,
		maxRetries: 5,
	});
	for (const r of broadcast) {
		if (r.signature) console.log(`  [tx ${r.txIndex}] sent: ${r.signature}`);
		else console.log(`  [tx ${r.txIndex}] FAILED:`, r.error);
	}

	// ── Step J: verify destination got SOL + every SPL token ──
	console.log('\n[J] verifying destination balances …');
	const start = Date.now();
	let destLamports = 0n;
	while (Date.now() - start < 90_000) {
		destLamports = BigInt(await conn.getBalance(destination, 'confirmed'));
		if (destLamports > 0n) break;
		await new Promise((r) => setTimeout(r, 3_000));
	}
	console.log(`  destination SOL      : ${Number(destLamports) / LAMPORTS_PER_SOL}`);

	// For each SPL mint, derive destination's ATA and read balance.
	let okMints = 0;
	for (const m of minted) {
		const destAta = getAssociatedTokenAddressSync(m.mint, destination, true, TOKEN_PROGRAM_ID);
		try {
			const acct = await getAccount(conn, destAta);
			if (acct.amount === m.amount) {
				okMints++;
				console.log(`  destination ATA ${destAta.toBase58().slice(0, 6)}…: ${acct.amount} ✓`);
			} else {
				console.log(
					`  destination ATA ${destAta.toBase58().slice(0, 6)}…: ${acct.amount} (expected ${m.amount})`,
				);
			}
		} catch (_e) {
			console.log(`  destination ATA ${destAta.toBase58().slice(0, 6)}…: NOT FOUND`);
		}
	}
	if (destLamports === 0n) throw new Error('destination did not receive SOL within 90s');
	if (okMints !== minted.length)
		throw new Error(`destination only received ${okMints}/${minted.length} SPL balances`);

	console.log(
		`\n✓ combined enrollment + multi-tx SPL sweep e2e complete (${sweepMessages.length} tx(s))`,
	);
}

function byteEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

main().catch((e) => {
	console.error('\ne2e failed:', e);
	process.exit(1);
});
