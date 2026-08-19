/**
 * End-to-end recovery flow on Sui testnet + Solana devnet.
 *
 * Required env:
 *   SUI_KEYPAIR_1            - bech32 (`suiprivkey...`); funded testnet, owns the IKA coin.
 *   SUI_KEYPAIR_2            - bech32; funded testnet (small amount for gas).
 *   RECOVERY_PACKAGE_ID      - published `recovery` package id on testnet.
 *   RECOVERY_REGISTRY_ID     - shared `recovery::registry::Registry` object id.
 *   SOLANA_SOURCE_PATH       - path to a Solana JSON keypair (devnet, funded).
 *   SOLANA_DESTINATION       - base58 pubkey to sweep into.
 *   SOLANA_RPC               - default https://api.devnet.solana.com
 */

import { readFileSync } from 'node:fs';
import { Curve, getNetworkConfig, IkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { Connection, PublicKey, Keypair as SolKeypair } from '@solana/web3.js';

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
import { buildSweepBundle, SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT } from '../src/solana/build-sweep';

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

function loadSolanaKeypair(path: string): SolKeypair {
	const arr = JSON.parse(readFileSync(path, 'utf-8'));
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
				/* not ready yet */
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

async function main() {
	const network = env('SUI_NETWORK', 'testnet') as 'testnet' | 'mainnet';
	// Allow override since the public testnet RPC is aggressively rate-limited.
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

	console.log('network        :', network);
	console.log('sui address #1 :', signer1.toSuiAddress());
	console.log('sui address #2 :', signer2.toSuiAddress());
	console.log('source solana  :', sourceKp.publicKey.toBase58());
	console.log('destination    :', destination.toBase58());

	// Pre-check: source has SOL.
	const srcLamports = BigInt(await conn.getBalance(sourceKp.publicKey, 'confirmed'));
	console.log('source SOL     :', Number(srcLamports) / 1e9);
	if (srcLamports === 0n) throw new Error('source has 0 SOL — fund it first');

	// 1. Derive a deterministic PRF seed for the importer's encryption identity.
	//    In the real flow this comes from a passkey PRF; for the e2e we use a
	//    constant 32-byte seed so re-runs hit the same encryption-key address.
	const prfSeed = new Uint8Array(32).fill(0x42);
	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		prfSeed,
		Curve.ED25519,
	);

	// 2. RecoveryClient with placeholder recoveryId (we'll patch after import).
	const refPlaceholder = { packageId, recoveryId: '0x0', registryId };
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: refPlaceholder,
		rpId: 'recovery.test',
		gasSigner: signer1,
	});

	// 3. Import: zero-trust imported-key dWallet + create Recovery atomically.
	console.log('\n[1/6] importing Solana key …');
	const imp = await importSolanaKey(client, {
		solanaSecretKey: sourceKp.secretKey,
		userShareEncryptionKeys,
		gasSigner: signer1,
		initialMembers: [
			{ scheme: 'ed25519', publicKey: signer1.getPublicKey().toRawBytes() },
			{ scheme: 'ed25519', publicKey: signer2.getPublicKey().toRawBytes() },
		],
		threshold: 2,
		verificationIkaFee: 500_000_000n,
		verificationSuiFee: 50_000_000n,
	});
	console.log('  recoveryId           :', imp.recoveryId);
	console.log('  dwalletId            :', imp.dwalletId);
	console.log('  encryptedUserShareId :', imp.encryptedUserShareId);
	console.log('  digests              :', imp.txDigests);

	client.ref.recoveryId = imp.recoveryId;

	// 4. Replenish presigns. SOL-only sweep is one tx → one presign needed.
	//    Buffer with 2 to be safe.
	console.log('\n[2/6] replenishing presigns …');
	const presignsToWarm = 2;
	await replenishPresigns(client, signer1, presignsToWarm, 500_000_000n, 20_000_000n);
	await waitForPresigns(client, presignsToWarm);

	// 5. Build the Solana sweep bundle (SOL-only for the e2e).
	console.log('\n[3/6] building Solana sweep bundle …');
	const { blockhash } = await conn.getLatestBlockhash('confirmed');
	const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + 5_000n;
	const sweepMessages = buildSweepBundle({
		source: sourceKp.publicKey,
		destination,
		solBalance: srcLamports,
		feeReserveLamports: feeReserve,
		tokenAccounts: [],
		recentBlockhash: blockhash,
	});
	console.log(`  bundle size : ${sweepMessages.length} tx(s)`);

	// 6. Need the executor's encrypted user share for executeRecovery (sigs are
	//    produced at execute time now, not at propose).
	const encryptedShare = await ikaClient.getEncryptedUserSecretKeyShare(imp.encryptedUserShareId);

	// 7. Propose with sender credential (signer1 = member #1). Propose now just
	//    parses the bundle into stored intents — no centralized sigs, no future-
	//    sign, no per-message Ika/Sui fees.
	console.log('\n[4/6] proposing recovery …');
	const prop = await proposeRecovery(client, {
		sweepMessages,
		authSigner: authSignerFromKeypair(signer1),
		gasSigner: signer1,
	});
	console.log('  proposalId :', prop.proposalId);
	console.log('  digest     :', prop.digest);

	// 8. Preview the proposal — what the approver would see.
	console.log('\n[5a/6] preview from on-chain proposal:');
	const snap = await previewProposal(client, prop.proposalId);
	console.log('  approvals/threshold:', `${snap.approvals}/${snap.threshold}`);
	console.log('  txCount            :', snap.preview.txCount);
	console.log('  totalLamports      :', snap.preview.totalLamportsTransferred);
	for (const t of snap.preview.txs) {
		console.log(`  tx[${t.messageByteLength}B]:`);
		for (const ix of t.instructions) {
			if (ix.kind === 'system-transfer') {
				console.log(`    SystemTransfer ${ix.from} -> ${ix.to} : ${ix.lamports} lamports`);
			} else {
				console.log(`    ${ix.kind}`);
			}
		}
	}

	// 9. Approve with signer2 (member #2) — sender credential.
	console.log('\n[5b/6] approving as member #2 …');
	const apr = await approveRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer2),
		gasSigner: signer2,
	});
	console.log('  digest :', apr.digest);

	// 10. Execute and broadcast. Execute now rebuilds messages with a current
	//     blockhash, decrypts our share, and creates centralized sigs at execute
	//     time. This is what makes propose-then-wait safe across blockhash expiry.
	const sleepBeforeExecuteSec = Number(env('SLEEP_BEFORE_EXECUTE_SEC', '0'));
	if (sleepBeforeExecuteSec > 0) {
		console.log(`\n  sleeping ${sleepBeforeExecuteSec}s before execute (blockhash-expiry test) …`);
		await new Promise((r) => setTimeout(r, sleepBeforeExecuteSec * 1000));
	}
	console.log('\n[6/6] executing + broadcasting …');
	const exec = await executeRecovery(client, {
		proposalId: prop.proposalId,
		authSigner: authSignerFromKeypair(signer1),
		userShareEncryptionKeys,
		encryptedUserShare: encryptedShare,
		solanaConnection: conn,
		gasSigner: signer1,
		ikaFeePerMessage: 500_000_000n,
		suiFeePerMessage: 20_000_000n,
	});
	console.log('  digest    :', exec.digest);
	console.log('  signIds   :', exec.signIds);
	console.log('  signedTxs :', exec.signedTransactions.length);

	const broadcastResults = await broadcastSignedTransactions(conn, exec.signedTransactions, {
		skipPreflight: false,
		maxRetries: 5,
	});
	for (const r of broadcastResults) {
		if (r.signature) {
			console.log(`  [tx ${r.txIndex}] sent: ${r.signature}`);
		} else {
			console.log(`  [tx ${r.txIndex}] FAILED:`, r.error);
		}
	}

	// 11. Verify destination got the SOL.
	console.log('\nverifying destination balance …');
	// Wait for confirmation: poll up to ~30s.
	const start = Date.now();
	let destBalance = 0n;
	while (Date.now() - start < 60_000) {
		destBalance = BigInt(await conn.getBalance(destination, 'confirmed'));
		if (destBalance > 0n) break;
		await new Promise((r) => setTimeout(r, 3_000));
	}
	console.log(`  destination SOL: ${Number(destBalance) / 1e9}`);
	if (destBalance === 0n) {
		throw new Error('destination did not receive SOL within 60s');
	}
	console.log('\n✓ e2e recovery complete');
}

main().catch((e) => {
	console.error('\ne2e failed:', e);
	process.exit(1);
});
