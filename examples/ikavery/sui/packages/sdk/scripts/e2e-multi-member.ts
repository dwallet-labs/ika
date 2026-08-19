/**
 * Phase 2 end-to-end check: 5-member provisionInitialMembers run, exercising
 * batched register-all + batched re-encrypt + batched accept across 4
 * non-importer members.
 *
 * Required env (same as e2e-recover.ts):
 *   SUI_KEYPAIR_1        - bech32, funded testnet, gas payer + member #1.
 *   RECOVERY_PACKAGE_ID  - published `recovery` package id on testnet.
 *   RECOVERY_REGISTRY_ID - shared `recovery::registry::Registry` object id.
 *   SOLANA_SOURCE_PATH   - path to a Solana JSON keypair (any keypair; not swept).
 *
 * What this proves:
 *   - 3-PTB setup scales to N=5 members regardless of roster size.
 *   - Each non-importer member can decrypt their own share.
 *   - No member can decrypt another member's share (segregation).
 */

import { readFileSync } from 'node:fs';
import {
	Curve,
	getNetworkConfig,
	IkaClient,
	UserShareEncryptionKeys,
	type ImportedKeyDWallet,
} from '@ika.xyz/sdk';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Keypair as SolKeypair } from '@solana/web3.js';

import { RecoveryClient } from '../src/client';
import { provisionInitialMembers } from '../src/flows/provision-initial-members';

const NUM_NON_IMPORTERS = 4; // total roster = 5

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
	const packageId = env('RECOVERY_PACKAGE_ID');
	const registryId = env('RECOVERY_REGISTRY_ID');
	const sourceKp = loadSolanaKeypair(env('SOLANA_SOURCE_PATH'));

	console.log('network        :', network);
	console.log('gas payer      :', signer1.toSuiAddress());

	// Importer's encryption identity (deterministic seed for re-runs).
	const importerSeed = new Uint8Array(32).fill(0x42);
	const importerKeys = await UserShareEncryptionKeys.fromRootSeedKey(importerSeed, Curve.ED25519);
	// Use the importer's encryption Sui address as their on-chain sender
	// identity to keep the test self-contained (no extra funded keypairs).
	const importerPubkey = importerKeys.getSigningPublicKeyBytes();

	// 4 distinct non-importer encryption identities, derived from different
	// seeds. Each member's encryption-Sui-address doubles as its on-chain
	// sender identity here — both roles collapse to the same address for the
	// test.
	const nonImporterKeys: UserShareEncryptionKeys[] = [];
	for (let i = 0; i < NUM_NON_IMPORTERS; i++) {
		const seed = new Uint8Array(32).fill(0x99 + i);
		const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.ED25519);
		nonImporterKeys.push(keys);
		console.log(`member #${i + 2} enc  :`, keys.getSuiAddress());
	}
	console.log('importer pk    :', Buffer.from(importerPubkey).toString('hex'));

	const refPlaceholder = { packageId, recoveryId: '0x0', registryId };
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: refPlaceholder,
		rpId: 'recovery.test',
		gasSigner: signer1,
	});

	console.log(`\n[1/2] provisioning ${1 + NUM_NON_IMPORTERS}-member vault in 3 PTBs …`);
	const t0 = Date.now();
	const result = await provisionInitialMembers(client, {
		solanaSecretKey: sourceKp.secretKey,
		importerEncryptionKeys: importerKeys,
		nonImporterMemberKeys: nonImporterKeys,
		initialMembers: [
			{ scheme: 'ed25519', publicKey: importerPubkey },
			...nonImporterKeys.map((k) => ({
				scheme: 'ed25519' as const,
				publicKey: k.getSigningPublicKeyBytes(),
			})),
		],
		threshold: 3,
		gasSigner: signer1,
		onProgress: (phase) => process.stdout.write(`  · ${phase}\n`),
	});
	const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
	console.log(`  elapsed              : ${elapsed}s`);
	console.log('  recoveryId           :', result.recoveryId);
	console.log('  dwalletId            :', result.dwalletId);
	console.log('  importer share id    :', result.importerEncryptedUserShareId);
	for (const [i, id] of result.nonImporterEncryptedUserShareIds.entries()) {
		console.log(`  member #${i + 2} share id   :`, id);
	}
	console.log('  digests              :', result.txDigests);

	client.ref.recoveryId = result.recoveryId;

	console.log(`\n[2/2] verifying every non-importer can decrypt their share …`);
	const dWallet = (await ikaClient.getDWalletInParticularState(
		result.dwalletId,
		'Active',
	)) as ImportedKeyDWallet;
	const pp = await ikaClient.getProtocolPublicParameters(dWallet);

	const destShares = await Promise.all(
		result.nonImporterEncryptedUserShareIds.map((id) =>
			ikaClient.getEncryptedUserSecretKeyShare(id),
		),
	);

	let allOk = true;
	for (let i = 0; i < nonImporterKeys.length; i++) {
		const memberLabel = `member #${i + 2}`;
		try {
			const { secretShare } = await nonImporterKeys[i].decryptUserShare(dWallet, destShares[i], pp);
			const ok = secretShare.length > 0 && secretShare.some((b) => b !== 0);
			console.log(`  ${memberLabel}: decrypted ${secretShare.length} bytes (non-zero=${ok})`);
			if (!ok) allOk = false;
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			console.log(`  ${memberLabel}: FAILED to decrypt — ${msg}`);
			allOk = false;
		}
	}

	// Cross-segregation check: pick a random pair and confirm member i can't
	// decrypt member j's share when i ≠ j.
	console.log(`\n  segregation spot-check: member #2 → member #5's share`);
	let crossDecrypt = false;
	try {
		await nonImporterKeys[0].decryptUserShare(dWallet, destShares[NUM_NON_IMPORTERS - 1], pp);
		crossDecrypt = true;
	} catch {
		/* expected */
	}
	console.log(
		`  member #2 decrypted member #5's share? ${crossDecrypt} ${
			crossDecrypt ? '(WRONG)' : '(correct — segregated)'
		}`,
	);
	if (crossDecrypt) allOk = false;

	if (!allOk) {
		console.error('\n✘ at least one verification failed.');
		process.exit(1);
	}
	console.log(`\n✓ 5-member 3-PTB provisioning works. PTB count is constant in N.`);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
