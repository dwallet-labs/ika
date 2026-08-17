/**
 * End-to-end roster-change test on Sui testnet.
 *
 * Provisions a 5-member ed25519 vault (importer + 4 non-importers) at
 * threshold 3. Then runs a single roster_change proposal that drops members
 * #4 and #5 and lowers the threshold to 2. Verifies on-chain state matches
 * the post-change shape.
 *
 * Required env (mirrors e2e-multi-member.ts):
 *   SUI_KEYPAIR_1            bech32, funded testnet — gas payer + signer for
 *                            members 1..5 (we sign with the same keypair for
 *                            each member's auth challenge in this test; the
 *                            *encryption identity* of each member is distinct,
 *                            and member ids on-chain are
 *                            `(scheme=ed25519, encryption_pubkey)`, so the
 *                            contract sees five distinct members).
 *   RECOVERY_PACKAGE_ID      newly-republished `recovery` package id.
 *   RECOVERY_REGISTRY_ID     new shared `recovery::registry::Registry` id.
 *   SOLANA_SOURCE_PATH       any Solana JSON keypair (only the secret key is
 *                            imported into the dWallet — never broadcasts).
 */

import { readFileSync } from 'node:fs';
import { Curve, getNetworkConfig, IkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Keypair as SolKeypair } from '@solana/web3.js';

import { RecoveryClient } from '../src/client';
import { provisionInitialMembers } from '../src/flows/provision-initial-members';
import {
	approveRosterChange,
	executeRosterChange,
	proposeRosterChange,
	readRosterChange,
} from '../src/flows/roster-change';
import { readRecoveryState } from '../src/flows/state';
import { authSignerFromKeypair } from '../src/move/credential';
import { memberIdBytes, type NewMemberInput } from '../src/move/members';

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

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

function memberPresent(set: Uint8Array[], id: Uint8Array): boolean {
	return set.some((m) => bytesEq(m, id));
}

async function main() {
	const network = env('SUI_NETWORK', 'testnet') as 'testnet' | 'mainnet';
	const suiRpcUrl = env('SUI_RPC_URL', getGrpcFullnodeUrl(network));

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
	console.log('sui rpc        :', suiRpcUrl);
	console.log('packageId      :', packageId);
	console.log('registryId     :', registryId);
	console.log('gas payer      :', signer1.toSuiAddress());

	// 5 distinct ed25519 encryption identities. Each member's encryption
	// *signing* pubkey is what gets stored as the canonical member id.
	const importerSeed = new Uint8Array(32).fill(0x42);
	const importerKeys = await UserShareEncryptionKeys.fromRootSeedKey(importerSeed, Curve.ED25519);
	const importerPubkey = importerKeys.getSigningPublicKeyBytes();

	const nonImporterKeys: UserShareEncryptionKeys[] = [];
	for (let i = 0; i < NUM_NON_IMPORTERS; i++) {
		const seed = new Uint8Array(32).fill(0x99 + i);
		const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.ED25519);
		nonImporterKeys.push(keys);
	}

	const allMemberInputs: NewMemberInput[] = [
		{ scheme: 'ed25519', publicKey: importerPubkey },
		...nonImporterKeys.map((k) => ({
			scheme: 'ed25519' as const,
			publicKey: k.getSigningPublicKeyBytes(),
		})),
	];
	const _allMemberIds = allMemberInputs.map(memberIdBytes);

	// One Ed25519Keypair per member, derived from the same per-member seed used
	// for the encryption identity (so the test is fully deterministic). The
	// *auth* pubkey (this Sui keypair's) is what becomes the on-chain member id;
	// the encryption identity is independent (used only for share segregation).
	function memberAuthSigner(idx: number) {
		const seed =
			idx === 0 ? new Uint8Array(32).fill(0x42) : new Uint8Array(32).fill(0x99 + idx - 1);
		// Salt the seed for the auth role so it's distinct from the encryption
		// identity's signing key — Sui validators don't care, but keeping them
		// separate makes the test's intent explicit.
		const authSeed = new Uint8Array(32);
		for (let i = 0; i < 32; i++) authSeed[i] = seed[i] ^ 0xa5;
		const kp = Ed25519Keypair.fromSecretKey(authSeed);
		return { kp, signer: authSignerFromKeypair(kp) };
	}
	const memberAuth = Array.from({ length: 1 + NUM_NON_IMPORTERS }, (_, i) => memberAuthSigner(i));
	const memberInputsForRoster: NewMemberInput[] = memberAuth.map((m) => ({
		scheme: 'ed25519',
		publicKey: m.kp.getPublicKey().toRawBytes(),
	}));
	const memberIdsForRoster = memberInputsForRoster.map(memberIdBytes);

	// Print plan
	console.log('\nplan:');
	console.log('  initial roster: 5 ed25519 members, threshold = 3');
	console.log('  → roster_change: remove members #4 + #5, threshold → 2');
	console.log('  expected post: 3 members, threshold = 2\n');

	const refPlaceholder = { packageId, recoveryId: '0x0', registryId };
	const client = new RecoveryClient({
		ikaClient,
		suiClient: sui,
		ref: refPlaceholder,
		rpId: 'recovery.test',
		gasSigner: signer1,
	});

	console.log('[1/4] provisioning 5-member vault …');
	const t0 = Date.now();
	const result = await provisionInitialMembers(client, {
		solanaSecretKey: sourceKp.secretKey,
		importerEncryptionKeys: importerKeys,
		nonImporterMembers: nonImporterKeys.map((keys) => ({
			kind: 'key-holder' as const,
			keys,
		})),
		initialMembers: memberInputsForRoster,
		threshold: 3,
		gasSigner: signer1,
		onProgress: (phase) => process.stdout.write(`  · ${phase}\n`),
	});
	const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
	console.log(`  elapsed              : ${elapsed}s`);
	console.log('  recoveryId           :', result.recoveryId);

	client.ref.recoveryId = result.recoveryId;

	// Confirm pre-change state.
	let state = await readRecoveryState(client);
	console.log('  members              :', state.members.length);
	console.log('  threshold            :', state.threshold.toString());
	if (state.members.length !== 5)
		throw new Error(`expected 5 members, got ${state.members.length}`);
	if (state.threshold !== 3n) throw new Error(`expected threshold=3, got ${state.threshold}`);

	// Pick the two members to remove (index 3, 4 in 0-based — i.e. members #4 + #5).
	const idsToRemove = [memberIdsForRoster[3], memberIdsForRoster[4]];
	for (const id of idsToRemove) {
		if (!memberPresent(state.members, id)) {
			throw new Error(
				`pre-flight: removal target not in roster: ${Buffer.from(id).toString('hex')}`,
			);
		}
	}

	console.log('\n[2/4] proposing roster change (member #1 proposes) …');
	const propose = await proposeRosterChange(client, {
		membersToRemove: idsToRemove,
		newThreshold: 2n,
		authSigner: memberAuth[0].signer,
		gasSigner: signer1,
	});
	console.log('  rosterChangeId       :', propose.rosterChangeId.toString());
	console.log('  digest               :', propose.digest);

	let snap = await readRosterChange(client, propose.rosterChangeId);
	console.log('  approvals (post-prop):', snap.approvals.toString(), '/ 3');
	if (snap.approvals !== 1n) throw new Error('propose should auto-vote (=1 approval)');

	console.log('\n[3/4] approving from members #2 + #3 to reach quorum …');
	for (const idx of [1, 2]) {
		const r = await approveRosterChange(client, {
			rosterChangeId: propose.rosterChangeId,
			authSigner: memberAuth[idx].signer,
			gasSigner: signer1,
		});
		console.log(`  member #${idx + 1} approve  : ${r.digest}`);
		snap = await readRosterChange(client, propose.rosterChangeId);
		console.log(`  approvals            : ${snap.approvals}/3`);
	}

	if (snap.approvals < 3n) {
		throw new Error(`quorum not reached, got ${snap.approvals}`);
	}

	console.log('\n[4/4] executing roster change …');
	const exec = await executeRosterChange(client, {
		rosterChangeId: propose.rosterChangeId,
		gasSigner: signer1,
	});
	console.log('  digest               :', exec.digest);

	state = await readRecoveryState(client);
	console.log('\nfinal on-chain state:');
	console.log('  members              :', state.members.length);
	console.log('  threshold            :', state.threshold.toString());

	// Hard assertions.
	if (state.threshold !== 2n) {
		throw new Error(`expected threshold=2 after execute, got ${state.threshold}`);
	}
	if (state.members.length !== 3) {
		throw new Error(`expected 3 remaining members, got ${state.members.length}`);
	}
	for (const removed of idsToRemove) {
		if (memberPresent(state.members, removed)) {
			throw new Error(`removed id is still in roster: ${Buffer.from(removed).toString('hex')}`);
		}
	}
	for (const kept of [memberIdsForRoster[0], memberIdsForRoster[1], memberIdsForRoster[2]]) {
		if (!memberPresent(state.members, kept)) {
			throw new Error(`kept id missing from roster: ${Buffer.from(kept).toString('hex')}`);
		}
	}

	snap = await readRosterChange(client, propose.rosterChangeId);
	if (!snap.executed) throw new Error('snap.executed should be true');

	console.log('\n✓ roster-change e2e passed:');
	console.log('    5 ed25519 members @ threshold=3');
	console.log('    → propose remove(#4,#5) + threshold=2');
	console.log('    → 3-of-5 approvals');
	console.log('    → execute → 3 members @ threshold=2 (verified on-chain)');
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
