/**
 * Devnet roster-change e2e on ikavery alone (no ika dWallet involvement).
 *
 * Flow:
 *   1. create_recovery with a 2-of-3 roster (alice + bob + charlie, all
 *      Solana addresses).
 *   2. propose a roster change that drops charlie and lowers threshold to 1.
 *   3. alice approves (auto-vote on propose) → 1/2.
 *   4. bob approves → threshold met → status flips to APPROVED.
 *   5. anyone executes → roster mutates in-place; charlie disappears,
 *      threshold becomes 1.
 *   6. read the Recovery PDA back and assert the new shape.
 *
 * No dWallet PDA / gRPC / sweep — execute_roster_change is a pure on-chain
 * mutation, so this script doesn't need 0.6 SOL like e2e-recover.ts.
 *
 * Required env:
 *   SOLANA_KEYPAIR     - path to a Solana JSON keypair (devnet-funded ≥0.05 SOL).
 *                        Acts as alice + the rent payer for everything.
 *   SOLANA_RPC         - default https://api.devnet.solana.com
 */

import { sha256 } from '@noble/hashes/sha2';
import { Connection, Keypair } from '@solana/web3.js';

import {
	approveRosterChangeAndConfirm,
	buildApproveIx,
	createRecoveryAndConfirm,
	executeRosterChangeAndConfirm,
	IKAVERY_PROGRAM_ID,
	memberIdBytes,
	packSolanaMember,
	proposeRosterChangeAndConfirm,
	readRecovery,
	SCHEME_SOLANA_ADDRESS,
	STATUS_APPROVED,
	STATUS_EXECUTED,
} from '../src';
import { createIkaveryAlt, env, loadKeypair, sendVersioned } from './lib';

async function main() {
	const rpc = env('SOLANA_RPC', 'https://api.devnet.solana.com');
	const keypairPath = env('SOLANA_KEYPAIR');
	const connection = new Connection(rpc, 'confirmed');
	const alice = loadKeypair(keypairPath);
	const bob = Keypair.generate();
	const charlie = Keypair.generate();

	console.log('rpc:    ', rpc);
	console.log('ikavery:', IKAVERY_PROGRAM_ID.toBase58());
	console.log('alice:  ', alice.publicKey.toBase58());
	console.log('bob:    ', bob.publicKey.toBase58());
	console.log('charlie:', charlie.publicKey.toBase58());

	const balance = await connection.getBalance(alice.publicKey);
	if (balance < 80_000_000) {
		throw new Error(
			`alice has ${balance / 1e9} SOL; need ≥0.08 SOL for create + roster + execute rent`,
		);
	}

	// Bob also signs `approve_roster_change`, so bob needs lamports for fees
	// and the new approval PDA's rent. Send a small float from alice.
	console.log('\n[setup] funding bob for tx fees + approval PDA rent…');
	const fundBobIx = (await import('@solana/web3.js')).SystemProgram.transfer({
		fromPubkey: alice.publicKey,
		toPubkey: bob.publicKey,
		lamports: 10_000_000,
	});
	await sendVersioned(connection, alice, [fundBobIx]);

	// Stand-in dWallet handle. roster-change never touches it.
	const dwallet32 = new Uint8Array(32).fill(0xfa);
	const aliceSlot = packSolanaMember(alice.publicKey);
	const bobSlot = packSolanaMember(bob.publicKey);
	const charlieSlot = packSolanaMember(charlie.publicKey);

	console.log('\n[1/4] create_recovery (3-of-3 → start at threshold 2)…');
	const created = await createRecoveryAndConfirm(
		{ connection, payer: alice },
		{
			creator: alice,
			dwallet: dwallet32,
			dwalletCurve: 2,
			threshold: 2,
			members: [aliceSlot, bobSlot, charlieSlot],
		},
	);
	console.log('  recovery:  ', created.recovery.toBase58());
	console.log('  recoveryId:', created.recoveryId.publicKey.toBase58());

	// ALT compressing sysvars + per-recovery accounts. propose_roster_change's
	// ix data with MAX_MEMBERS=8 is 945 bytes; we need the recovery + recoveryId
	// in the ALT alongside the sysvars to keep the v0 tx under 1232 bytes.
	const alt = await createIkaveryAlt(connection, alice, [
		created.recovery,
		created.recoveryId.publicKey,
	]);
	console.log('  alt:       ', alt.key.toBase58());

	// The on-chain handler treats `payload_hash` as opaque — it's the
	// per-op challenge digest the credential is "claimed" to have signed.
	// For SCHEME_SOLANA_ADDRESS the runtime gate is the Signer match, so
	// any 32-byte digest is fine. Use sha256 of the additions||removals
	// concatenation so the digest is deterministic for replay debugging.
	const payloadHash = sha256(Buffer.concat([memberIdBytes(charlieSlot)]));

	console.log('\n[2/4] propose_roster_change (remove charlie, threshold → 1)…');
	const proposed = await proposeRosterChangeAndConfirm(
		{ connection, payer: alice, lookupTables: [alt] },
		{
			recovery: created.recovery,
			recoveryId: created.recoveryId.publicKey,
			proposer: alice,
			payloadHash,
			additions: [],
			removals: [charlieSlot],
			newThreshold: 1,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alice.publicKey.toBytes(),
			},
		},
	);
	console.log('  rosterChange:', proposed.rosterChange.toBase58());

	// propose_roster_change does NOT auto-vote — approval_count starts at 0.
	// We need 2 separate approve_roster_change ixs to hit threshold=2.
	console.log('\n[3/4] alice + bob approve → threshold met…');
	await approveRosterChangeAndConfirm(
		{ connection, payer: alice, lookupTables: [alt] },
		{
			recovery: created.recovery,
			rosterChange: proposed.rosterChange,
			approver: alice,
			memberSlot: aliceSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alice.publicKey.toBytes(),
			},
		},
	);
	await approveRosterChangeAndConfirm(
		{ connection, payer: bob, lookupTables: [alt] },
		{
			recovery: created.recovery,
			rosterChange: proposed.rosterChange,
			approver: bob,
			memberSlot: bobSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: bob.publicKey.toBytes(),
			},
		},
	);

	// Re-read the rosterChange to confirm STATUS_APPROVED before execute.
	const rcAccount = await connection.getAccountInfo(proposed.rosterChange);
	if (!rcAccount) throw new Error('rosterChange disappeared after approve');
	const { decodeRosterChangeProposal } = await import('../src');
	const rcDecoded = decodeRosterChangeProposal(rcAccount.data);
	if (rcDecoded.status !== STATUS_APPROVED) {
		throw new Error(`expected STATUS_APPROVED on roster change, got ${rcDecoded.status}`);
	}
	console.log('  ✓ rosterChange status: STATUS_APPROVED');

	console.log('\n[4/4] execute_roster_change (alice sponsors)…');
	const executed = await executeRosterChangeAndConfirm(
		{ connection, payer: alice },
		{
			recovery: created.recovery,
			rosterChange: proposed.rosterChange,
			executor: alice,
		},
	);
	console.log('  execute sig:', executed.signature);

	const finalRecovery = await readRecovery(connection, created.recovery);
	if (!finalRecovery) throw new Error('recovery disappeared post-execute');
	if (finalRecovery.threshold !== 1) {
		throw new Error(`expected threshold=1, got ${finalRecovery.threshold}`);
	}
	if (finalRecovery.members.length !== 2) {
		throw new Error(`expected 2 members (alice + bob), got ${finalRecovery.members.length}`);
	}
	const stillCharlie = finalRecovery.members.some((slot) =>
		Buffer.from(memberIdBytes(slot)).equals(memberIdBytes(charlieSlot)),
	);
	if (stillCharlie) throw new Error('charlie should have been removed');

	const rcExecuted = decodeRosterChangeProposal(
		(await connection.getAccountInfo(proposed.rosterChange))!.data,
	);
	if (rcExecuted.status !== STATUS_EXECUTED) {
		throw new Error(`expected STATUS_EXECUTED, got ${rcExecuted.status}`);
	}

	console.log('\n✓ roster-change e2e: charlie removed, threshold 2 → 1');
	console.log(`  members now: alice + bob (was 3, threshold 2 → 1)`);

	// Suppress an "unused" warning while keeping the import documenting intent.
	void buildApproveIx;
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
