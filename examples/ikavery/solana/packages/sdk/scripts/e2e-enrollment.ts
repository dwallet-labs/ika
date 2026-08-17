/**
 * Devnet enrollment e2e on ikavery alone (no ika dWallet involvement).
 *
 * Flow:
 *   1. create_recovery with a 1-of-1 roster (alice only).
 *   2. propose_enrollment to add bob as a key-holding member.
 *   3. alice approves → threshold met → status flips to APPROVED.
 *   4. anyone executes → roster grows in-place; bob appears.
 *   5. read the Recovery PDA back and assert the new shape.
 *
 * No dWallet PDA / gRPC / sweep — execute_enrollment is a pure on-chain
 * mutation (no re-encrypt CPI on pre-alpha; mock signer has no real shares).
 *
 * Required env:
 *   SOLANA_KEYPAIR     - path to a Solana JSON keypair (devnet-funded ≥0.05 SOL).
 *                        Acts as alice + the rent payer for everything.
 *   SOLANA_RPC         - default https://api.devnet.solana.com
 */

import { Connection, Keypair } from '@solana/web3.js';

import {
	approveEnrollmentAndConfirm,
	createRecoveryAndConfirm,
	decodeEnrollmentProposal,
	executeEnrollmentAndConfirm,
	IKAVERY_PROGRAM_ID,
	memberIdBytes,
	packSolanaMember,
	proposeEnrollmentAndConfirm,
	readRecovery,
	SCHEME_SOLANA_ADDRESS,
	STATUS_APPROVED,
	STATUS_EXECUTED,
} from '../src';
import { createIkaveryAlt, env, loadKeypair } from './lib';

async function main() {
	const rpc = env('SOLANA_RPC', 'https://api.devnet.solana.com');
	const keypairPath = env('SOLANA_KEYPAIR');
	const connection = new Connection(rpc, 'confirmed');
	const alice = loadKeypair(keypairPath);
	const bob = Keypair.generate();

	console.log('rpc:    ', rpc);
	console.log('ikavery:', IKAVERY_PROGRAM_ID.toBase58());
	console.log('alice:  ', alice.publicKey.toBase58());
	console.log('bob:    ', bob.publicKey.toBase58());

	const balance = await connection.getBalance(alice.publicKey);
	if (balance < 50_000_000) {
		throw new Error(
			`alice has ${balance / 1e9} SOL; need ≥0.05 SOL for create + enroll + execute rent`,
		);
	}

	// Stand-in dWallet handle. enrollment never touches it.
	const dwallet32 = new Uint8Array(32).fill(0xfa);
	const aliceSlot = packSolanaMember(alice.publicKey);
	const bobSlot = packSolanaMember(bob.publicKey);

	console.log('\n[1/4] create_recovery (1-of-1 alice only)…');
	const created = await createRecoveryAndConfirm(
		{ connection, payer: alice },
		{
			creator: alice,
			dwallet: dwallet32,
			dwalletCurve: 2,
			threshold: 1,
			members: [aliceSlot],
		},
	);
	console.log('  recovery:  ', created.recovery.toBase58());
	console.log('  recoveryId:', created.recoveryId.publicKey.toBase58());

	// ALT compresses sysvars + per-recovery accounts so propose_enrollment's
	// ix data (~440 bytes) stays comfortably under the 1232-byte tx cap.
	const alt = await createIkaveryAlt(connection, alice, [
		created.recovery,
		created.recoveryId.publicKey,
	]);
	console.log('  alt:       ', alt.key.toBase58());

	// Stand-in encryption key address. Solana ika pre-alpha has no re-encrypt
	// CPI, so the on-chain handler stores this opaquely; mainnet would bind
	// the new member's class-groups public key here.
	const encryptionKeyAddress = new Uint8Array(32).fill(0xee);

	console.log('\n[2/4] propose_enrollment (add bob as key-holding member)…');
	const proposed = await proposeEnrollmentAndConfirm(
		{ connection, payer: alice, lookupTables: [alt] },
		{
			recovery: created.recovery,
			recoveryId: created.recoveryId.publicKey,
			proposer: alice,
			newMember: bobSlot,
			newEncryptionKeyAddress: encryptionKeyAddress,
			additionApproverOnly: 0,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alice.publicKey.toBytes(),
			},
		},
	);
	console.log('  enrollment:', proposed.enrollment.toBase58());

	console.log('\n[3/4] alice approves → threshold met…');
	await approveEnrollmentAndConfirm(
		{ connection, payer: alice, lookupTables: [alt] },
		{
			recovery: created.recovery,
			enrollment: proposed.enrollment,
			approver: alice,
			memberSlot: aliceSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: alice.publicKey.toBytes(),
			},
		},
	);

	const enAccount = await connection.getAccountInfo(proposed.enrollment);
	if (!enAccount) throw new Error('enrollment disappeared after approve');
	const enDecoded = decodeEnrollmentProposal(enAccount.data);
	if (enDecoded.status !== STATUS_APPROVED) {
		throw new Error(`expected STATUS_APPROVED on enrollment, got ${enDecoded.status}`);
	}
	console.log('  ✓ enrollment status: STATUS_APPROVED');

	console.log('\n[4/4] execute_enrollment (alice sponsors)…');
	const executed = await executeEnrollmentAndConfirm(
		{ connection, payer: alice },
		{
			recovery: created.recovery,
			enrollment: proposed.enrollment,
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
	const hasBob = finalRecovery.members.some((slot) =>
		Buffer.from(memberIdBytes(slot)).equals(memberIdBytes(bobSlot)),
	);
	if (!hasBob) throw new Error('bob should have been added');

	const enExecuted = decodeEnrollmentProposal(
		(await connection.getAccountInfo(proposed.enrollment))!.data,
	);
	if (enExecuted.status !== STATUS_EXECUTED) {
		throw new Error(`expected STATUS_EXECUTED, got ${enExecuted.status}`);
	}

	console.log('\n✓ enrollment e2e: bob added (1 → 2 members, threshold 1)');
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
