/**
 * Full devnet end-to-end recovery: ika DKG → ikavery create → propose →
 * approve → execute (CPI to dWallet program) → ika gRPC Sign → broadcast
 * the rebuilt sweep tx. Funds actually move at the end.
 *
 * Required env:
 *   SOLANA_KEYPAIR     - path to a Solana JSON keypair (devnet-funded). Acts
 *                        as the recovery creator + sole roster member +
 *                        dWallet pre-transfer authority. Need ≥0.6 SOL —
 *                        most of it goes into the dWallet that gets swept.
 *   SOLANA_RPC         - default https://api.devnet.solana.com
 *   IKA_GRPC           - default pre-alpha-dev-1.ika.ika-network.net:443
 */

import { createIkaClient } from '@ika.xyz/pre-alpha-solana-client/grpc';
import { keccak_256 } from '@noble/hashes/sha3';
import {
	Connection,
	Keypair,
	PublicKey,
	SystemProgram,
	VersionedTransaction,
} from '@solana/web3.js';
import bs58 from 'bs58';

import {
	approveAndConfirm,
	buildExecuteIx,
	buildSweepMessage,
	createRecoveryAndConfirm,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	packSolanaMember,
	proposeAndConfirm,
	readProposal,
	SCHEME_SOLANA_ADDRESS,
	STATUS_APPROVED,
	STATUS_EXECUTED,
	transferSol,
} from '../src';
import {
	createIkaveryAlt,
	dkgSessionId,
	env,
	loadKeypair,
	makeRawGrpcSubmit,
	pollUntil,
	requestGlobalPresignCurve25519,
	requestSignCurve25519,
	sendVersioned,
} from './lib';

const {
	CURVE_CURVE25519,
	IKA_DWALLET_PROGRAM_ID,
	IKA_GRPC_URL,
	SIG_SCHEME_EDDSA_SHA512,
	buildTransferDwalletAuthorityIx,
	coordinatorPda,
	cpiAuthorityPda,
	dwalletPda,
	messageApprovalPda,
} = ikaDwallet;

async function main() {
	const rpc = env('SOLANA_RPC', 'https://api.devnet.solana.com');
	const grpcUrl = env('IKA_GRPC', IKA_GRPC_URL);
	const keypairPath = env('SOLANA_KEYPAIR');
	const connection = new Connection(rpc, 'confirmed');
	const alice = loadKeypair(keypairPath);

	console.log('rpc:        ', rpc);
	console.log('grpc:       ', grpcUrl);
	console.log('ikavery:    ', IKAVERY_PROGRAM_ID.toBase58());
	console.log('dwallet pgm:', IKA_DWALLET_PROGRAM_ID.toBase58());
	console.log('alice:      ', alice.publicKey.toBase58());

	const balance = await connection.getBalance(alice.publicKey);
	console.log('balance:    ', balance / 1e9, 'SOL');
	if (balance < 600_000_000) {
		throw new Error(`alice has ${balance / 1e9} SOL; need ≥0.6 SOL (most goes into the dWallet)`);
	}

	const ika = createIkaClient(grpcUrl);
	const rawGrpc = makeRawGrpcSubmit(grpcUrl);

	try {
		console.log('\n[1/9] gRPC DKG…');
		const dkg = await ika.requestDKG(alice.publicKey.toBytes());
		const dwalletPubkey = dkg.publicKey;
		const dwalletSolPubkey = new PublicKey(dwalletPubkey);
		const dwalletSessionId = dkgSessionId(dkg.attestationData);
		console.log('  dwallet pk:', dwalletSolPubkey.toBase58());

		const { pda: dwalletAccount } = dwalletPda(CURVE_CURVE25519, dwalletPubkey);
		console.log('  dwallet PDA:', dwalletAccount.toBase58());

		console.log('\n[2/9] waiting for on-chain dWallet PDA…');
		await pollUntil(
			() => connection.getAccountInfo(dwalletAccount),
			(info) => !!info && info.data.length > 2 && info.data[0] === ikaDwallet.DWALLET_DISC,
			30_000,
		);
		console.log('  ok');

		console.log('\n[3/9] transferring dWallet authority to ikavery CPI PDA…');
		const { pda: cpiAuthority, bump: cpiAuthorityBump } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
		console.log('  cpi authority:', cpiAuthority.toBase58());
		const transferIx = buildTransferDwalletAuthorityIx({
			currentAuthority: alice.publicKey,
			dwallet: dwalletAccount,
			newAuthority: cpiAuthority,
		});
		const transferSig = await sendVersioned(connection, alice, [transferIx]);
		console.log('  transfer sig:', transferSig);

		console.log('\n[4/9] funding dWallet with 0.05 SOL…');
		const fundIx = SystemProgram.transfer({
			fromPubkey: alice.publicKey,
			toPubkey: dwalletSolPubkey,
			lamports: 50_000_000,
		});
		const fundSig = await sendVersioned(connection, alice, [fundIx]);
		console.log('  fund sig:   ', fundSig);

		console.log('\n[5/9] ikavery create_recovery…');
		const aliceSlot = packSolanaMember(alice.publicKey);
		const created = await createRecoveryAndConfirm(
			{ connection, payer: alice },
			{
				creator: alice,
				dwallet: dwalletPubkey,
				dwalletCurve: CURVE_CURVE25519,
				threshold: 1,
				members: [aliceSlot],
			},
		);
		console.log('  recovery:  ', created.recovery.toBase58());
		console.log('  recoveryId:', created.recoveryId.publicKey.toBase58());

		console.log('\n[6/9] propose + approve sweep…');
		const alt = await createIkaveryAlt(connection, alice);

		const recipient = Keypair.generate();
		const sweepInstructions = [transferSol(dwalletSolPubkey, recipient.publicKey, 40_000_000)];
		const proposeMsg = buildSweepMessage({
			feePayer: dwalletSolPubkey,
			instructions: sweepInstructions,
		});
		const proposed = await proposeAndConfirm(
			{ connection, payer: alice, lookupTables: [alt] },
			{
				recovery: created.recovery,
				recoveryId: created.recoveryId.publicKey,
				proposer: alice,
				messageBytes: proposeMsg.messageBytes,
				userPubkey: dwalletPubkey,
				signatureScheme: SIG_SCHEME_EDDSA_SHA512,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: alice.publicKey.toBytes(),
				},
			},
		);
		console.log('  proposal:  ', proposed.proposal.toBase58());
		console.log('  recipient: ', recipient.publicKey.toBase58());

		const approved = await approveAndConfirm(
			{ connection, payer: alice, lookupTables: [alt] },
			{
				recovery: created.recovery,
				proposal: proposed.proposal,
				approver: alice,
				memberSlot: aliceSlot,
				credential: {
					scheme: SCHEME_SOLANA_ADDRESS,
					pubkey: alice.publicKey.toBytes(),
				},
			},
		);
		const proposalApproved = await readProposal(connection, proposed.proposal);
		if (proposalApproved?.status !== STATUS_APPROVED) {
			throw new Error(`expected STATUS_APPROVED, got ${proposalApproved?.status}`);
		}
		console.log('  approval:  ', approved.approval.toBase58());

		console.log('\n[7/9] ikavery execute (CPI → dwallet MessageApproval)…');
		const { blockhash: sweepBlockhash, lastValidBlockHeight: sweepLastValid } =
			await connection.getLatestBlockhash('confirmed');
		const finalMsg = buildSweepMessage({
			feePayer: dwalletSolPubkey,
			instructions: sweepInstructions,
			recentBlockhash: sweepBlockhash,
		});
		const messageDigest = keccak_256(finalMsg.messageBytes);
		const { pda: messageApproval, bump: messageApprovalBump } = messageApprovalPda(
			CURVE_CURVE25519,
			dwalletPubkey,
			SIG_SCHEME_EDDSA_SHA512,
			messageDigest,
		);
		const { pda: coordinator } = coordinatorPda();
		const executeIx = buildExecuteIx({
			recovery: created.recovery,
			proposal: proposed.proposal,
			payer: alice.publicKey,
			messageBytes: finalMsg.messageBytes,
			coordinator,
			messageApproval,
			dwallet: dwalletAccount,
			callerProgram: IKAVERY_PROGRAM_ID,
			cpiAuthority,
			dwalletProgram: IKA_DWALLET_PROGRAM_ID,
			messageApprovalBump,
			cpiAuthorityBump,
		});
		const executeSig = await sendVersioned(connection, alice, [executeIx], [], [alt]);
		console.log('  execute sig:', executeSig);

		const proposalExecuted = await readProposal(connection, proposed.proposal);
		if (proposalExecuted?.status !== STATUS_EXECUTED) {
			throw new Error(`expected STATUS_EXECUTED, got ${proposalExecuted?.status}`);
		}
		console.log('  ✓ proposal status: STATUS_EXECUTED');

		console.log('\n[8/9] gRPC presign + sign (Curve25519/EdDSA)…');
		const presignId = await requestGlobalPresignCurve25519(
			rawGrpc,
			alice.publicKey.toBytes(),
			dwalletSessionId,
		);
		const txSigBytes = bs58.decode(executeSig);
		const sigBytes = await requestSignCurve25519(
			rawGrpc,
			alice.publicKey.toBytes(),
			dwalletSessionId,
			{
				attestation_data: dkg.attestationData,
				network_signature: dkg.networkSignature,
				network_pubkey: dkg.networkPubkey,
			},
			presignId,
			finalMsg.messageBytes,
			txSigBytes,
		);
		if (sigBytes.length !== 64) {
			throw new Error(`expected 64-byte ed25519 signature, got ${sigBytes.length}`);
		}

		console.log('\n[9/9] broadcasting sweep tx…');
		const sweepTx = VersionedTransaction.deserialize(
			Buffer.concat([
				Buffer.from([0x01]),
				Buffer.from(sigBytes),
				Buffer.from(finalMsg.messageBytes),
			]),
		);
		const broadcastSig = await connection.sendRawTransaction(sweepTx.serialize(), {
			skipPreflight: true,
		});
		await connection.confirmTransaction(
			{
				signature: broadcastSig,
				blockhash: sweepBlockhash,
				lastValidBlockHeight: sweepLastValid,
			},
			'confirmed',
		);
		console.log('  broadcast sig:', broadcastSig);

		const finalRecipientBalance = await connection.getBalance(recipient.publicKey);
		console.log('  recipient balance:', finalRecipientBalance / 1e9, 'SOL');
		if (finalRecipientBalance !== 40_000_000) {
			throw new Error(`expected recipient to hold 0.04 SOL, got ${finalRecipientBalance / 1e9}`);
		}
		console.log('\n✓ full e2e: dWallet swept by ikavery → recipient');
	} finally {
		ika.close();
		rawGrpc.close();
	}
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
