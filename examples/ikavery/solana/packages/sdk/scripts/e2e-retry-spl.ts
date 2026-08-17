/**
 * Devnet retry-on-same-dWallet e2e: two consecutive sweeps through the same
 * Recovery PDA + dWallet, each as its own proposal.
 *
 * Mirrors Sui's `e2e-retry-spl.ts` purpose — proves the recovery layer is
 * replayable. After run 1 sweeps SOL + 1 SPL, the admin re-mints, the dWallet
 * is re-funded with SOL, and run 2 fires a fresh `proposal_index = 1` against
 * the same Recovery to sweep again. Destination receives both waves.
 *
 * Required env: same as `e2e-recover-spl.ts` (SOLANA_KEYPAIR ≥ 1 SOL).
 */

import { createIkaClient } from '@ika.xyz/pre-alpha-solana-client/grpc';
import { keccak_256 } from '@noble/hashes/sha3';
import {
	createMint,
	getAccount,
	getAssociatedTokenAddressSync,
	getOrCreateAssociatedTokenAccount,
	mintTo,
} from '@solana/spl-token';
import {
	Connection,
	Keypair,
	PublicKey,
	SystemProgram,
	VersionedTransaction,
	type Signer,
} from '@solana/web3.js';
import bs58 from 'bs58';

import {
	approveAndConfirm,
	buildExecuteIx,
	buildSweepMessage,
	closeSplAccount,
	createIdempotentAta,
	createRecoveryAndConfirm,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	packSolanaMember,
	proposeAndConfirm,
	readProposal,
	readRecovery,
	SCHEME_SOLANA_ADDRESS,
	STATUS_APPROVED,
	STATUS_EXECUTED,
	transferSol,
	transferSplTokenChecked,
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
	type RawGrpc,
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

interface RunContext {
	connection: Connection;
	alice: Signer;
	rawGrpc: RawGrpc;
	dwalletPubkey: Uint8Array;
	dwalletSolPubkey: PublicKey;
	dwalletAccount: PublicKey;
	dwalletSessionId: Uint8Array;
	dkgAttestation: {
		attestation_data: Uint8Array;
		network_signature: Uint8Array;
		network_pubkey: Uint8Array;
	};
	cpiAuthority: PublicKey;
	cpiAuthorityBump: number;
	recovery: PublicKey;
	recoveryId: PublicKey;
	aliceSlot: Uint8Array;
	alt: import('@solana/web3.js').AddressLookupTableAccount;
	destination: PublicKey;
}

async function runSweep(
	ctx: RunContext,
	proposalIndex: number,
	mintAmount: bigint,
	sweepLamports: number,
	label: string,
) {
	console.log(`\n=== ${label} (proposal_index=${proposalIndex}) ===`);

	// (Re)mint SPL tokens to the dWallet's source ATA. The source ATA was
	// closed at the end of the previous run, so getOrCreateAssociatedTokenAccount
	// recreates it; admin pays rent.
	const decimals = 6;
	console.log('[mint] creating mint + minting to source ATA…');
	const mint = await createMint(
		ctx.connection,
		ctx.alice as Keypair,
		(ctx.alice as Keypair).publicKey,
		null,
		decimals,
	);
	const sourceAtaInfo = await getOrCreateAssociatedTokenAccount(
		ctx.connection,
		ctx.alice as Keypair,
		mint,
		ctx.dwalletSolPubkey,
		true,
	);
	await mintTo(
		ctx.connection,
		ctx.alice as Keypair,
		mint,
		sourceAtaInfo.address,
		ctx.alice as Keypair,
		mintAmount,
	);
	console.log('  mint:    ', mint.toBase58());
	console.log('  src ATA: ', sourceAtaInfo.address.toBase58());

	// Top up the dWallet's SOL balance — last run drained it minus rent.
	console.log('[fund] re-funding dWallet with 0.05 SOL…');
	await sendVersioned(ctx.connection, ctx.alice, [
		SystemProgram.transfer({
			fromPubkey: (ctx.alice as Keypair).publicKey,
			toPubkey: ctx.dwalletSolPubkey,
			lamports: 50_000_000,
		}),
	]);

	const destAta = getAssociatedTokenAddressSync(mint, ctx.destination, true);
	const sweepInstructions = [
		createIdempotentAta({
			payer: ctx.dwalletSolPubkey,
			ata: destAta,
			owner: ctx.destination,
			mint,
		}),
		transferSplTokenChecked({
			source: sourceAtaInfo.address,
			mint,
			destination: destAta,
			authority: ctx.dwalletSolPubkey,
			amount: mintAmount,
			decimals,
		}),
		closeSplAccount({
			account: sourceAtaInfo.address,
			destination: ctx.dwalletSolPubkey,
			authority: ctx.dwalletSolPubkey,
		}),
		transferSol(ctx.dwalletSolPubkey, ctx.destination, sweepLamports),
	];
	const proposeMsg = buildSweepMessage({
		feePayer: ctx.dwalletSolPubkey,
		instructions: sweepInstructions,
	});
	console.log('[propose] msg bytes:', proposeMsg.messageLen);

	const proposed = await proposeAndConfirm(
		{
			connection: ctx.connection,
			payer: ctx.alice,
			lookupTables: [ctx.alt],
		},
		{
			recovery: ctx.recovery,
			recoveryId: ctx.recoveryId,
			proposer: ctx.alice,
			proposalIndex,
			messageBytes: proposeMsg.messageBytes,
			userPubkey: ctx.dwalletPubkey,
			signatureScheme: SIG_SCHEME_EDDSA_SHA512,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: (ctx.alice as Keypair).publicKey.toBytes(),
			},
		},
	);
	console.log('[propose] proposal:', proposed.proposal.toBase58());

	await approveAndConfirm(
		{ connection: ctx.connection, payer: ctx.alice, lookupTables: [ctx.alt] },
		{
			recovery: ctx.recovery,
			proposal: proposed.proposal,
			approver: ctx.alice,
			memberSlot: ctx.aliceSlot,
			credential: {
				scheme: SCHEME_SOLANA_ADDRESS,
				pubkey: (ctx.alice as Keypair).publicKey.toBytes(),
			},
		},
	);
	const proposalApproved = await readProposal(ctx.connection, proposed.proposal);
	if (proposalApproved?.status !== STATUS_APPROVED) {
		throw new Error(`expected STATUS_APPROVED, got ${proposalApproved?.status}`);
	}
	console.log('[approve] status: STATUS_APPROVED');

	const { blockhash: sweepBlockhash, lastValidBlockHeight: sweepLastValid } =
		await ctx.connection.getLatestBlockhash('confirmed');
	const finalMsg = buildSweepMessage({
		feePayer: ctx.dwalletSolPubkey,
		instructions: sweepInstructions,
		recentBlockhash: sweepBlockhash,
	});
	const messageDigest = keccak_256(finalMsg.messageBytes);
	const { pda: messageApproval, bump: messageApprovalBump } = messageApprovalPda(
		CURVE_CURVE25519,
		ctx.dwalletPubkey,
		SIG_SCHEME_EDDSA_SHA512,
		messageDigest,
	);
	const { pda: coordinator } = coordinatorPda();
	const executeIx = buildExecuteIx({
		recovery: ctx.recovery,
		proposal: proposed.proposal,
		payer: (ctx.alice as Keypair).publicKey,
		messageBytes: finalMsg.messageBytes,
		coordinator,
		messageApproval,
		dwallet: ctx.dwalletAccount,
		callerProgram: IKAVERY_PROGRAM_ID,
		cpiAuthority: ctx.cpiAuthority,
		dwalletProgram: IKA_DWALLET_PROGRAM_ID,
		messageApprovalBump,
		cpiAuthorityBump: ctx.cpiAuthorityBump,
	});
	const executeSig = await sendVersioned(ctx.connection, ctx.alice, [executeIx], [], [ctx.alt]);
	console.log('[execute] sig:', executeSig);
	const proposalExecuted = await readProposal(ctx.connection, proposed.proposal);
	if (proposalExecuted?.status !== STATUS_EXECUTED) {
		throw new Error(`expected STATUS_EXECUTED, got ${proposalExecuted?.status}`);
	}

	console.log('[sign] gRPC presign + sign…');
	const presignId = await requestGlobalPresignCurve25519(
		ctx.rawGrpc,
		(ctx.alice as Keypair).publicKey.toBytes(),
		ctx.dwalletSessionId,
	);
	const txSigBytes = bs58.decode(executeSig);
	const sigBytes = await requestSignCurve25519(
		ctx.rawGrpc,
		(ctx.alice as Keypair).publicKey.toBytes(),
		ctx.dwalletSessionId,
		ctx.dkgAttestation,
		presignId,
		finalMsg.messageBytes,
		txSigBytes,
	);

	console.log('[broadcast] sweep tx…');
	const sweepTx = VersionedTransaction.deserialize(
		Buffer.concat([Buffer.from([0x01]), Buffer.from(sigBytes), Buffer.from(finalMsg.messageBytes)]),
	);
	const broadcastSig = await ctx.connection.sendRawTransaction(sweepTx.serialize(), {
		skipPreflight: true,
	});
	await ctx.connection.confirmTransaction(
		{
			signature: broadcastSig,
			blockhash: sweepBlockhash,
			lastValidBlockHeight: sweepLastValid,
		},
		'confirmed',
	);
	console.log('[broadcast] sig:', broadcastSig);

	return { mint, destAta, mintAmount, sweepLamports };
}

async function main() {
	const rpc = env('SOLANA_RPC', 'https://api.devnet.solana.com');
	const grpcUrl = env('IKA_GRPC', IKA_GRPC_URL);
	const keypairPath = env('SOLANA_KEYPAIR');
	const connection = new Connection(rpc, 'confirmed');
	const alice = loadKeypair(keypairPath);
	const destination = Keypair.generate().publicKey;

	console.log('rpc:        ', rpc);
	console.log('ikavery:    ', IKAVERY_PROGRAM_ID.toBase58());
	console.log('alice:      ', alice.publicKey.toBase58());
	console.log('destination:', destination.toBase58());

	const balance = await connection.getBalance(alice.publicKey);
	if (balance < 1_000_000_000) {
		throw new Error(
			`alice has ${balance / 1e9} SOL; need ≥1.0 SOL (two mint cycles + dWallet funding x2)`,
		);
	}

	const ika = createIkaClient(grpcUrl);
	const rawGrpc = makeRawGrpcSubmit(grpcUrl);

	try {
		console.log('\n[setup 1/3] gRPC DKG…');
		const dkg = await ika.requestDKG(alice.publicKey.toBytes());
		const dwalletPubkey = dkg.publicKey;
		const dwalletSolPubkey = new PublicKey(dwalletPubkey);
		const dwalletSessionId = dkgSessionId(dkg.attestationData);
		const { pda: dwalletAccount } = dwalletPda(CURVE_CURVE25519, dwalletPubkey);
		console.log('  dwallet pk:  ', dwalletSolPubkey.toBase58());
		console.log('  dwallet PDA: ', dwalletAccount.toBase58());

		await pollUntil(
			() => connection.getAccountInfo(dwalletAccount),
			(info) => !!info && info.data.length > 2 && info.data[0] === ikaDwallet.DWALLET_DISC,
			30_000,
		);

		console.log('[setup 2/3] transfer authority + create_recovery…');
		const { pda: cpiAuthority, bump: cpiAuthorityBump } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
		await sendVersioned(connection, alice, [
			buildTransferDwalletAuthorityIx({
				currentAuthority: alice.publicKey,
				dwallet: dwalletAccount,
				newAuthority: cpiAuthority,
			}),
		]);

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

		console.log('[setup 3/3] ALT…');
		const alt = await createIkaveryAlt(connection, alice);

		const ctx: RunContext = {
			connection,
			alice,
			rawGrpc,
			dwalletPubkey,
			dwalletSolPubkey,
			dwalletAccount,
			dwalletSessionId,
			dkgAttestation: {
				attestation_data: dkg.attestationData,
				network_signature: dkg.networkSignature,
				network_pubkey: dkg.networkPubkey,
			},
			cpiAuthority,
			cpiAuthorityBump,
			recovery: created.recovery,
			recoveryId: created.recoveryId.publicKey,
			aliceSlot,
			alt,
			destination,
		};

		const run1 = await runSweep(ctx, 0, 1_000_000n, 30_000_000, 'RUN 1');
		const run2 = await runSweep(ctx, 1, 2_000_000n, 20_000_000, 'RUN 2');

		// Verify cumulative effect on destination.
		console.log('\n=== verifying ===');
		const destLamports = await connection.getBalance(destination);
		const expectedLamports = run1.sweepLamports + run2.sweepLamports;
		console.log(`  destination SOL: ${destLamports / 1e9} (expected ≥ ${expectedLamports / 1e9})`);
		if (destLamports < expectedLamports) {
			throw new Error(`destination short on lamports: ${destLamports} < ${expectedLamports}`);
		}

		for (const r of [run1, run2]) {
			const ata = await getAccount(connection, r.destAta);
			console.log(`  destAta ${r.destAta.toBase58().slice(0, 8)}… amount=${ata.amount}`);
			if (ata.amount !== r.mintAmount) {
				throw new Error(
					`expected ${r.mintAmount}, got ${ata.amount} for mint ${r.mint.toBase58()}`,
				);
			}
		}

		// Recovery counters should reflect the two proposals.
		const recoveryAfter = await readRecovery(connection, created.recovery);
		if (!recoveryAfter) throw new Error('recovery disappeared');
		if (recoveryAfter.proposalCount !== 2) {
			throw new Error(`expected proposal_count=2, got ${recoveryAfter.proposalCount}`);
		}

		console.log('\n✓ retry e2e: same Recovery PDA replayed across two proposals');
	} finally {
		ika.close();
		rawGrpc.close();
	}
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
