/**
 * Shared scaffolding for ikavery devnet e2e scripts. Anything that doesn't
 * belong in the SDK proper (env handling, keypair loading, ad-hoc
 * VersionedTransaction senders, ALT bootstrap, raw ika gRPC calls for the
 * variants the package wrapper doesn't expose) lives here.
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { credentials as grpcCredentials } from '@grpc/grpc-js';
import { defineBcsTypes } from '@ika.xyz/pre-alpha-solana-client/grpc';
import {
	AddressLookupTableProgram,
	Connection,
	Keypair,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type PublicKey,
	type Signer,
	type TransactionInstruction,
} from '@solana/web3.js';

import { SYSVAR_INSTRUCTIONS_ID, SYSVAR_RENT_ID } from '../src';

// ── env / keypairs ─────────────────────────────────────────────────────────

export function env(k: string, fallback?: string): string {
	const v = process.env[k] ?? fallback;
	if (!v) throw new Error(`missing env ${k}`);
	return v;
}

export function loadKeypair(path: string): Keypair {
	const raw = JSON.parse(readFileSync(path, 'utf-8'));
	return Keypair.fromSecretKey(Uint8Array.from(raw));
}

// ── tx send ────────────────────────────────────────────────────────────────

export async function sendVersioned(
	connection: Connection,
	payer: Signer,
	ixs: TransactionInstruction[],
	extraSigners: Signer[] = [],
	lookupTables: AddressLookupTableAccount[] = [],
): Promise<string> {
	const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
	const message = new TransactionMessage({
		payerKey: payer.publicKey,
		recentBlockhash: blockhash,
		instructions: ixs,
	}).compileToV0Message(lookupTables);
	const tx = new VersionedTransaction(message);
	tx.sign([payer, ...extraSigners]);
	const sig = await connection.sendRawTransaction(tx.serialize(), {
		skipPreflight: false,
		preflightCommitment: 'confirmed',
	});
	await connection.confirmTransaction(
		{ signature: sig, blockhash, lastValidBlockHeight },
		'confirmed',
	);
	return sig;
}

export async function pollUntil<T>(
	fn: () => Promise<T | null>,
	predicate: (v: T) => boolean,
	timeoutMs: number,
	intervalMs = 800,
): Promise<T> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		const v = await fn();
		if (v && predicate(v)) return v;
		await new Promise((r) => setTimeout(r, intervalMs));
	}
	throw new Error(`pollUntil: timed out after ${timeoutMs}ms`);
}

/**
 * Create an ALT containing the three static accounts every ikavery ix
 * references (sysvar instructions, sysvar rent, system program). Without
 * ALT compression a single `propose` ix exceeds devnet/mainnet's
 * 1232-byte single-tx cap.
 */
export async function createIkaveryAlt(
	connection: Connection,
	payer: Keypair,
	/**
	 * Extra per-recovery accounts to compress (e.g. recovery PDA, recoveryId).
	 * `propose_roster_change` is fundamentally size-tight on Solana — the ix
	 * data alone is 1489 bytes for MAX_MEMBERS=16, so we need to pull as
	 * many account slots as possible into the lookup table to stay under
	 * the 1232-byte tx packet cap.
	 */
	extraAccounts: PublicKey[] = [],
): Promise<AddressLookupTableAccount> {
	const slot = await connection.getSlot('finalized');
	const [createIx, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
		authority: payer.publicKey,
		payer: payer.publicKey,
		recentSlot: slot,
	});
	const extendIx = AddressLookupTableProgram.extendLookupTable({
		payer: payer.publicKey,
		authority: payer.publicKey,
		lookupTable: lookupTableAddress,
		addresses: [SYSVAR_INSTRUCTIONS_ID, SYSVAR_RENT_ID, SystemProgram.programId, ...extraAccounts],
	});
	await sendVersioned(connection, payer, [createIx, extendIx]);
	await new Promise((r) => setTimeout(r, 800));
	const fetched = await connection.getAddressLookupTable(lookupTableAddress);
	if (!fetched.value) {
		throw new Error(`ALT ${lookupTableAddress.toBase58()} not visible after create`);
	}
	return fetched.value;
}

// ── raw gRPC (Curve25519/EdDSA — variants the wrapper doesn't expose) ──────

const requireFromHere = createRequire(import.meta.url);
const wrapperPath = requireFromHere.resolve('@ika.xyz/pre-alpha-solana-client/grpc');
const generatedClientPath = wrapperPath.replace(/grpc\.ts$/, 'generated/grpc/ika_dwallet.ts');
const generatedGrpc = requireFromHere(generatedClientPath);
const DWalletServiceClient = generatedGrpc.DWalletServiceClient as unknown as {
	new (
		addr: string,
		creds: ReturnType<typeof grpcCredentials.createSsl>,
	): {
		submitTransaction: (
			req: { userSignature: Buffer; signedRequestData: Buffer },
			cb: (err: Error | null, resp?: { responseData: Uint8Array }) => void,
		) => void;
		close: () => void;
	};
};

export const BCS_TYPES = defineBcsTypes();

export interface RawGrpc {
	submit(userSignature: Uint8Array, signedRequestData: Uint8Array): Promise<Uint8Array>;
	close(): void;
}

export function makeRawGrpcSubmit(grpcUrl: string): RawGrpc {
	const isSecure = !grpcUrl.includes('localhost') && !grpcUrl.match(/127\.0\.0\.1/);
	const cleaned = grpcUrl.replace(/^https?:\/\//, '');
	const client = new DWalletServiceClient(
		cleaned,
		isSecure ? grpcCredentials.createSsl() : grpcCredentials.createInsecure(),
	);
	return {
		submit(userSignature, signedRequestData) {
			return new Promise((resolve, reject) => {
				client.submitTransaction(
					{
						userSignature: Buffer.from(userSignature),
						signedRequestData: Buffer.from(signedRequestData),
					},
					(err, resp) => {
						if (err) reject(err);
						else resolve(new Uint8Array(resp!.responseData));
					},
				);
			});
		},
		close() {
			client.close();
		},
	};
}

export function buildMockUserSig(senderPubkey: Uint8Array): Uint8Array {
	return BCS_TYPES.UserSignature.serialize({
		Ed25519: {
			signature: Array.from(new Uint8Array(64)),
			public_key: Array.from(senderPubkey),
		},
	}).toBytes();
}

/**
 * Global Presign for Curve25519/EdDSA — the wrapper hardcodes
 * `PresignForDWallet` which the network rejects for Curve25519 with
 * "only for imported ECDSA keys". Returns the presign session id.
 */
export async function requestGlobalPresignCurve25519(
	raw: RawGrpc,
	senderPubkey: Uint8Array,
	dwalletSessionId: Uint8Array,
): Promise<Uint8Array> {
	const data = BCS_TYPES.SignedRequestData.serialize({
		session_identifier_preimage: Array.from(dwalletSessionId),
		epoch: 1n,
		chain_id: { Solana: true },
		intended_chain_sender: Array.from(senderPubkey),
		request: {
			Presign: {
				dwallet_network_encryption_public_key: Array.from(new Uint8Array(32)),
				curve: { Curve25519: true },
				signature_algorithm: { EdDSA: true },
			},
		},
	}).toBytes();
	const respBytes = await raw.submit(buildMockUserSig(senderPubkey), data);
	const resp = BCS_TYPES.TransactionResponseData.parse(new Uint8Array(respBytes));
	if (!resp.Attestation) {
		throw new Error(`Presign failed: ${JSON.stringify(resp)}`);
	}
	const versioned = BCS_TYPES.VersionedPresignDataAttestation.parse(
		new Uint8Array(resp.Attestation.attestation_data),
	);
	if (!versioned.V1) {
		throw new Error(`unexpected presign payload: ${JSON.stringify(versioned)}`);
	}
	return new Uint8Array(versioned.V1.presign_session_identifier);
}

export async function requestSignCurve25519(
	raw: RawGrpc,
	senderPubkey: Uint8Array,
	dwalletSessionId: Uint8Array,
	dwalletAttestation: {
		attestation_data: Uint8Array;
		network_signature: Uint8Array;
		network_pubkey: Uint8Array;
	},
	presignId: Uint8Array,
	message: Uint8Array,
	txSignature: Uint8Array,
): Promise<Uint8Array> {
	const data = BCS_TYPES.SignedRequestData.serialize({
		session_identifier_preimage: Array.from(dwalletSessionId),
		epoch: 1n,
		chain_id: { Solana: true },
		intended_chain_sender: Array.from(senderPubkey),
		request: {
			Sign: {
				message: Array.from(message),
				message_metadata: [],
				presign_session_identifier: Array.from(presignId),
				message_centralized_signature: Array.from(new Uint8Array(64)),
				dwallet_attestation: {
					attestation_data: Array.from(dwalletAttestation.attestation_data),
					network_signature: Array.from(dwalletAttestation.network_signature),
					network_pubkey: Array.from(dwalletAttestation.network_pubkey),
					epoch: 1n,
				},
				approval_proof: {
					Solana: {
						transaction_signature: Array.from(txSignature),
						slot: 0n,
					},
				},
			},
		},
	}).toBytes();
	const respBytes = await raw.submit(buildMockUserSig(senderPubkey), data);
	const resp = BCS_TYPES.TransactionResponseData.parse(new Uint8Array(respBytes));
	if (resp.Signature) {
		return new Uint8Array(resp.Signature.signature);
	}
	if (resp.Error) {
		throw new Error(`gRPC Sign error: ${resp.Error.message}`);
	}
	throw new Error(`unexpected sign response: ${JSON.stringify(resp)}`);
}

/**
 * Extract the DWallet PDA's `session_identifier` from a DKG attestation —
 * the mock signer commits its key under this preimage, not under the
 * public key. Subsequent Presign / Sign calls must echo it back.
 */
export function dkgSessionId(attestationData: Uint8Array): Uint8Array {
	const versioned = BCS_TYPES.VersionedDWalletDataAttestation.parse(attestationData);
	if (!versioned.V1) {
		throw new Error(`unexpected DKG attestation: ${JSON.stringify(versioned)}`);
	}
	return Uint8Array.from(versioned.V1.session_identifier);
}
