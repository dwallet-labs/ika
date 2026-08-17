'use client';

import { defineBcsTypes } from '@ika.xyz/pre-alpha-solana-client/grpc-web';

import { IKA_GRPC_WEB_URL } from '@/lib/env';

/**
 * Client-side BCS + gRPC-Web wiring for the ika dWallet pre-alpha
 * service.
 *
 * The shipped `createIkaWebClient` wrapper hardcodes `PresignForDWallet`,
 * which the pre-alpha network rejects for Curve25519 with "only for
 * imported ECDSA keys". So for both DKG and the Curve25519 Presign +
 * Sign path we drive the underlying `submitTransaction` RPC ourselves
 * over a hand-rolled gRPC-Web fetch.
 *
 * gRPC-Web framing is one length-prefixed frame:
 *   [0x00 (compression flag)] [4 bytes BE length] [protobuf bytes]
 * Trailers come back as a second frame with a `0x80` MSB on the flag.
 * We only need to read the data frame here.
 */
const SERVICE_PATH = '/ika.dwallet.v1.DWalletService/SubmitTransaction';

interface BcsCodec {
	serialize: (input: unknown) => { toBytes: () => Uint8Array };
	parse: (input: Uint8Array) => Record<string, unknown>;
}

const bcsTypes = defineBcsTypes() as Record<string, BcsCodec>;
const SignedRequestData = bcsTypes.SignedRequestData!;
const TransactionResponseData = bcsTypes.TransactionResponseData!;
const UserSignature = bcsTypes.UserSignature!;
const VersionedDWalletDataAttestation = bcsTypes.VersionedDWalletDataAttestation!;
const VersionedPresignDataAttestation = bcsTypes.VersionedPresignDataAttestation!;

export interface IkaDkgResult {
	publicKey: Uint8Array;
	attestationData: Uint8Array;
	networkSignature: Uint8Array;
	networkPubkey: Uint8Array;
}

export interface IkaAttestation {
	attestationData: Uint8Array;
	networkSignature: Uint8Array;
	networkPubkey: Uint8Array;
}

/** DKG via the same gRPC-Web hop. Returns the dWallet pubkey + attestation. */
export async function ikaDkgWeb(senderPubkey: Uint8Array): Promise<IkaDkgResult> {
	const data = SignedRequestData.serialize({
		session_identifier_preimage: Array.from(new Uint8Array(32)),
		epoch: 1n,
		chain_id: { Solana: true },
		intended_chain_sender: Array.from(senderPubkey),
		request: {
			DKG: {
				dwallet_network_encryption_public_key: Array.from(new Uint8Array(32)),
				curve: { Curve25519: true },
				centralized_public_key_share_and_proof: Array.from(new Uint8Array(32)),
				user_secret_key_share: {
					Encrypted: {
						encrypted_centralized_secret_share_and_proof: Array.from(new Uint8Array(32)),
						encryption_key: Array.from(new Uint8Array(32)),
						signer_public_key: Array.from(senderPubkey),
					},
				},
				user_public_output: Array.from(new Uint8Array(32)),
				sign_during_dkg_request: null,
			},
		},
	}).toBytes();
	const respBytes = await submit(buildMockUserSig(senderPubkey), data);
	const resp = TransactionResponseData.parse(respBytes) as {
		Attestation?: {
			attestation_data: number[];
			network_signature: number[];
			network_pubkey: number[];
		};
		Error?: { message: string };
	};
	if (resp.Error) throw new Error(`DKG failed: ${resp.Error.message}`);
	if (!resp.Attestation) {
		throw new Error(`DKG failed: ${JSON.stringify(resp)}`);
	}
	const att = resp.Attestation;
	const payload = VersionedDWalletDataAttestation.parse(new Uint8Array(att.attestation_data)) as {
		V1?: { public_key: number[] };
	};
	if (!payload.V1) {
		throw new Error('DKG payload: missing V1 variant');
	}
	return {
		publicKey: new Uint8Array(payload.V1.public_key),
		attestationData: new Uint8Array(att.attestation_data),
		networkSignature: new Uint8Array(att.network_signature),
		networkPubkey: new Uint8Array(att.network_pubkey),
	};
}

/**
 * Presign + sign over a Curve25519/EdDSA dWallet — the path the recover
 * flow walks. Returns the 64-byte EdDSA signature ready to splice into
 * the v0 sweep tx.
 */
export async function ikaPresignAndSignCurve25519(
	senderPubkey: Uint8Array,
	attestation: IkaAttestation,
	message: Uint8Array,
	txSignature: Uint8Array,
): Promise<Uint8Array> {
	const sessionId = dkgSessionId(attestation.attestationData);
	const presignId = await ikaGlobalPresignCurve25519(senderPubkey, sessionId);
	return ikaSignCurve25519(senderPubkey, sessionId, attestation, presignId, message, txSignature);
}

async function ikaGlobalPresignCurve25519(
	senderPubkey: Uint8Array,
	dwalletSessionId: Uint8Array,
): Promise<Uint8Array> {
	const data = SignedRequestData.serialize({
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
	const respBytes = await submit(buildMockUserSig(senderPubkey), data);
	const resp = TransactionResponseData.parse(respBytes) as {
		Attestation?: { attestation_data: number[] };
		Error?: { message: string };
	};
	if (resp.Error) throw new Error(`Presign failed: ${resp.Error.message}`);
	if (!resp.Attestation) {
		throw new Error(`Presign failed: ${JSON.stringify(resp)}`);
	}
	const versioned = VersionedPresignDataAttestation.parse(
		new Uint8Array(resp.Attestation.attestation_data),
	) as { V1?: { presign_session_identifier: number[] } };
	if (!versioned.V1) {
		throw new Error('unexpected presign payload variant');
	}
	return new Uint8Array(versioned.V1.presign_session_identifier);
}

async function ikaSignCurve25519(
	senderPubkey: Uint8Array,
	dwalletSessionId: Uint8Array,
	attestation: IkaAttestation,
	presignId: Uint8Array,
	message: Uint8Array,
	txSignature: Uint8Array,
): Promise<Uint8Array> {
	const data = SignedRequestData.serialize({
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
					attestation_data: Array.from(attestation.attestationData),
					network_signature: Array.from(attestation.networkSignature),
					network_pubkey: Array.from(attestation.networkPubkey),
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
	const respBytes = await submit(buildMockUserSig(senderPubkey), data);
	const resp = TransactionResponseData.parse(respBytes) as {
		Signature?: { signature: number[] };
		Error?: { message: string };
	};
	if (resp.Signature) return new Uint8Array(resp.Signature.signature);
	if (resp.Error) throw new Error(`Sign error: ${resp.Error.message}`);
	throw new Error(`unexpected sign response: ${JSON.stringify(resp)}`);
}

function dkgSessionId(attestationData: Uint8Array): Uint8Array {
	const versioned = VersionedDWalletDataAttestation.parse(attestationData) as {
		V1?: { session_identifier: number[] };
	};
	if (!versioned.V1) {
		throw new Error('DKG attestation: missing V1 variant');
	}
	return Uint8Array.from(versioned.V1.session_identifier);
}

function buildMockUserSig(senderPubkey: Uint8Array): Uint8Array {
	return UserSignature.serialize({
		Ed25519: {
			signature: Array.from(new Uint8Array(64)),
			public_key: Array.from(senderPubkey),
		},
	}).toBytes();
}

// ─── gRPC-Web framing over fetch ─────────────────────────────────────

async function submit(
	userSignature: Uint8Array,
	signedRequestData: Uint8Array,
): Promise<Uint8Array> {
	const requestProto = encodeUserSignedRequest(userSignature, signedRequestData);
	const framed = frameRequest(requestProto);

	const baseUrl = IKA_GRPC_WEB_URL.replace(/\/$/, '');
	const res = await fetch(baseUrl + SERVICE_PATH, {
		method: 'POST',
		headers: {
			'content-type': 'application/grpc-web+proto',
			accept: 'application/grpc-web+proto',
			'x-grpc-web': '1',
		},
		// Cast through ArrayBuffer — TypeScript's `BodyInit` rejects the
		// typed-array form even though browsers accept it.
		body: framed.buffer.slice(
			framed.byteOffset,
			framed.byteOffset + framed.byteLength,
		) as ArrayBuffer,
	});
	if (!res.ok) {
		throw new Error(`gRPC-Web HTTP ${res.status}: ${await res.text()}`);
	}
	// Trailer-only error response: `grpc-status` may live in headers.
	const status = res.headers.get('grpc-status');
	if (status && status !== '0') {
		const message = res.headers.get('grpc-message') ?? `gRPC status ${status}`;
		throw new Error(`gRPC-Web error ${status}: ${decodeURIComponent(message)}`);
	}
	const buf = new Uint8Array(await res.arrayBuffer());
	const { dataFrame, trailerStatus, trailerMessage } = readFrames(buf);
	if (trailerStatus !== null && trailerStatus !== '0') {
		throw new Error(`gRPC-Web error ${trailerStatus}: ${trailerMessage ?? 'unknown'}`);
	}
	if (!dataFrame) {
		throw new Error('gRPC-Web response had no data frame');
	}
	return decodeTransactionResponse(dataFrame);
}

function frameRequest(proto: Uint8Array): Uint8Array {
	const out = new Uint8Array(5 + proto.length);
	out[0] = 0x00; // compression flag
	const view = new DataView(out.buffer);
	view.setUint32(1, proto.length, false);
	out.set(proto, 5);
	return out;
}

function readFrames(buf: Uint8Array): {
	dataFrame: Uint8Array | null;
	trailerStatus: string | null;
	trailerMessage: string | null;
} {
	let offset = 0;
	let dataFrame: Uint8Array | null = null;
	let trailerStatus: string | null = null;
	let trailerMessage: string | null = null;
	while (offset + 5 <= buf.length) {
		const flag = buf[offset]!;
		const view = new DataView(buf.buffer, buf.byteOffset + offset + 1, 4);
		const len = view.getUint32(0, false);
		const start = offset + 5;
		const end = start + len;
		if (end > buf.length) break;
		const body = buf.subarray(start, end);
		if ((flag & 0x80) === 0) {
			dataFrame = body;
		} else {
			const trailer = new TextDecoder().decode(body);
			for (const raw of trailer.split(/\r\n|\n/)) {
				if (!raw) continue;
				const idx = raw.indexOf(':');
				if (idx === -1) continue;
				const key = raw.slice(0, idx).trim().toLowerCase();
				const value = raw.slice(idx + 1).trim();
				if (key === 'grpc-status') trailerStatus = value;
				if (key === 'grpc-message') trailerMessage = decodeURIComponent(value);
			}
		}
		offset = end;
	}
	return { dataFrame, trailerStatus, trailerMessage };
}

// ─── minimal proto3 encode/decode ────────────────────────────────────
//
// The two messages we touch are dead simple — bytes-only — so we don't
// need a full proto runtime.

function encodeUserSignedRequest(
	userSignature: Uint8Array,
	signedRequestData: Uint8Array,
): Uint8Array {
	// Field 1, 2 = bytes (wire type 2 = length-delimited). Tag = (n<<3)|2.
	const parts: Uint8Array[] = [];
	parts.push(new Uint8Array([0x0a]));
	parts.push(varint(userSignature.length));
	parts.push(userSignature);
	parts.push(new Uint8Array([0x12]));
	parts.push(varint(signedRequestData.length));
	parts.push(signedRequestData);
	return concat(parts);
}

function decodeTransactionResponse(buf: Uint8Array): Uint8Array {
	// TransactionResponse { bytes response_data = 1 }
	let off = 0;
	let responseData: Uint8Array | null = null;
	while (off < buf.length) {
		const [tag, t1] = readVarint(buf, off);
		off = t1;
		const fieldNumber = tag >>> 3;
		const wireType = tag & 0x07;
		if (wireType !== 2) {
			throw new Error(`unexpected wire type ${wireType}`);
		}
		const [len, t2] = readVarint(buf, off);
		off = t2;
		const body = buf.subarray(off, off + len);
		off += len;
		if (fieldNumber === 1) responseData = body;
	}
	if (!responseData) throw new Error('response missing field 1 (response_data)');
	return new Uint8Array(responseData);
}

function varint(n: number): Uint8Array {
	const bytes: number[] = [];
	let v = n >>> 0;
	while (v >= 0x80) {
		bytes.push((v & 0x7f) | 0x80);
		v >>>= 7;
	}
	bytes.push(v & 0x7f);
	return new Uint8Array(bytes);
}

function readVarint(buf: Uint8Array, offset: number): [number, number] {
	let result = 0;
	let shift = 0;
	let off = offset;
	while (off < buf.length) {
		const b = buf[off]!;
		off += 1;
		result |= (b & 0x7f) << shift;
		if ((b & 0x80) === 0) return [result >>> 0, off];
		shift += 7;
		if (shift > 28) throw new Error('varint too long');
	}
	throw new Error('truncated varint');
}

function concat(parts: Uint8Array[]): Uint8Array {
	const total = parts.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}
