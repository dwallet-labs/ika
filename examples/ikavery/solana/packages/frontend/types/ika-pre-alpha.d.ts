/**
 * Local override for `@ika.xyz/pre-alpha-solana-client/grpc-web`. The
 * upstream package ships raw `.ts` files (no build step), and its
 * declared `DKGResult` requires a `dwalletAddr` field that the
 * implementation does not actually return — so a strict typecheck
 * fails on its own source.
 *
 * We restate the runtime-actual shape here so our consumers (the
 * setup + recover flows) typecheck cleanly. We only need
 * `defineBcsTypes` from the wrapper at runtime — the wrapped client's
 * Presign/Sign hardcode `PresignForDWallet`, which the network rejects
 * for Curve25519, so we drive `submitTransaction` ourselves over a
 * hand-rolled gRPC-Web fetch (`lib/ika-web.ts`).
 */
declare module '@ika.xyz/pre-alpha-solana-client/grpc-web' {
	export interface DKGResult {
		publicKey: Uint8Array;
		publicOutput?: Uint8Array;
	}

	export interface IkaDWalletWebClient {
		requestDKG(senderPubkey: Uint8Array): Promise<DKGResult>;
		requestPresign(senderPubkey: Uint8Array, dwalletAddr: Uint8Array): Promise<Uint8Array>;
		requestSign(
			senderPubkey: Uint8Array,
			dwalletAddr: Uint8Array,
			message: Uint8Array,
			presignId: Uint8Array,
			txSignature: Uint8Array,
		): Promise<Uint8Array>;
	}

	export function createIkaWebClient(baseUrl: string): IkaDWalletWebClient;

	/**
	 * Re-exported BCS schema definitions matching `crates/ika-dwallet-types`.
	 * The shape is opaque (each value is an `@mysten/bcs` schema with
	 * `.serialize` / `.parse`); we keep it as `unknown` here and let the
	 * frontend lib narrow per-call to avoid leaking the @mysten/bcs type
	 * into our own surface.
	 */
	export function defineBcsTypes(): Record<string, unknown>;
}
