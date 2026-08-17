/**
 * Public env wiring. Each value falls back to a sensible devnet default so a
 * fresh clone can `bun dev` without needing a `.env.local` file. Override
 * via the env variables documented in `.env.example`.
 */

export const DYNAMIC_ENVIRONMENT_ID =
	process.env.NEXT_PUBLIC_DYNAMIC_ENVIRONMENT_ID ?? '9dd6152b-680a-4322-bee8-69fced543f9a';

export const SOLANA_RPC = process.env.NEXT_PUBLIC_SOLANA_RPC ?? 'https://api.devnet.solana.com';

export const IKAVERY_PROGRAM_ID =
	process.env.NEXT_PUBLIC_IKAVERY_PROGRAM_ID ?? '6kdyWi8FJah4xt2SyL2fEBFYacQ7iaDsgQjKCDhgEbCi';

export const IKA_GRPC_URL =
	process.env.NEXT_PUBLIC_IKA_GRPC ?? 'pre-alpha-dev-1.ika.ika-network.net:443';

/**
 * gRPC-Web endpoint of the same Ika service. Browser-callable via
 * `fetch` over HTTPS — the network's tonic gateway speaks both gRPC and
 * gRPC-Web on the same host. For setup (DKG) and recover (Presign +
 * Sign) the frontend calls it directly with no Node-side hop.
 */
export const IKA_GRPC_WEB_URL =
	process.env.NEXT_PUBLIC_IKA_GRPC_WEB ?? 'https://pre-alpha-dev-1.ika.ika-network.net';

/**
 * WebAuthn relying-party id. Defaults to the page's hostname so a passkey
 * created on `localhost` stays scoped to localhost. Override via
 * `NEXT_PUBLIC_RP_ID` for production deployments where the page is served
 * on a different origin than the credential id should be bound to.
 */
export const rpId =
	process.env.NEXT_PUBLIC_RP_ID ??
	(typeof window !== 'undefined' ? window.location.hostname : 'localhost');

export const rpName = process.env.NEXT_PUBLIC_RP_NAME ?? 'Ikavery';
