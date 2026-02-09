import {
  Curve,
  getNetworkConfig,
  IkaClient,
  prepareDKG,
  UserShareEncryptionKeys,
  createUserSignMessageWithPublicOutput,
  Hash,
  SignatureAlgorithm,
} from "@ika.xyz/sdk";
import { SuiClient } from "@mysten/sui/client";

const ADMIN_ADDRESS =
  process.env.NEXT_PUBLIC_ADMIN_ADDRESS ||
  "0x60c2fb8e919a6bd487b8424524f484da5d0b2a9b3e0300d993707212ffbf953e";

// Message to sign for deterministic key derivation
// IMPORTANT: Do not change this message - it affects the derived wallet address
export const DKG_SIGN_MESSAGE = `Ika dWallet DKG Demo - Ethereum

This signature is used to derive your encryption keys.

Sign this message to create your cross-chain dWallet for Ethereum.

Note: This signature does not authorize any transactions.`;

// Cache for protocol parameters
let cachedProtocolParams: Map<Curve, Uint8Array> = new Map();

// Use SECP256K1 for Ethereum-compatible wallets
export const ETHEREUM_CURVE = Curve.SECP256K1;

// Wallet types supported
export type WalletType = "ethereum" | "solana";

/**
 * Get IKA client instance
 */
export function getIkaClient(): IkaClient {
  const config = getNetworkConfig("testnet");
  const suiClient = new SuiClient({
    url: "https://sui-testnet-rpc.publicnode.com",
  });

  return new IkaClient({
    suiClient,
    config,
    cache: true,
  });
}

/**
 * Get protocol public parameters from Ika network
 */
export async function getProtocolPublicParameters(
  curve: Curve = ETHEREUM_CURVE
): Promise<Uint8Array> {
  const cached = cachedProtocolParams.get(curve);
  if (cached) {
    return cached;
  }

  const ikaClient = getIkaClient();
  const params = await ikaClient.getProtocolPublicParameters(undefined, curve);
  cachedProtocolParams.set(curve, params);
  return params;
}

/**
 * Compute encryption keys from a signature seed
 */
export async function computeEncryptionKeys(
  signatureSeed: string,
  curve: Curve = ETHEREUM_CURVE
): Promise<UserShareEncryptionKeys> {
  const keys = await UserShareEncryptionKeys.fromRootSeedKey(
    new TextEncoder().encode(signatureSeed),
    curve
  );
  return keys;
}

/**
 * Prepare DKG locally
 */
export async function prepareDKGLocal(params: {
  curve: Curve;
  encryptionKeys: UserShareEncryptionKeys;
  sessionIdentifier: Uint8Array;
  protocolPublicParameters: Uint8Array;
}): Promise<{
  userPublicOutput: number[];
  userSecretKeyShare: number[];
  userDKGMessage: number[];
  encryptedUserShareAndProof: number[];
}> {
  const result = await prepareDKG(
    params.protocolPublicParameters,
    params.curve,
    params.encryptionKeys.encryptionKey,
    params.sessionIdentifier,
    ADMIN_ADDRESS
  );

  return {
    userPublicOutput: Array.from(result.userPublicOutput),
    userSecretKeyShare: Array.from(result.userSecretKeyShare),
    userDKGMessage: Array.from(result.userDKGMessage),
    encryptedUserShareAndProof: Array.from(result.encryptedUserShareAndProof),
  };
}

/**
 * Create user sign message locally (non-custodial)
 * This is called with the decrypted secret share on the client
 */
export async function createUserSignMessage(params: {
  protocolPublicParameters: Uint8Array;
  publicOutput: Uint8Array;
  secretShare: Uint8Array;
  presignBytes: Uint8Array;
  message: Uint8Array;
}): Promise<Uint8Array> {
  const userSignMessage = await createUserSignMessageWithPublicOutput(
    params.protocolPublicParameters,
    params.publicOutput,
    params.secretShare,
    params.presignBytes,
    params.message,
    Hash.KECCAK256, // For Ethereum
    SignatureAlgorithm.ECDSASecp256k1, // For Ethereum
    Curve.SECP256K1
  );

  return userSignMessage;
}

/**
 * DKG step names for UI - user-friendly labels
 */
export type DKGStep =
  | "idle"
  | "signing"
  | "fetching_params"
  | "computing_keys"
  | "preparing_dkg"
  | "submitting"
  | "waiting"
  | "completed"
  | "failed";

export const DKG_STEP_LABELS: Record<DKGStep, string> = {
  idle: "Ready",
  signing: "Sign in your wallet...",
  fetching_params: "Getting ready...",
  computing_keys: "Setting up security...",
  preparing_dkg: "Creating your wallet...",
  submitting: "Almost there...",
  waiting: "Finishing up...",
  completed: "Done!",
  failed: "Something went wrong",
};

/**
 * Curve value mapping for backend
 */
export function getCurveValue(curve: Curve): number {
  switch (curve) {
    case Curve.SECP256K1:
      return 0;
    case Curve.SECP256R1:
      return 1;
    case Curve.ED25519:
      return 2;
    case Curve.RISTRETTO:
      return 3;
    default:
      return 0;
  }
}
