// Demo backend API client

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5153";

export interface DKGSubmitParams {
  userPublicOutput: number[];
  userDkgMessage: number[];
  encryptedUserShareAndProof: number[];
  sessionIdentifier: number[];
  signerPublicKey: number[];
  encryptionKeyAddress: string;
  encryptionKey: number[];
  encryptionKeySignature: number[];
  curve?: number;
}

export interface DKGSubmitResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
}

export interface DKGStatusResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  encryptedUserSecretKeyShareId?: string | null;
  ethereumAddress?: string;
  error?: string;
}

export interface PresignRequestResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
}

export interface PresignStatusResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
  presignId?: string;
  error?: string;
}

export interface EthTxParams {
  to: string;
  value: string; // wei in hex
  nonce: number;
  gasLimit: string; // hex
  maxFeePerGas: string; // hex
  maxPriorityFeePerGas: string; // hex
  chainId: number;
  from: string;
}

export interface SignRequestParams {
  dWalletId: string;
  dWalletCapId: string;
  encryptedUserSecretKeyShareId: string;
  userOutputSignature: number[];
  presignId: string;
  messageHex: string;
  userSignMessage: number[];
  ethTx?: EthTxParams;
}

export interface SignRequestResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
}

export interface SignStatusResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
  signatureHex?: string;
  signId?: string;
  ethTxHash?: string;
  ethBlockNumber?: number;
  error?: string;
}

export async function submitDKG(
  params: DKGSubmitParams
): Promise<DKGSubmitResponse> {
  const response = await fetch(`${API_BASE}/api/dkg/submit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to submit DKG");
  }

  return response.json();
}

export async function getDKGStatus(
  requestId: string
): Promise<DKGStatusResponse> {
  const response = await fetch(`${API_BASE}/api/dkg/status/${requestId}`);

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to get DKG status");
  }

  return response.json();
}

export async function requestPresign(
  dWalletId: string
): Promise<PresignRequestResponse> {
  const response = await fetch(`${API_BASE}/api/presign/request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ dWalletId }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to request presign");
  }

  return response.json();
}

export async function getPresignStatus(
  requestId: string
): Promise<PresignStatusResponse> {
  const response = await fetch(`${API_BASE}/api/presign/status/${requestId}`);

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to get presign status");
  }

  return response.json();
}

export async function requestSign(
  params: SignRequestParams
): Promise<SignRequestResponse> {
  const response = await fetch(`${API_BASE}/api/sign/request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to request sign");
  }

  return response.json();
}

export async function getSignStatus(
  requestId: string
): Promise<SignStatusResponse> {
  const response = await fetch(`${API_BASE}/api/sign/status/${requestId}`);

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to get sign status");
  }

  return response.json();
}

export interface EthTxParamsResponse {
  success: boolean;
  nonce: number;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  gasLimit: string;
  error?: string;
}

/**
 * Fetch current nonce and gas prices for an Ethereum address
 * Call this before signing to get accurate transaction parameters
 */
export async function getEthTxParams(
  address: string
): Promise<EthTxParamsResponse> {
  const response = await fetch(`${API_BASE}/api/eth/tx-params/${address}`);

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to get transaction parameters");
  }

  return response.json();
}
