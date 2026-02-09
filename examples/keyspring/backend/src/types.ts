/**
 * DKG submission data from frontend
 * Matches the IKA SDK CreateDWalletParams structure
 */
export interface DKGSubmitInput {
  // Public output from local DKG computation
  userPublicOutput: number[];
  // DKG message for the network
  userDkgMessage: number[];
  // Encrypted user secret key share and proof
  encryptedUserShareAndProof: number[];
  // Session identifier (random bytes)
  sessionIdentifier: number[];
  // Signer public key for encryption key registration
  signerPublicKey: number[];
  // Address where encryption key is registered
  encryptionKeyAddress: string;
  // Encryption key bytes
  encryptionKey: number[];
  // Signature over encryption key
  encryptionKeySignature: number[];
  // Curve type (0 = SECP256K1 for Ethereum, 2 = ED25519 for Sui)
  curve?: number;
}

/**
 * In-memory store for pending DKG requests
 */
export interface DKGRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: DKGSubmitInput;
  createdAt: Date;
  // Results after processing
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  encryptedUserSecretKeyShareId?: string | null;
  ethereumAddress?: string;
  digest?: string;
  error?: string;
}

/**
 * DKG submit response
 */
export interface DKGSubmitResponse {
  success: boolean;
  requestId: string;
  status: DKGRequest["status"];
}

/**
 * DKG status response
 */
export interface DKGStatusResponse {
  requestId: string;
  status: DKGRequest["status"];
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  ethereumAddress?: string;
  error?: string;
}

/**
 * Sign request input - NON-CUSTODIAL
 * The user computes userSignMessage client-side using createUserSignMessageWithPublicOutput
 * The secret share NEVER leaves the client
 * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet#signing-a-message
 */
export interface SignRequestInput {
  // The dWallet ID to sign with
  dWalletId: string;
  // The dWallet Cap ID for message approval
  dWalletCapId: string;
  // Encrypted user secret key share id
  encryptedUserSecretKeyShareId: string;
  // User output signature
  userOutputSignature: number[];
  // Presign ID (must be completed)
  presignId: string;
  // Message to sign (hex-encoded, e.g., Ethereum transaction hash)
  messageHex: string;
  // User sign message computed client-side via createUserSignMessageWithPublicOutput
  // This is the user's partial signature - NOT the secret share
  userSignMessage: number[];
  // Optional: Ethereum transaction details for broadcasting
  ethTx?: {
    to: string; // Recipient address
    value: string; // Value in wei (hex)
    nonce: number;
    gasLimit: string; // Hex
    maxFeePerGas: string; // Hex
    maxPriorityFeePerGas: string; // Hex
    chainId: number;
    from: string; // dWallet's Ethereum address
  };
}

/**
 * Sign request stored in memory
 */
export interface SignRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: SignRequestInput;
  createdAt: Date;
  // encrypted user secret key share id
  encryptedUserSecretKeyShareId?: string | null;
  userOutputSignature?: string;
  // Results
  signatureHex?: string;
  signId?: string;
  digest?: string;
  // Ethereum broadcast results
  ethTxHash?: string;
  ethBlockNumber?: number;
  error?: string;
}

/**
 * Presign request
 */
export interface PresignRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  dWalletId: string;
  createdAt: Date;
  // Results
  presignId?: string;
  error?: string;
}
