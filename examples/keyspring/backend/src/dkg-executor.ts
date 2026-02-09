import { SuiClient } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import {
  SerialTransactionExecutor,
  Transaction,
} from "@mysten/sui/transactions";
import {
  getNetworkConfig,
  IkaClient,
  coordinatorTransactions,
  type IkaConfig,
  SessionsManagerModule,
  CoordinatorInnerModule,
  Curve,
  publicKeyFromCentralizedDKGOutput,
  SignatureAlgorithm,
  IkaTransaction,
  Hash,
} from "@ika.xyz/sdk";
import {
  createPublicClient,
  http,
  serializeTransaction,
  type TransactionSerializableEIP1559,
  type Hex,
  recoverTransactionAddress,
} from "viem";
import { baseSepolia } from "viem/chains";
import { config } from "./config.js";
import { logger } from "./logger.js";
import type {
  DKGRequest,
  DKGSubmitInput,
  PresignRequest,
  SignRequest,
  SignRequestInput,
} from "./types.js";
import { computeAddress } from "ethers";

// Timeout helper to prevent indefinite waits
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ]);
}

// Operation timeouts (in milliseconds)
const TIMEOUTS = {
  TRANSACTION_WAIT: 60_000, // 60 seconds for transaction confirmation
  SIGN_WAIT: 120_000, // 2 minutes for signature from network
  PRESIGN_WAIT: 120_000, // 2 minutes for presign completion
  ETH_RECEIPT_WAIT: 60_000, // 60 seconds for ETH transaction receipt
} as const;

// In-memory store for DKG requests
const dkgRequests = new Map<string, DKGRequest>();
// In-memory store for presign requests
const presignRequests = new Map<string, PresignRequest>();
// In-memory store for sign requests
const signRequests = new Map<string, SignRequest>();

// Curve constants
const CURVE_SECP256K1 = 0; // For Ethereum
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Derive Ethereum address from BCS-encoded SECP256K1 public key (x-coordinate only)
 */

function deriveEthereumAddress(publicKeyBytes: Uint8Array): string {
  // accepts 33B compressed or 65B uncompressed (with 0x04)
  return computeAddress(("0x" + bytesToHex(publicKeyBytes)) as `0x${string}`);
}

// Base Sepolia testnet client
const ethClient = createPublicClient({
  chain: baseSepolia,
  transport: http("https://sepolia.base.org"),
});

/**
 * DKG Executor Service
 * Processes DKG requests and creates dWallets on the Ika network
 */
export class DKGExecutorService {
  private client: SuiClient;
  private ikaConfig: IkaConfig;
  private ikaClient: IkaClient;
  private executor: SerialTransactionExecutor;
  private adminKeypair: Ed25519Keypair;
  private isRunning = false;
  private pollTimeout: NodeJS.Timeout | null = null;

  constructor() {
    // Get network-specific RPC URL
    const rpcUrl =
      config.sui.network === "mainnet"
        ? "https://ikafn-on-sui-2-mainnet.ika-network.net/"
        : "https://sui-testnet-rpc.publicnode.com";

    this.client = new SuiClient({ url: rpcUrl });
    this.ikaConfig = getNetworkConfig(config.sui.network);
    this.ikaClient = new IkaClient({
      suiClient: this.client,
      config: this.ikaConfig,
    });

    // Initialize admin keypair
    this.adminKeypair = Ed25519Keypair.fromSecretKey(config.sui.adminSecretKey);

    // Initialize executor
    this.executor = new SerialTransactionExecutor({
      client: this.client,
      signer: this.adminKeypair,
    });

    logger.info(
      {
        signerAddress: this.adminKeypair.toSuiAddress(),
        network: config.sui.network,
      },
      "DKG Executor initialized"
    );
  }

  /**
   * Get IKA client for external use
   */
  getIkaClient(): IkaClient {
    return this.ikaClient;
  }

  /**
   * Submit a new DKG request
   */
  submitRequest(data: DKGSubmitInput): DKGRequest {
    const id = crypto.randomUUID();
    const request: DKGRequest = {
      id,
      status: "pending",
      data,
      createdAt: new Date(),
    };
    dkgRequests.set(id, request);
    logger.info(
      { requestId: id, curve: data.curve ?? CURVE_SECP256K1 },
      "DKG request submitted"
    );
    return request;
  }

  /**
   * Get request status
   */
  getRequest(id: string): DKGRequest | undefined {
    return dkgRequests.get(id);
  }

  /**
   * Submit a presign request
   */
  submitPresignRequest(dWalletId: string): PresignRequest {
    const id = crypto.randomUUID();
    const request: PresignRequest = {
      id,
      status: "pending",
      dWalletId,
      createdAt: new Date(),
    };
    presignRequests.set(id, request);
    logger.info({ requestId: id, dWalletId }, "Presign request submitted");
    return request;
  }

  /**
   * Get presign request status
   */
  getPresignRequest(id: string): PresignRequest | undefined {
    return presignRequests.get(id);
  }

  /**
   * Submit a sign request (non-custodial)
   * The userSignMessage is computed client-side - secret share never leaves the client
   */
  submitSignRequest(data: SignRequestInput): SignRequest {
    const id = crypto.randomUUID();
    const request: SignRequest = {
      id,
      status: "pending",
      data,
      createdAt: new Date(),
    };
    signRequests.set(id, request);
    logger.info(
      { requestId: id, dWalletId: data.dWalletId, presignId: data.presignId },
      "Sign request submitted"
    );
    return request;
  }

  /**
   * Get sign request status
   */
  getSignRequest(id: string): SignRequest | undefined {
    return signRequests.get(id);
  }

  /**
   * Start the execution loop
   */
  start(): void {
    if (this.isRunning) {
      logger.warn("DKG Executor is already running");
      return;
    }

    this.isRunning = true;
    logger.info("Starting DKG Executor...");

    // Start polling with error recovery
    this.poll().catch((err) => {
      logger.error({ err }, "Error starting poll loop - will retry");
      if (this.isRunning) {
        this.pollTimeout = setTimeout(() => this.poll(), 5000);
      }
    });
  }

  /**
   * Stop the execution loop
   */
  stop(): void {
    this.isRunning = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
      this.pollTimeout = null;
    }
    logger.info("Stopped DKG Executor");
  }

  /**
   * Poll for pending requests
   * Uses setInterval pattern for more reliable scheduling on Railway
   */
  private async poll(): Promise<void> {
    if (!this.isRunning) return;

    try {
      await this.processPendingRequests();
    } catch (error) {
      logger.error({ error }, "Error processing DKG requests");
    }

    try {
      await this.processPendingPresigns();
    } catch (error) {
      logger.error({ error }, "Error processing presigns");
    }

    try {
      await this.processPendingSigns();
    } catch (error) {
      logger.error({ error }, "Error processing signs");
    }

    try {
      this.cleanupOldRequests();
    } catch (error) {
      logger.error({ error }, "Error cleaning up old requests");
    }

    // Schedule next poll (2 seconds) - always schedule even if errors occurred
    if (this.isRunning) {
      this.pollTimeout = setTimeout(() => {
        this.poll().catch((err) => {
          logger.error({ err }, "Fatal error in poll loop - restarting");
          // Force restart the poll loop after a delay
          if (this.isRunning) {
            this.pollTimeout = setTimeout(() => this.poll(), 5000);
          }
        });
      }, 2000);
    }
  }

  /**
   * Clean up old completed/failed requests to prevent memory leaks
   * Keeps requests for 1 hour after completion
   */
  private cleanupOldRequests(): void {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;

    for (const [id, request] of dkgRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        dkgRequests.delete(id);
      }
    }

    for (const [id, request] of presignRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        presignRequests.delete(id);
      }
    }

    for (const [id, request] of signRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        signRequests.delete(id);
      }
    }
  }

  /**
   * Process all pending requests
   */
  private async processPendingRequests(): Promise<void> {
    const pending = Array.from(dkgRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info({ count: pending.length }, "Processing pending DKG requests");

    for (const request of pending) {
      await this.processRequest(request);
    }
  }

  /**
   * Process all pending presign requests
   */
  private async processPendingPresigns(): Promise<void> {
    const pending = Array.from(presignRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info(
      { count: pending.length },
      "Processing pending presign requests"
    );

    for (const request of pending) {
      await this.processPresignRequest(request);
    }
  }

  /**
   * Process all pending sign requests
   */
  private async processPendingSigns(): Promise<void> {
    const pending = Array.from(signRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info({ count: pending.length }, "Processing pending sign requests");

    for (const request of pending) {
      await this.processSignRequest(request);
    }
  }

  /**
   * Process a single DKG request
   */
  private async processRequest(request: DKGRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      // Mark as processing
      request.status = "processing";
      requestLogger.info("Processing DKG request");

      // Execute the DKG transaction
      const result = await this.executeDKGTransaction(request.data);

      // Mark as completed
      request.status = "completed";
      request.dWalletCapObjectId = result.dWalletCapObjectId;
      request.dWalletObjectId = result.dWalletObjectId;
      request.ethereumAddress = result.ethereumAddress;
      request.digest = result.digest;
      request.encryptedUserSecretKeyShareId =
        result.encryptedUserSecretKeyShareId || null;

      requestLogger.info(
        {
          dWalletCapObjectId: result.dWalletCapObjectId,
          dWalletObjectId: result.dWalletObjectId,
          ethereumAddress: result.ethereumAddress,
          digest: result.digest,
          encryptedUserSecretKeyShareId: result.encryptedUserSecretKeyShareId,
        },
        "DKG request completed successfully"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "DKG request failed");
    }
  }

  /**
   * Process a single presign request
   */
  private async processPresignRequest(request: PresignRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      request.status = "processing";
      requestLogger.info("Processing presign request");

      const result = await this.executePresignTransaction(request.dWalletId);

      request.status = "completed";
      request.presignId = result.presignId;

      requestLogger.info(
        { presignId: result.presignId },
        "Presign request completed"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "Presign request failed");
    }
  }

  /**
   * Process a single sign request (non-custodial)
   * Uses the userSignMessage computed client-side
   */
  private async processSignRequest(request: SignRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      request.status = "processing";
      requestLogger.info("Processing sign request");

      const result = await this.executeSignTransaction(request.data);

      request.status = "completed";
      request.signatureHex = result.signatureHex;
      request.signId = result.signId;
      request.digest = result.digest;
      request.ethTxHash = result.ethTxHash;
      request.ethBlockNumber = result.ethBlockNumber;

      requestLogger.info(
        {
          signId: result.signId,
          signatureHex: result.signatureHex?.slice(0, 20) + "...",
          ethTxHash: result.ethTxHash,
        },
        "Sign request completed"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "Sign request failed");
    }
  }

  /**
   * Execute the DKG transaction on Sui/Ika network
   * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet
   */
  private async executeDKGTransaction(data: DKGSubmitInput): Promise<{
    dWalletCapObjectId: string;
    dWalletObjectId: string;
    ethereumAddress?: string;
    digest: string;
    encryptedUserSecretKeyShareId: string | null;
  }> {
    let tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    tx.setGasBudget(1 * 10 ** 9); // 1 SUI

    // Use SECP256K1 for Ethereum by default
    const curve = data.curve ?? CURVE_SECP256K1;

    // Get the latest network encryption key
    const encryptionKey = await this.ikaClient.getLatestNetworkEncryptionKey();

    logger.debug(
      { encryptionKeyId: encryptionKey.id, curve },
      "Got network encryption key"
    );

    // Step 1: Register encryption key
    coordinatorTransactions.registerEncryptionKeyTx(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      curve,
      new Uint8Array(data.encryptionKey),
      new Uint8Array(data.encryptionKeySignature),
      new Uint8Array(data.signerPublicKey),
      tx
    );

    // dry run tx here because maybe user already did have an enc key
    const res = await this.client.devInspectTransactionBlock({
      sender: this.adminKeypair.toSuiAddress(),
      transactionBlock: tx,
    });

    if (res.error) {
      // user already has an enc key we shouldn't register it again
      tx = new Transaction();
      tx.setSender(adminAddress);
      tx.setGasBudget(1 * 10 ** 9); // 1 SUI
    }

    const latestNetworkEncryptionKeyId = encryptionKey.id;

    // Step 2: Request DKG - create the dWallet
    const [dWalletCap] = coordinatorTransactions.requestDWalletDKG(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      latestNetworkEncryptionKeyId,
      curve,
      new Uint8Array(data.userDkgMessage),
      new Uint8Array(data.encryptedUserShareAndProof),
      data.encryptionKeyAddress,
      new Uint8Array(data.userPublicOutput),
      new Uint8Array(data.signerPublicKey),
      coordinatorTransactions.registerSessionIdentifier(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        new Uint8Array(data.sessionIdentifier),
        tx
      ),
      null,
      tx.object(config.ika.coinId),
      tx.gas,
      tx
    );

    // Step 3: Transfer the dWallet cap to the admin address
    tx.transferObjects([dWalletCap], adminAddress);

    logger.debug("Executing DKG transaction...");

    // Execute transaction
    const result = await this.executor.executeTransaction(tx);

    logger.debug({ digest: result.digest }, "Transaction executed");

    // Wait for transaction and parse events (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: {
          showEvents: true,
        },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "DKG transaction confirmation"
    );

    // Find the created DWalletCap and dWallet objects from events
    let dWalletCapObjectId: string | null = null;
    let dWalletObjectId: string | null = null;
    let encryptedUserSecretKeyShareId: string | null = null;

    for (const event of txResult.events || []) {
      if (event.type.includes("DWalletSessionEvent")) {
        try {
          const parsedData = SessionsManagerModule.DWalletSessionEvent(
            CoordinatorInnerModule.DWalletDKGRequestEvent
          ).fromBase64(event.bcs);

          dWalletCapObjectId = parsedData.event_data.dwallet_cap_id;
          dWalletObjectId = parsedData.event_data.dwallet_id;
          encryptedUserSecretKeyShareId =
            parsedData.event_data.user_secret_key_share.Encrypted
              ?.encrypted_user_secret_key_share_id || null;
        } catch (parseError) {
          logger.warn(
            { event: event.type, parseError },
            "Failed to parse DWalletSessionEvent"
          );
        }
      }
    }

    if (!dWalletCapObjectId || !dWalletObjectId) {
      logger.warn(
        {
          events: txResult.events?.map((e) => e.type),
          digest: result.digest,
        },
        "Could not find dWallet objects in transaction result"
      );
      throw new Error("Failed to parse dWallet objects from transaction");
    }

    // Derive Ethereum address from the dWallet's combined public output (not user's contribution)
    let ethereumAddress: string | undefined;
    const publicKey = await publicKeyFromCentralizedDKGOutput(
      Curve.SECP256K1,
      new Uint8Array(data.userPublicOutput)
    );
    ethereumAddress = deriveEthereumAddress(publicKey);

    return {
      dWalletCapObjectId,
      dWalletObjectId,
      ethereumAddress,
      digest: result.digest,
      encryptedUserSecretKeyShareId,
    };
  }

  /**
   * Execute presign transaction
   * Presigns are needed before signing messages
   */
  private async executePresignTransaction(dWalletId: string): Promise<{
    presignId: string;
  }> {
    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    tx.setGasBudget(1 * 10 ** 9);

    const latestNetworkEncryptionKey =
      await this.ikaClient.getLatestNetworkEncryptionKey();
    const latestNetworkEncryptionKeyId = latestNetworkEncryptionKey.id;

    const random32Bytes = new Uint8Array(32);
    crypto.getRandomValues(random32Bytes);

    // Request a global presign for the dWallet
    const presign = coordinatorTransactions.requestGlobalPresign(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      latestNetworkEncryptionKeyId,
      0,
      0,
      // random 32 bytes and register session identifier
      coordinatorTransactions.registerSessionIdentifier(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        random32Bytes,
        tx
      ),
      tx.object(config.ika.coinId),
      tx.gas,
      tx
    );

    // Transfer presign to admin
    tx.transferObjects([presign], adminAddress);

    const result = await this.executor.executeTransaction(tx);

    // Parse presign ID from events (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Presign transaction confirmation"
    );

    let presignId: string | null = null;
    for (const event of txResult.events || []) {
      if (event.type.includes("PresignRequestEvent")) {
        try {
          const parsedData = SessionsManagerModule.DWalletSessionEvent(
            CoordinatorInnerModule.PresignRequestEvent
          ).fromBase64(event.bcs);
          presignId = parsedData.event_data.presign_id;
        } catch (err) {
          logger.warn(
            { event: event.type, err },
            "Failed to parse presign event"
          );
        }
      }
    }

    if (!presignId) {
      throw new Error("Failed to get presign ID from transaction");
    }

    return { presignId };
  }

  /**
   * Execute sign transaction (non-custodial)
   * Uses userSignMessage computed by the client via createUserSignMessageWithPublicOutput
   * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet#signing-a-message
   *
   * After signing, optionally broadcasts to Base Sepolia testnet
   */
  private async executeSignTransaction(data: SignRequestInput): Promise<{
    signatureHex: string;
    signId: string;
    digest: string;
    ethTxHash?: string;
    ethBlockNumber?: number;
  }> {
    // Verify presign exists (with timeout to prevent indefinite wait)
    const presign = await withTimeout(
      this.ikaClient.getPresignInParticularState(data.presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    if (!presign) {
      throw new Error(`Presign ${data.presignId} not found or not completed`);
    }

    logger.info(
      {
        messageHex: data.messageHex.slice(0, 20) + "...",
        userSignMessageLength: data.userSignMessage.length,
        userOutputSignatureLength: data.userOutputSignature.length,
        encryptedUserSecretKeyShareId: data.encryptedUserSecretKeyShareId,
        presignId: data.presignId,
        dWalletId: data.dWalletId,
        dWalletCapId: data.dWalletCapId,
        ethTx: data.ethTx,
      },
      "Processing sign request"
    );

    const tx = new Transaction();
    const ikaTx = new IkaTransaction({
      ikaClient: this.ikaClient,
      transaction: tx,
    });
    tx.setSender(this.adminKeypair.toSuiAddress());
    tx.setGasBudget(1 * 10 ** 9);

    const random32Bytes = new Uint8Array(32);
    crypto.getRandomValues(random32Bytes);

    coordinatorTransactions.acceptEncryptedUserShare(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      data.dWalletId,
      data.encryptedUserSecretKeyShareId,
      new Uint8Array(data.userOutputSignature),
      tx
    );

    const verifiedPresignCap = ikaTx.verifyPresignCap({
      presign,
    });

    const verifiedMessageApproval = ikaTx.approveMessage({
      curve: Curve.SECP256K1,
      hashScheme: Hash.KECCAK256,
      signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
      dWalletCap: data.dWalletCapId,
      message: new Uint8Array(
        Buffer.from(data.messageHex.replace(/^0x/, ""), "hex")
      ),
    });

    coordinatorTransactions.requestSign(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      verifiedPresignCap,
      verifiedMessageApproval,
      new Uint8Array(data.userSignMessage),
      ikaTx.createSessionIdentifier(),
      tx.object(config.ika.coinId),
      tx.gas,
      tx
    );

    const result = await this.executor.executeTransaction(tx);

    // Wait for sign transaction confirmation (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Sign transaction confirmation"
    );

    let signId: string | null = null;
    for (const event of txResult.events || []) {
      if (event.type.includes("SignRequestEvent")) {
        try {
          const parsedData = SessionsManagerModule.DWalletSessionEvent(
            CoordinatorInnerModule.SignRequestEvent
          ).fromBase64(event.bcs);
          signId = parsedData.event_data.sign_id;
        } catch (err) {
          logger.warn({ event: event.type, err }, "Failed to parse sign event");
        }
      }
    }

    if (!signId) {
      throw new Error("Failed to get sign ID from transaction");
    }

    // Wait for network to complete the signature (with timeout to prevent indefinite wait)
    const signResult = await withTimeout(
      this.ikaClient.getSignInParticularState(
        signId,
        Curve.SECP256K1,
        SignatureAlgorithm.ECDSASecp256k1,
        "Completed"
      ),
      TIMEOUTS.SIGN_WAIT,
      "Signature from Ika network"
    );

    const signatureBytes = signResult.state.Completed.signature;
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    logger.info(
      { signId, signatureLength: signatureBytes.length },
      "Got signature from Ika network"
    );

    // If Ethereum transaction details provided, broadcast to Base Sepolia
    let ethTxHash: string | undefined;
    let ethBlockNumber: number | undefined;

    if (data.ethTx) {
      try {
        const broadcastResult = await this.broadcastToEthereum(
          data.ethTx,
          new Uint8Array(signatureBytes)
        );
        ethTxHash = broadcastResult.txHash;
        ethBlockNumber = broadcastResult.blockNumber;

        logger.info(
          { ethTxHash, ethBlockNumber },
          "Ethereum transaction broadcast successful"
        );
      } catch (err) {
        logger.error({ err }, "Failed to broadcast to Ethereum");
        // Don't fail the whole request, just log the error
      }
    }

    return {
      signatureHex,
      signId,
      digest: result.digest,
      ethTxHash,
      ethBlockNumber,
    };
  }

  /**
   * Broadcast a signed transaction to Base Sepolia testnet
   */
  private async broadcastToEthereum(
    ethTx: NonNullable<SignRequestInput["ethTx"]>,
    signatureBytes: Uint8Array
  ): Promise<{ txHash: string; blockNumber: number }> {
    // Use the EXACT values from ethTx that were signed by the frontend
    // Do NOT fetch fresh nonce/gas - the signature was computed over these specific values
    logger.info(
      {
        from: ethTx.from,
        nonce: ethTx.nonce,
        maxFeePerGas: ethTx.maxFeePerGas,
        maxPriorityFeePerGas: ethTx.maxPriorityFeePerGas,
      },
      "Using signed transaction values for broadcast"
    );

    // Parse signature (r, s from ECDSA signature)
    // Format: r[32-byte]-s[32-byte] (no v/recovery ID from Ika)
    const r = `0x${Buffer.from(signatureBytes.slice(0, 32)).toString(
      "hex"
    )}` as Hex;
    const s = `0x${Buffer.from(signatureBytes.slice(32, 64)).toString(
      "hex"
    )}` as Hex;

    // Create the transaction object with the EXACT values that were signed
    const unsignedTx: TransactionSerializableEIP1559 = {
      type: "eip1559",
      chainId: ethTx.chainId,
      nonce: ethTx.nonce,
      to: ethTx.to as Hex,
      value: BigInt(ethTx.value),
      maxFeePerGas: BigInt(ethTx.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(ethTx.maxPriorityFeePerGas),
      gas: BigInt(ethTx.gasLimit),
    };

    // No recovery ID (v) from Ika - try both yParity values (0 and 1)
    // and use the one that recovers to the correct address
    let signedTx: Hex | null = null;
    for (const yParity of [0, 1] as const) {
      const candidateTx = serializeTransaction(unsignedTx, { r, s, yParity });
      try {
        const recoveredAddress = await recoverTransactionAddress({
          serializedTransaction: candidateTx,
        });
        if (recoveredAddress.toLowerCase() === ethTx.from.toLowerCase()) {
          signedTx = candidateTx;
          logger.info({ yParity }, "Found correct yParity for signature");
          break;
        }
      } catch {
        // This yParity didn't work, try the other
        continue;
      }
    }

    if (!signedTx) {
      throw new Error(
        "Failed to recover correct signer address with either yParity value"
      );
    }

    logger.info(
      {
        to: ethTx.to,
        value: ethTx.value,
        chainId: ethTx.chainId,
        nonce: ethTx.nonce,
        signedTxLength: signedTx.length,
      },
      "Broadcasting signed transaction to Base Sepolia"
    );

    // Send the raw transaction
    const txHash = await ethClient.sendRawTransaction({
      serializedTransaction: signedTx,
    });

    // Wait for transaction receipt (with timeout)
    const receipt = await withTimeout(
      ethClient.waitForTransactionReceipt({
        hash: txHash,
        confirmations: 1,
      }),
      TIMEOUTS.ETH_RECEIPT_WAIT,
      "Ethereum transaction receipt"
    );

    return {
      txHash,
      blockNumber: Number(receipt.blockNumber),
    };
  }

  /**
   * Get admin address for display
   */
  getAdminAddress(): string {
    return this.adminKeypair.toSuiAddress();
  }

  /**
   * Get Ethereum transaction parameters (nonce, gas prices) for an address
   * Frontend calls this before signing to get actual values
   */
  async getEthTxParams(address: string): Promise<{
    nonce: number;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    gasLimit: string;
  }> {
    const [nonce, feeData] = await Promise.all([
      ethClient.getTransactionCount({ address: address as Hex }),
      ethClient.estimateFeesPerGas(),
    ]);

    return {
      nonce,
      maxFeePerGas: (feeData.maxFeePerGas || BigInt("50000000000")).toString(),
      maxPriorityFeePerGas: (
        feeData.maxPriorityFeePerGas || BigInt("2000000000")
      ).toString(),
      gasLimit: "21000", // Standard ETH transfer
    };
  }
}

// Export singleton instance
export const dkgExecutor = new DKGExecutorService();
