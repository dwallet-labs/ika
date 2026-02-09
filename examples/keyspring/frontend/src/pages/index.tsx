import { useState, useCallback, useEffect, useRef } from "react";
import {
  toHex,
  parseEther,
  serializeTransaction,
  type TransactionSerializableEIP1559,
} from "viem";
import {
  submitDKG,
  getDKGStatus,
  requestPresign,
  getPresignStatus,
  requestSign,
  getSignStatus,
  getEthTxParams,
  type DKGStatusResponse,
  type PresignStatusResponse,
  type SignStatusResponse,
  type EthTxParams,
} from "@/lib/api";
import {
  DKG_SIGN_MESSAGE,
  getProtocolPublicParameters,
  computeEncryptionKeys,
  prepareDKGLocal,
  createUserSignMessage,
  getIkaClient,
  type DKGStep,
  DKG_STEP_LABELS,
  ETHEREUM_CURVE,
  getCurveValue,
  type WalletType,
} from "@/lib/dkg";
import { UserShareEncryptionKeys } from "@ika.xyz/sdk";
import {
  checkPasskeySupport,
  hasStoredCredential,
  getStoredCredential,
  registerPasskey,
  authenticateWithPasskey,
  prfSecretToSeedString,
  clearStoredCredential,
  updateCredentialEthAddress,
} from "@/lib/passkey";

// Base Sepolia chain ID
const BASE_SEPOLIA_CHAIN_ID = 84532;

// Generic EIP-1193 provider
interface EthereumProvider {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
  on?: (event: string, callback: (...args: unknown[]) => void) => void;
  removeListener?: (
    event: string,
    callback: (...args: unknown[]) => void
  ) => void;
}

// Solana provider
interface SolanaProvider {
  isPhantom?: boolean;
  publicKey?: { toBase58: () => string };
  connect: () => Promise<{ publicKey: { toBase58: () => string } }>;
  disconnect: () => Promise<void>;
  signMessage: (
    message: Uint8Array,
    encoding: string
  ) => Promise<{ signature: Uint8Array }>;
  on?: (event: string, callback: (...args: unknown[]) => void) => void;
  removeListener?: (
    event: string,
    callback: (...args: unknown[]) => void
  ) => void;
}

declare global {
  interface Window {
    ethereum?: EthereumProvider;
    phantom?: {
      ethereum?: EthereumProvider;
      solana?: SolanaProvider;
    };
    solana?: SolanaProvider;
  }
}

// Wallet info for display
interface WalletInfo {
  id: string;
  name: string;
  icon: string;
  type: WalletType;
  getProvider: () => EthereumProvider | SolanaProvider | null;
}

export default function Home() {
  // Wallet state
  const [selectedWallet, setSelectedWallet] = useState<WalletInfo | null>(null);
  const [walletAddress, setWalletAddress] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  const [availableWallets, setAvailableWallets] = useState<WalletInfo[]>([]);

  // DKG flow state
  const [step, setStep] = useState<DKGStep>("idle");
  const [error, setError] = useState<string | null>(null);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [dkgResult, setDkgResult] = useState<DKGStatusResponse | null>(null);

  // Store DKG data locally for signing (never sent to server)
  const userSecretKeyShareRef = useRef<number[] | null>(null);
  const userPublicOutputRef = useRef<number[] | null>(null);
  const signatureRef = useRef<Uint8Array | null>(null);
  const encryptedUserSecretKeyShareIdRef = useRef<string | null>(null);
  const userShareEncryptionKeysRef = useRef<UserShareEncryptionKeys | null>(
    null
  );

  // Presign state
  const [presignRequestId, setPresignRequestId] = useState<string | null>(null);
  const [presignResult, setPresignResult] =
    useState<PresignStatusResponse | null>(null);
  const [isRequestingPresign, setIsRequestingPresign] = useState(false);

  // Sign state
  const [signRequestId, setSignRequestId] = useState<string | null>(null);
  const [signResult, setSignResult] = useState<SignStatusResponse | null>(null);
  const [isSigning, setIsSigning] = useState(false);

  // Transaction form
  const [recipientAddress, setRecipientAddress] = useState("");
  const [ethAmount, setEthAmount] = useState("0.001");

  // View state
  const [showWalletPicker, setShowWalletPicker] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState(false);
  const [showDisclaimer, setShowDisclaimer] = useState(true);

  // Passkey state
  const [passkeySupported, setPasskeySupported] = useState(false);
  const [prfSupported, setPrfSupported] = useState(false);
  const [hasPasskey, setHasPasskey] = useState(false);
  const [isPasskeyLoading, setIsPasskeyLoading] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [isPasskeyMode, setIsPasskeyMode] = useState(false);

  // Detect available wallets
  useEffect(() => {
    const detectWallets = () => {
      const wallets: WalletInfo[] = [];

      // Check for MetaMask or other injected Ethereum wallets
      if (window.ethereum && !(window.ethereum as any).isPhantom) {
        wallets.push({
          id: "metamask",
          name: "MetaMask",
          icon: "🦊",
          type: "ethereum",
          getProvider: () => window.ethereum || null,
        });
      }

      // Check for Phantom Ethereum
      if (window.phantom?.ethereum) {
        wallets.push({
          id: "phantom-eth",
          name: "Phantom (Ethereum)",
          icon: "👻",
          type: "ethereum",
          getProvider: () => window.phantom?.ethereum || null,
        });
      }

      // Check for Phantom Solana
      if (window.phantom?.solana || window.solana?.isPhantom) {
        wallets.push({
          id: "phantom-sol",
          name: "Phantom (Solana)",
          icon: "👻",
          type: "solana",
          getProvider: () => window.phantom?.solana || window.solana || null,
        });
      }

      // Check for other Solana wallets
      if (window.solana && !window.solana.isPhantom) {
        wallets.push({
          id: "solana",
          name: "Solana Wallet",
          icon: "◎",
          type: "solana",
          getProvider: () => window.solana || null,
        });
      }

      setAvailableWallets(wallets);
    };

    detectWallets();
    const timeout = setTimeout(detectWallets, 500);
    return () => clearTimeout(timeout);
  }, []);

  // Detect passkey support
  useEffect(() => {
    const detectPasskey = async () => {
      const support = await checkPasskeySupport();
      setPasskeySupported(support.webauthnSupported);
      setPrfSupported(support.prfSupported);
      setHasPasskey(hasStoredCredential());
    };
    detectPasskey();
  }, []);

  // Update stored passkey credential with ethereum address when wallet is created
  useEffect(() => {
    if (isPasskeyMode && dkgResult?.ethereumAddress) {
      updateCredentialEthAddress(dkgResult.ethereumAddress);
    }
  }, [isPasskeyMode, dkgResult?.ethereumAddress]);

  // Connect wallet
  const connectWallet = useCallback(async (wallet: WalletInfo) => {
    setIsConnecting(true);
    setError(null);
    setSelectedWallet(wallet);

    try {
      if (wallet.type === "ethereum") {
        const provider = wallet.getProvider() as EthereumProvider;
        if (!provider) throw new Error("Wallet not available");

        const accounts = (await provider.request({
          method: "eth_requestAccounts",
        })) as string[];

        if (accounts.length > 0) {
          setWalletAddress(accounts[0]);
          setShowWalletPicker(false);
        }
      } else if (wallet.type === "solana") {
        const provider = wallet.getProvider() as SolanaProvider;
        if (!provider) throw new Error("Wallet not available");

        const response = await provider.connect();
        setWalletAddress(response.publicKey.toBase58());
        setShowWalletPicker(false);
      }
    } catch (err) {
      console.error("Failed to connect:", err);
      setError("Could not connect wallet. Please try again.");
      setSelectedWallet(null);
    } finally {
      setIsConnecting(false);
    }
  }, []);

  // Disconnect wallet
  const disconnectWallet = useCallback(async () => {
    if (selectedWallet?.type === "solana") {
      const provider = selectedWallet.getProvider() as SolanaProvider;
      await provider?.disconnect?.();
    }
    setWalletAddress(null);
    setSelectedWallet(null);
    setIsPasskeyMode(false);
    setPasskeyError(null);
    reset();
  }, [selectedWallet]);

  // Connect with passkey
  const connectWithPasskey = useCallback(
    async (isNewRegistration: boolean) => {
      setIsPasskeyLoading(true);
      setPasskeyError(null);
      setError(null);

      try {
        if (isNewRegistration) {
          // Register new passkey
          const regResult = await registerPasskey();
          if (!regResult.success) {
            setPasskeyError(regResult.error || "Failed to create passkey");
            setIsPasskeyLoading(false);
            return;
          }
          if (!regResult.prfEnabled) {
            setPasskeyError(
              "Your device does not support the required PRF extension. Please try a different browser or device."
            );
            setIsPasskeyLoading(false);
            return;
          }
          setHasPasskey(true);
        }

        // Authenticate and get PRF secret
        const authResult = await authenticateWithPasskey();
        if (!authResult.success || !authResult.prfSecret) {
          setPasskeyError(authResult.error || "Authentication failed");
          setIsPasskeyLoading(false);
          return;
        }

        // Convert PRF secret to seed string (same format as wallet signature)
        const seedString = prfSecretToSeedString(authResult.prfSecret);

        // Set passkey mode
        setIsPasskeyMode(true);
        setWalletAddress("passkey-user");
        setSelectedWallet({
          id: "passkey",
          name: "Passkey",
          icon: "🔐",
          type: "ethereum" as WalletType,
          getProvider: () => null,
        });

        // Store seed in ref for DKG execution (convert hex to bytes)
        signatureRef.current = new Uint8Array(
          Buffer.from(seedString.replace(/^0x/, ""), "hex")
        );
      } catch (err) {
        console.error("Passkey error:", err);
        setPasskeyError(
          err instanceof Error ? err.message : "Passkey authentication failed"
        );
      } finally {
        setIsPasskeyLoading(false);
      }
    },
    []
  );

  // Poll for DKG status
  useEffect(() => {
    if (!requestId || step !== "waiting") return;

    const pollInterval = setInterval(async () => {
      try {
        const status = await getDKGStatus(requestId);
        if (status.status === "completed") {
          setDkgResult(status);
          setStep("completed");
          clearInterval(pollInterval);
        } else if (status.status === "failed") {
          setError(status.error || "Something went wrong");
          setStep("failed");
          clearInterval(pollInterval);
        }
        if (status.encryptedUserSecretKeyShareId) {
          encryptedUserSecretKeyShareIdRef.current =
            status.encryptedUserSecretKeyShareId;
        }
      } catch (err) {
        console.error("Error polling status:", err);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [requestId, step]);

  // Poll for presign status
  useEffect(() => {
    if (!presignRequestId || presignResult?.status === "completed") return;

    const pollInterval = setInterval(async () => {
      try {
        const status = await getPresignStatus(presignRequestId);
        setPresignResult(status);
        if (status.status === "completed" || status.status === "failed") {
          clearInterval(pollInterval);
          setIsRequestingPresign(false);
        }
      } catch (err) {
        console.error("Error polling presign status:", err);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [presignRequestId, presignResult?.status]);

  // Poll for sign status
  useEffect(() => {
    if (!signRequestId || signResult?.status === "completed") return;

    const pollInterval = setInterval(async () => {
      try {
        const status = await getSignStatus(signRequestId);
        setSignResult(status);
        if (status.status === "completed" || status.status === "failed") {
          clearInterval(pollInterval);
          setIsSigning(false);
        }
      } catch (err) {
        console.error("Error polling sign status:", err);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [signRequestId, signResult?.status]);

  // Sign message with wallet
  const signWithWallet = async (message: string): Promise<string> => {
    if (!selectedWallet) throw new Error("No wallet selected");

    if (selectedWallet.type === "ethereum") {
      const provider = selectedWallet.getProvider() as EthereumProvider;
      const hexMessage = toHex(new TextEncoder().encode(message));
      return (await provider.request({
        method: "personal_sign",
        params: [hexMessage, walletAddress],
      })) as string;
    } else {
      const provider = selectedWallet.getProvider() as SolanaProvider;
      const messageBytes = new TextEncoder().encode(message);
      const response = await provider.signMessage(messageBytes, "utf8");
      // Convert Solana signature to hex string
      return "0x" + Buffer.from(response.signature).toString("hex");
    }
  };

  // Execute DKG flow
  const executeDKG = useCallback(async () => {
    // For passkey mode, we already have the seed in signatureRef
    if (isPasskeyMode) {
      if (!signatureRef.current) {
        setError("Passkey authentication required. Please try again.");
        return;
      }
    } else {
      // Traditional wallet mode
      if (!selectedWallet || !walletAddress) {
        setError("Please connect your wallet first");
        return;
      }
    }

    setError(null);

    try {
      let seedString: string;

      if (isPasskeyMode) {
        // Passkey mode: use the PRF-derived seed already stored
        setStep("computing_keys");
        seedString = prfSecretToSeedString(signatureRef.current!);
      } else {
        // Traditional wallet mode: sign message for key derivation
        setStep("signing");
        const signature = await signWithWallet(DKG_SIGN_MESSAGE);
        seedString = signature;

        // Convert signature to bytes
        const sigBytes = new Uint8Array(
          Buffer.from(signature.replace(/^0x/, ""), "hex")
        );
        signatureRef.current = sigBytes;
      }

      // Fetch protocol parameters
      setStep("fetching_params");
      const protocolPublicParameters = await getProtocolPublicParameters(
        ETHEREUM_CURVE
      );

      // Compute encryption keys
      setStep("computing_keys");
      const encryptionKeys = await computeEncryptionKeys(
        seedString,
        ETHEREUM_CURVE
      );
      userShareEncryptionKeysRef.current = encryptionKeys;

      // Generate session identifier
      const sessionIdentifier = new Uint8Array(32);
      crypto.getRandomValues(sessionIdentifier);

      // Prepare DKG locally
      setStep("preparing_dkg");
      const dkgResult = await prepareDKGLocal({
        curve: ETHEREUM_CURVE,
        encryptionKeys,
        sessionIdentifier,
        protocolPublicParameters,
      });

      // Store locally for signing (NEVER sent to server)
      userSecretKeyShareRef.current = dkgResult.userSecretKeyShare;
      userPublicOutputRef.current = dkgResult.userPublicOutput;

      // Submit to backend
      setStep("submitting");
      const response = await submitDKG({
        userPublicOutput: dkgResult.userPublicOutput,
        userDkgMessage: dkgResult.userDKGMessage,
        encryptedUserShareAndProof: dkgResult.encryptedUserShareAndProof,
        sessionIdentifier: Array.from(sessionIdentifier),
        signerPublicKey: Array.from(encryptionKeys.getPublicKey().toRawBytes()),
        encryptionKeyAddress: encryptionKeys.getSuiAddress(),
        encryptionKey: Array.from(encryptionKeys.encryptionKey),
        encryptionKeySignature: Array.from(
          await encryptionKeys.getEncryptionKeySignature()
        ),
        curve: getCurveValue(ETHEREUM_CURVE),
      });

      setRequestId(response.requestId);
      setStep("waiting");
    } catch (err) {
      console.error("DKG error:", err);
      setError(err instanceof Error ? err.message : "Something went wrong");
      setStep("failed");
    }
  }, [isPasskeyMode, selectedWallet, walletAddress]);

  // Request presign
  const handleRequestPresign = useCallback(async () => {
    if (!dkgResult?.dWalletObjectId) return;

    setIsRequestingPresign(true);
    setPresignResult(null);

    try {
      const response = await requestPresign(dkgResult.dWalletObjectId);
      setPresignRequestId(response.requestId);
    } catch (err) {
      console.error("Presign error:", err);
      setIsRequestingPresign(false);
      setError("Could not prepare for signing. Please try again.");
    }
  }, [dkgResult?.dWalletObjectId]);

  // Build and sign transaction
  const handleSignAndBroadcast = useCallback(async () => {
    if (
      !dkgResult?.dWalletObjectId ||
      !dkgResult?.dWalletCapObjectId ||
      !dkgResult?.ethereumAddress ||
      !presignResult?.presignId ||
      !userSecretKeyShareRef.current ||
      !userPublicOutputRef.current
    ) {
      setError("Missing data. Please start over.");
      return;
    }

    if (!recipientAddress || !recipientAddress.startsWith("0x")) {
      setError("Please enter a valid address starting with 0x");
      return;
    }

    if (!ethAmount || parseFloat(ethAmount) <= 0) {
      setError("Please enter a valid amount");
      return;
    }

    setIsSigning(true);
    setSignResult(null);
    setError(null);

    try {
      const valueWei = parseEther(ethAmount);

      // Get transaction parameters
      const txParams = await getEthTxParams(dkgResult.ethereumAddress);
      if (!txParams.success) {
        throw new Error(txParams.error || "Could not get transaction info");
      }

      // Build transaction
      const ethTx: EthTxParams = {
        from: dkgResult.ethereumAddress,
        to: recipientAddress,
        value: toHex(valueWei),
        nonce: txParams.nonce,
        gasLimit: toHex(BigInt(txParams.gasLimit)),
        maxFeePerGas: toHex(BigInt(txParams.maxFeePerGas)),
        maxPriorityFeePerGas: toHex(BigInt(txParams.maxPriorityFeePerGas)),
        chainId: BASE_SEPOLIA_CHAIN_ID,
      };

      const unsignedTx: TransactionSerializableEIP1559 = {
        type: "eip1559",
        chainId: ethTx.chainId,
        nonce: ethTx.nonce,
        to: ethTx.to as `0x${string}`,
        value: valueWei,
        maxFeePerGas: BigInt(txParams.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(txParams.maxPriorityFeePerGas),
        gas: BigInt(txParams.gasLimit),
      };

      const serializedUnsigned = serializeTransaction(unsignedTx);
      const protocolPublicParameters = await getProtocolPublicParameters(
        ETHEREUM_CURVE
      );

      // Get presign data
      const ikaClient = getIkaClient();
      const presign = await ikaClient.getPresignInParticularState(
        presignResult.presignId,
        "Completed"
      );

      if (!presign) {
        throw new Error("Presign not ready yet. Please wait and try again.");
      }

      // Create user sign message locally
      const messageBytes = new Uint8Array(
        Buffer.from(serializedUnsigned.replace(/^0x/, ""), "hex")
      );
      const presignOutput = presign.state.Completed.presign;

      const dWallet = await ikaClient.getDWallet(dkgResult.dWalletObjectId);

      const publicOutput = new Uint8Array(
        dWallet.state.Active?.public_output ??
          dWallet.state.AwaitingKeyHolderSignature?.public_output ??
          []
      );

      const userSignMsg = await createUserSignMessage({
        protocolPublicParameters,
        publicOutput,
        secretShare: new Uint8Array(userSecretKeyShareRef.current),
        presignBytes: new Uint8Array(presignOutput),
        message: messageBytes,
      });

      // Submit to backend
      const response = await requestSign({
        dWalletId: dkgResult.dWalletObjectId,
        dWalletCapId: dkgResult.dWalletCapObjectId,
        presignId: presignResult.presignId,
        messageHex: Buffer.from(messageBytes).toString("hex"),
        userSignMessage: Array.from(userSignMsg),
        ethTx,
        encryptedUserSecretKeyShareId:
          dkgResult.encryptedUserSecretKeyShareId || "",
        userOutputSignature: Array.from(
          (await userShareEncryptionKeysRef.current?.getUserOutputSignature(
            dWallet,
            new Uint8Array(
              userPublicOutputRef.current
                ? [...userPublicOutputRef.current]
                : []
            )
          )) || []
        ),
      });

      setSignRequestId(response.requestId);
    } catch (err) {
      console.error("Sign error:", err);
      setError(err instanceof Error ? err.message : "Transaction failed");
      setIsSigning(false);
    }
  }, [dkgResult, presignResult, recipientAddress, ethAmount]);

  // Reset flow
  const reset = useCallback(() => {
    setStep("idle");
    setError(null);
    setRequestId(null);
    setDkgResult(null);
    setPresignRequestId(null);
    setPresignResult(null);
    setIsRequestingPresign(false);
    setSignRequestId(null);
    setSignResult(null);
    setIsSigning(false);
    setRecipientAddress("");
    setEthAmount("0.001");
    setPasskeyError(null);
    userSecretKeyShareRef.current = null;
    userPublicOutputRef.current = null;
    signatureRef.current = null;
  }, []);

  // Copy address
  const copyAddress = (address: string) => {
    navigator.clipboard.writeText(address);
    setCopiedAddress(true);
    setTimeout(() => setCopiedAddress(false), 2000);
  };

  // Step progress
  const steps: DKGStep[] = [
    "signing",
    "fetching_params",
    "computing_keys",
    "preparing_dkg",
    "submitting",
    "waiting",
  ];
  const currentStepIndex = steps.indexOf(step);
  const isConnected = !!walletAddress;

  return (
    <div className="min-h-screen">
      <div className="bg-pattern" />
      <div className="bg-grid" />

      {/* Disclaimer Modal */}
      {showDisclaimer && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            onClick={() => {}}
          />
          <div className="relative bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-2xl p-8 max-w-md w-full shadow-2xl fade-in">
            {/* Warning Icon */}
            <div className="flex justify-center mb-6">
              <div className="w-16 h-16 rounded-full bg-[rgba(234,179,8,0.15)] flex items-center justify-center">
                <span className="text-4xl">⚠️</span>
              </div>
            </div>

            {/* Title */}
            <h2 className="text-2xl font-bold text-center mb-2">
              Testnet Demo Only
            </h2>
            <p className="text-center text-[var(--warning)] font-medium mb-6">
              Developer Warning
            </p>

            {/* Content */}
            <div className="space-y-4 text-sm text-[var(--text-secondary)] mb-8">
              <p>
                This cross-chain wallet demo is provided for{" "}
                <strong className="text-[var(--text-primary)]">
                  developer testing and educational purposes only
                </strong>{" "}
                and must be used on{" "}
                <strong className="text-[var(--text-primary)]">
                  Base Sepolia testnet only
                </strong>
                .
              </p>
              <p>
                It has not been audited and may contain bugs or unexpected
                behavior.{" "}
                <strong className="text-[var(--error)]">
                  Do not use with real funds or production wallets.
                </strong>
              </p>
              <p>Use only test keys and disposable testnet amounts.</p>
            </div>

            {/* Risk acknowledgment */}
            <div className="p-4 rounded-lg bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.2)] mb-6">
              <p className="text-sm text-center text-[var(--error)] font-medium">
                You assume all risk by proceeding.
              </p>
            </div>

            {/* Button */}
            <button
              onClick={() => setShowDisclaimer(false)}
              className="btn-primary w-full"
            >
              I Understand, Continue
            </button>

            {/* Powered by */}
            <p className="text-center text-xs text-[var(--text-muted)] mt-4">
              Powered by{" "}
              <a
                href="https://ika.xyz"
                target="_blank"
                rel="noopener noreferrer"
                className="link"
              >
                Ika
              </a>
            </p>
          </div>
        </div>
      )}

      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen p-6">
        {/* Header */}
        <div className="text-center mb-10 fade-in">
          <div className="inline-flex items-center gap-2 mb-4 px-4 py-2 rounded-full bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-xl">🦑</span>
            <span className="text-sm font-medium text-[var(--text-secondary)]">
              Powered by Ika
            </span>
          </div>

          <h1 className="text-4xl sm:text-5xl font-bold mb-4 tracking-tight">
            <span className="gradient-text">KeySpring</span>
          </h1>

          <p className="text-[var(--text-secondary)] max-w-lg mx-auto text-lg">
            Create a new Ethereum wallet using your existing wallet or passkey.
            <br />
            Send ETH on Base — your keys, your control.
          </p>
        </div>

        {/* Main Card */}
        <div className="glass-card p-8 w-full max-w-lg fade-in">
          {/* Wallet Connection Section */}
          {!isConnected ? (
            <div>
              <h2 className="text-xl font-semibold mb-6 text-center">
                Connect Your Wallet
              </h2>

              {availableWallets.length === 0 && !passkeySupported ? (
                <div className="text-center py-8">
                  <div className="text-5xl mb-4">🔌</div>
                  <p className="text-[var(--text-secondary)] mb-4">
                    No wallet found
                  </p>
                  <a
                    href="https://phantom.app/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-primary inline-block"
                  >
                    Get Phantom Wallet
                  </a>
                </div>
              ) : (
                <>
                  {/* Wallet list */}
                  {availableWallets.length > 0 && (
                    <div className="wallet-list">
                      {availableWallets.map((wallet) => (
                        <button
                          key={wallet.id}
                          onClick={() => connectWallet(wallet)}
                          disabled={isConnecting}
                          className="wallet-btn"
                        >
                          <div
                            className="wallet-btn-icon"
                            style={{
                              background:
                                wallet.type === "solana"
                                  ? "linear-gradient(135deg, #9945FF 0%, #14F195 100%)"
                                  : "linear-gradient(135deg, #F6851B 0%, #E2761B 100%)",
                            }}
                          >
                            {wallet.icon}
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">{wallet.name}</div>
                            <div className="text-sm text-[var(--text-muted)]">
                              {wallet.type === "solana"
                                ? "Solana wallet"
                                : "Ethereum wallet"}
                            </div>
                          </div>
                          <svg
                            className="w-5 h-5 text-[var(--text-muted)]"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M9 5l7 7-7 7"
                            />
                          </svg>
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Passkey Option */}
                  {passkeySupported && prfSupported && (
                    <div className={availableWallets.length > 0 ? "mt-6" : ""}>
                      {availableWallets.length > 0 && (
                        <>
                          <div className="flex items-center gap-4 my-4">
                            <div className="flex-1 h-px bg-[var(--border-subtle)]" />
                            <span className="text-sm text-[var(--text-muted)]">
                              or use a passkey
                            </span>
                            <div className="flex-1 h-px bg-[var(--border-subtle)]" />
                          </div>
                        </>
                      )}

                      {hasPasskey ? (
                        <button
                          onClick={() => connectWithPasskey(false)}
                          disabled={isPasskeyLoading}
                          className="wallet-btn w-full"
                        >
                          <div
                            className="wallet-btn-icon"
                            style={{
                              background:
                                "linear-gradient(135deg, #00d4aa 0%, #8b5cf6 100%)",
                            }}
                          >
                            🔐
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">
                              Continue with Passkey
                            </div>
                            <div className="text-sm text-[var(--text-muted)]">
                              Use your saved passkey
                            </div>
                          </div>
                          {isPasskeyLoading ? (
                            <div className="w-5 h-5 border-2 border-[var(--text-muted)] border-t-transparent rounded-full animate-spin" />
                          ) : (
                            <svg
                              className="w-5 h-5 text-[var(--text-muted)]"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M9 5l7 7-7 7"
                              />
                            </svg>
                          )}
                        </button>
                      ) : (
                        <button
                          onClick={() => connectWithPasskey(true)}
                          disabled={isPasskeyLoading}
                          className="wallet-btn w-full"
                        >
                          <div
                            className="wallet-btn-icon"
                            style={{
                              background:
                                "linear-gradient(135deg, #00d4aa 0%, #8b5cf6 100%)",
                            }}
                          >
                            🔐
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">
                              Create Passkey Wallet
                            </div>
                            <div className="text-sm text-[var(--text-muted)]">
                              Passwordless, secure, biometric
                            </div>
                          </div>
                          {isPasskeyLoading ? (
                            <div className="w-5 h-5 border-2 border-[var(--text-muted)] border-t-transparent rounded-full animate-spin" />
                          ) : (
                            <svg
                              className="w-5 h-5 text-[var(--text-muted)]"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M9 5l7 7-7 7"
                              />
                            </svg>
                          )}
                        </button>
                      )}

                      {passkeyError && (
                        <p className="text-[var(--error)] text-sm mt-3 text-center">
                          {passkeyError}
                        </p>
                      )}
                    </div>
                  )}

                  {/* PRF not supported warning */}
                  {passkeySupported && !prfSupported && (
                    <div className="mt-4 p-3 rounded-lg bg-[rgba(234,179,8,0.1)] border border-[rgba(234,179,8,0.2)]">
                      <p className="text-[var(--warning)] text-xs text-center">
                        Passkeys available but PRF extension not supported on
                        this device
                      </p>
                    </div>
                  )}
                </>
              )}
            </div>
          ) : step === "idle" ? (
            /* Ready to Create Wallet */
            <div className="text-center">
              <div className="address-display justify-center mb-6">
                <span
                  className="dot"
                  style={
                    isPasskeyMode
                      ? {
                          background:
                            "linear-gradient(135deg, #00d4aa 0%, #8b5cf6 100%)",
                        }
                      : undefined
                  }
                />
                <span>
                  {isPasskeyMode ? (
                    <>🔐 Passkey Connected</>
                  ) : (
                    <>
                      {walletAddress?.slice(0, 6)}...{walletAddress?.slice(-4)}
                    </>
                  )}
                </span>
                <button
                  onClick={disconnectWallet}
                  className="ml-2 text-[var(--text-muted)] hover:text-[var(--error)] transition"
                  title="Disconnect"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                    />
                  </svg>
                </button>
              </div>

              <div className="mb-8">
                <h2 className="text-2xl font-semibold mb-3">
                  Create Your Wallet
                </h2>
                <p className="text-[var(--text-secondary)]">
                  {isPasskeyMode
                    ? "Your passkey will secure a new Ethereum address. Your private key stays with you."
                    : "Sign a message to create a new Ethereum address. Your private key stays with you."}
                </p>
              </div>

              <button
                onClick={executeDKG}
                className="btn-primary w-full text-lg py-4"
              >
                Create Wallet
              </button>

              <div className="mt-6 flex items-center justify-center gap-2 text-sm text-[var(--text-muted)]">
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                  />
                </svg>
                Secured by Ika distributed key generation
              </div>
            </div>
          ) : step === "completed" && dkgResult ? (
            /* Wallet Created - Show Actions */
            <div>
              {/* Success Header */}
              <div className="text-center mb-6">
                <div className="success-ring mx-auto mb-4">
                  <svg
                    className="w-10 h-10 text-[var(--success)]"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      className="checkmark"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>
                <h2 className="text-2xl font-semibold text-[var(--success)] mb-2">
                  Wallet Created!
                </h2>
              </div>

              {/* Your New Address */}
              {dkgResult.ethereumAddress && (
                <div className="success-box mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-[var(--success)]">
                      Your New Address
                    </span>
                    <div className="network-badge">
                      <span
                        className="chain-dot"
                        style={{ background: "#3b82f6" }}
                      />
                      Base Sepolia
                    </div>
                  </div>
                  <div className="flex items-center gap-2 mt-2">
                    <code className="flex-1 text-sm font-mono break-all">
                      {dkgResult.ethereumAddress.slice(0, 6)}...
                      {dkgResult.ethereumAddress.slice(-4)}
                    </code>
                    <button
                      onClick={() => copyAddress(dkgResult.ethereumAddress!)}
                      className="copy-btn flex items-center gap-1"
                    >
                      {copiedAddress ? (
                        <>
                          <svg
                            className="w-3 h-3"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M5 13l4 4L19 7"
                            />
                          </svg>
                          Copied
                        </>
                      ) : (
                        <>
                          <svg
                            className="w-3 h-3"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                            />
                          </svg>
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                  <a
                    href={`https://sepolia.basescan.org/address/${dkgResult.ethereumAddress}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="link text-sm mt-3 inline-flex items-center gap-1"
                  >
                    View on Basescan
                    <svg
                      className="w-3 h-3"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                      />
                    </svg>
                  </a>
                </div>
              )}

              {/* Fund Notice */}
              {!presignResult?.presignId && (
                <div className="warning-box mb-6">
                  <div className="flex items-start gap-3">
                    <span className="text-xl">💡</span>
                    <div>
                      <p className="font-medium text-[var(--warning)]">
                        Add funds first
                      </p>
                      <p className="text-sm text-[var(--text-secondary)] mt-1">
                        Send some Base Sepolia ETH to your new address to make
                        transactions.{" "}
                        <a
                          href="https://www.alchemy.com/faucets/base-sepolia"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="link"
                        >
                          Get free testnet ETH →
                        </a>
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Passkey Recovery Warning */}
              {isPasskeyMode && (
                <div className="mb-6 p-4 rounded-lg bg-[rgba(139,92,246,0.1)] border border-[rgba(139,92,246,0.2)]">
                  <div className="flex items-start gap-3">
                    <span className="text-xl">🔐</span>
                    <div>
                      <p className="font-medium text-[#a78bfa]">
                        Passkey-Controlled Wallet
                      </p>
                      <p className="text-sm text-[var(--text-secondary)] mt-1">
                        This wallet is secured by your passkey. If you delete
                        your passkey from your device, you will lose access to
                        this wallet permanently.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <div className="divider" />

              {/* Step 1: Prepare to Sign */}
              <div className="mb-6">
                <div className="section-title flex items-center gap-2">
                  <span
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                      presignResult?.presignId
                        ? "bg-[var(--success)]"
                        : "bg-[var(--accent-primary)]"
                    } text-[var(--bg-primary)]`}
                  >
                    {presignResult?.presignId ? "✓" : "1"}
                  </span>
                  Prepare to Sign
                </div>

                {!presignResult?.presignId ? (
                  <button
                    onClick={handleRequestPresign}
                    disabled={isRequestingPresign}
                    className="btn-secondary w-full"
                  >
                    {isRequestingPresign ? (
                      <span className="flex items-center justify-center gap-2">
                        <div className="w-4 h-4 border-2 border-[var(--text-muted)] border-t-[var(--text-primary)] rounded-full animate-spin" />
                        Preparing...
                      </span>
                    ) : (
                      "Get Ready to Sign"
                    )}
                  </button>
                ) : (
                  <div className="badge badge-success">
                    <svg
                      className="w-3 h-3"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                    Ready to sign transactions
                  </div>
                )}

                {presignResult?.status === "failed" && (
                  <p className="text-[var(--error)] text-sm mt-2">
                    {presignResult.error || "Something went wrong"}
                  </p>
                )}
              </div>

              {/* Step 2: Send ETH */}
              {presignResult?.status === "completed" && (
                <div className="fade-in">
                  <div className="section-title flex items-center gap-2">
                    <span
                      className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        signResult?.status === "completed"
                          ? "bg-[var(--success)]"
                          : "bg-[var(--accent-primary)]"
                      } text-[var(--bg-primary)]`}
                    >
                      {signResult?.status === "completed" ? "✓" : "2"}
                    </span>
                    Send ETH
                  </div>

                  {!signResult?.status ? (
                    <>
                      <div className="space-y-4 mb-4">
                        <div>
                          <label className="block text-sm text-[var(--text-secondary)] mb-2">
                            To Address
                          </label>
                          <input
                            type="text"
                            value={recipientAddress}
                            onChange={(e) =>
                              setRecipientAddress(e.target.value)
                            }
                            className="input-field font-mono"
                            placeholder="0x..."
                          />
                        </div>

                        <div>
                          <label className="block text-sm text-[var(--text-secondary)] mb-2">
                            Amount
                          </label>
                          <div className="amount-wrapper">
                            <input
                              type="number"
                              step="0.001"
                              min="0"
                              value={ethAmount}
                              onChange={(e) => setEthAmount(e.target.value)}
                              className="input-field font-mono pr-16"
                              placeholder="0.001"
                            />
                            <span className="currency">ETH</span>
                          </div>
                        </div>
                      </div>

                      {error && (
                        <div className="p-3 bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.2)] rounded-lg text-[var(--error)] text-sm mb-4">
                          {error}
                        </div>
                      )}

                      <button
                        onClick={handleSignAndBroadcast}
                        disabled={isSigning}
                        className="btn-primary w-full"
                      >
                        {isSigning ? (
                          <span className="flex items-center justify-center gap-2">
                            <div className="w-4 h-4 border-2 border-[var(--bg-primary)] border-t-transparent rounded-full animate-spin" />
                            Sending...
                          </span>
                        ) : (
                          "Send ETH"
                        )}
                      </button>
                    </>
                  ) : signResult?.status === "processing" ? (
                    <div className="info-box flex items-center gap-3">
                      <div className="w-5 h-5 border-2 border-[var(--accent-blue)] border-t-transparent rounded-full animate-spin" />
                      <span className="text-[var(--accent-blue)]">
                        Sending your transaction...
                      </span>
                    </div>
                  ) : signResult?.status === "completed" ? (
                    <div className="success-box">
                      <div className="text-center">
                        <div className="text-3xl mb-3">🎉</div>
                        <h3 className="text-lg font-semibold text-[var(--success)] mb-3">
                          Transaction Sent!
                        </h3>

                        {signResult.ethTxHash && (
                          <div className="text-left mt-4">
                            <p className="text-sm text-[var(--text-secondary)] mb-1">
                              Transaction
                            </p>
                            <code className="text-xs font-mono break-all text-[var(--text-primary)]">
                              {signResult.ethTxHash}
                            </code>
                          </div>
                        )}

                        {signResult.ethBlockNumber && (
                          <p className="text-sm text-[var(--text-secondary)] mt-2">
                            Confirmed in block {signResult.ethBlockNumber}
                          </p>
                        )}

                        <a
                          href={`https://sepolia.basescan.org/tx/${signResult.ethTxHash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="btn-primary inline-flex items-center gap-2 mt-4"
                        >
                          View Transaction
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                            />
                          </svg>
                        </a>
                      </div>
                    </div>
                  ) : signResult?.status === "failed" ? (
                    <div className="p-4 bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.2)] rounded-lg">
                      <p className="text-[var(--error)] font-medium mb-1">
                        Transaction Failed
                      </p>
                      <p className="text-sm text-[var(--text-secondary)]">
                        {signResult.error || "Something went wrong"}
                      </p>
                    </div>
                  ) : null}
                </div>
              )}

              <div className="divider" />

              <button onClick={reset} className="btn-secondary w-full">
                Start Over
              </button>
            </div>
          ) : step === "failed" ? (
            /* Error State */
            <div className="text-center py-8">
              <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[rgba(239,68,68,0.1)] flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-[var(--error)]"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-[var(--error)] mb-3">
                Something went wrong
              </h3>
              {error && (
                <p className="text-[var(--text-secondary)] text-sm mb-6 p-3 bg-[rgba(239,68,68,0.05)] rounded-lg">
                  {error}
                </p>
              )}
              <button onClick={reset} className="btn-primary">
                Try Again
              </button>
            </div>
          ) : (
            /* Loading State */
            <div className="text-center py-12">
              <div className="loader mx-auto mb-6" />

              <p className="text-lg font-medium mb-2">
                {DKG_STEP_LABELS[step]}
              </p>

              <div className="step-track justify-center mt-6">
                {steps.map((s, i) => (
                  <div
                    key={s}
                    className={`step-dot ${
                      i < currentStepIndex
                        ? "completed"
                        : i === currentStepIndex
                        ? "active"
                        : ""
                    }`}
                  />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-10 text-center text-[var(--text-muted)] text-sm max-w-md">
          {/* Testnet Warning */}
          <div className="mb-6 p-3 rounded-lg bg-[rgba(234,179,8,0.1)] border border-[rgba(234,179,8,0.2)]">
            <p className="text-[var(--warning)] text-xs font-medium">
              ⚠️ Testnet Demo — For testing purposes only. Do not use with real
              funds.
            </p>
          </div>

          <div className="flex items-center justify-center gap-4 mb-4">
            <div className="feature-tag">
              <svg
                className="w-3 h-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              Non-custodial
            </div>
            <div className="feature-tag">
              <svg
                className="w-3 h-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
                />
              </svg>
              Cross-chain
            </div>
          </div>

          <p className="mb-3">
            <strong className="text-[var(--text-primary)]">KeySpring</strong>{" "}
            uses{" "}
            <a
              href="https://ika.xyz"
              target="_blank"
              rel="noopener noreferrer"
              className="link"
            >
              Ika
            </a>{" "}
            distributed key generation. Your secret key never leaves your
            browser.
          </p>

          <div className="flex items-center justify-center gap-3 text-xs">
            <a
              href="https://docs.ika.xyz"
              target="_blank"
              rel="noopener noreferrer"
              className="link"
            >
              Ika Docs
            </a>
            <span>·</span>
            <a
              href="https://www.alchemy.com/faucets/base-sepolia"
              target="_blank"
              rel="noopener noreferrer"
              className="link"
            >
              Get Test ETH
            </a>
            <span>·</span>
            <a
              href="https://github.com/iamknownasfesal/key-spring"
              target="_blank"
              rel="noopener noreferrer"
              className="link"
            >
              GitHub
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
