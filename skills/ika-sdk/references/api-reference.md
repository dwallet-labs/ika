# API Reference

Complete API for IkaClient, IkaTransaction, cryptography functions, and UserShareEncryptionKeys.

## IkaClient

### Constructor

```typescript
new IkaClient({ suiClient, config, cache?, encryptionKeyOptions? }: IkaClientOptions)
```

### Properties

```typescript
public ikaConfig: IkaConfig               // The Ika network configuration (package IDs, object refs)
public encryptionKeyOptions: EncryptionKeyOptions  // Default encryption key options
```

### Initialization

```typescript
await ikaClient.initialize(): Promise<void>
```

### Query: dWallets

```typescript
// Single dWallet
getDWallet(dwalletID: string): Promise<DWallet>

// dWallet in specific state (polls until reached)
getDWalletInParticularState<S extends DWalletState>(
    dwalletID: string, state: S, options?: PollingOptions
): Promise<DWalletWithState<S>>

// Batch fetch
getMultipleDWallets(dwalletIDs: string[]): Promise<DWallet[]>

// Owned capabilities (paginated)
getOwnedDWalletCaps(address: string, cursor?: string, limit?: number): Promise<{
    dWalletCaps: DWalletCap[];
    cursor: string | null | undefined;
    hasNextPage: boolean;
}>
```

### Query: Presigns

```typescript
getPresign(presignID: string): Promise<Presign>
getPresignInParticularState<S extends PresignState>(
    presignID: string, state: S, options?: PollingOptions
): Promise<PresignWithState<S>>
```

### Query: Signs

```typescript
getSign<C extends Curve>(
    signID: string, curve: C,
    signatureAlgorithm: ValidSignatureAlgorithmForCurve<C>
): Promise<Sign>

getSignInParticularState<S extends SignState>(
    signID: string, curve: Curve,
    signatureAlgorithm: SignatureAlgorithm,
    state: S, options?: PollingOptions
): Promise<SignWithState<S>>
```

Note: `getSign` auto-parses signature when state is `Completed`.

### Query: Encrypted User Secret Key Shares

```typescript
getEncryptedUserSecretKeyShare(id: string): Promise<EncryptedUserSecretKeyShare>
getEncryptedUserSecretKeyShareInParticularState<S extends EncryptedUserSecretKeyShareState>(
    id: string, state: S, options?: PollingOptions
): Promise<EncryptedUserSecretKeyShareWithState<S>>
```

### Query: Partial User Signatures

```typescript
getPartialUserSignature(id: string): Promise<PartialUserSignature>
getPartialUserSignatureInParticularState<S extends PartialUserSignatureState>(
    id: string, state: S, options?: PollingOptions
): Promise<PartialUserSignatureWithState<S>>
```

### Encryption Keys

```typescript
getAllNetworkEncryptionKeys(): Promise<NetworkEncryptionKey[]>
getLatestNetworkEncryptionKey(): Promise<NetworkEncryptionKey>
getNetworkEncryptionKey(encryptionKeyID: string): Promise<NetworkEncryptionKey>
getDWalletNetworkEncryptionKey(dwalletID: string): Promise<NetworkEncryptionKey>
getConfiguredNetworkEncryptionKey(): Promise<NetworkEncryptionKey>
getActiveEncryptionKey(address: string): Promise<EncryptionKey>

// Options management
getEncryptionKeyOptions(): EncryptionKeyOptions
setEncryptionKeyOptions(options: EncryptionKeyOptions): void
setEncryptionKeyID(encryptionKeyID: string): void
```

### Protocol Parameters

```typescript
// Auto-detects encryption key from dWallet or uses configured key
getProtocolPublicParameters(dWallet?: DWallet, curve?: Curve): Promise<Uint8Array>

// Cache checks
getCachedProtocolPublicParameters(encryptionKeyID: string, curve: Curve): Uint8Array | undefined
isProtocolPublicParametersCached(encryptionKeyID: string, curve: Curve): boolean
```

### Cache Management

```typescript
invalidateCache(): void                           // All caches
invalidateObjectCache(): void                     // Coordinator + system objects only
invalidateEncryptionKeyCache(): void              // Encryption keys only
invalidateProtocolPublicParametersCache(          // Protocol params (optional filters)
    encryptionKeyID?: string, curve?: Curve
): void
```

---

## IkaTransaction

### Constructor

```typescript
new IkaTransaction({
    ikaClient: IkaClient,
    transaction: Transaction,            // Sui Transaction
    userShareEncryptionKeys?: UserShareEncryptionKeys,
})
```

### Encryption Key Registration

```typescript
registerEncryptionKey({ curve: Curve }): Promise<IkaTransaction>
```

### DKG (Create dWallet)

```typescript
// Standard DKG (zero-trust)
requestDWalletDKG<S extends SignatureAlgorithm = never>({
    dkgRequestInput: DKGRequestInput,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
    sessionIdentifier: TransactionObjectArgument,
    dwalletNetworkEncryptionKeyId: string,
    curve: Curve,
    signDuringDKGRequest?: {           // optional: sign during DKG
        message: Uint8Array,
        presign: Presign,
        verifiedPresignCap: TransactionObjectArgument,
        hashScheme: ValidHashForSignature<S>,
        signatureAlgorithm: S,
    },
}): Promise<TransactionResult>
// Returns [dwalletCap, signId]

// DKG with public user share (shared mode)
requestDWalletDKGWithPublicUserShare<S extends SignatureAlgorithm = never>({
    publicKeyShareAndProof: Uint8Array,
    publicUserSecretKeyShare: Uint8Array,
    userPublicOutput: Uint8Array,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
    sessionIdentifier: TransactionObjectArgument,
    dwalletNetworkEncryptionKeyId: string,
    curve: Curve,
    signDuringDKGRequest?: {           // optional: sign during DKG
        message: Uint8Array,
        presign: Presign,
        verifiedPresignCap: TransactionObjectArgument,
        hashScheme: ValidHashForSignature<S>,
        signatureAlgorithm: S,
    },
}): Promise<TransactionResult>
```

### Accept Encrypted User Share

```typescript
// For DKG dWallets
acceptEncryptedUserShare({
    dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
    userPublicOutput: Uint8Array,
    encryptedUserSecretKeyShareId: string,
}): Promise<IkaTransaction>

// For transferred dWallets
acceptEncryptedUserShare({
    dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
    sourceEncryptionKey: EncryptionKey,
    sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    destinationEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
}): Promise<IkaTransaction>
```

### Convert to Shared Mode

```typescript
makeDWalletUserSecretKeySharesPublic({
    dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
    secretShare: Uint8Array,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): IkaTransaction
```

### Presign

```typescript
// dWallet-specific presign (for ECDSA k1/r1 with imported key dWallets)
requestPresign({
    dWallet: DWallet,
    signatureAlgorithm: SignatureAlgorithm,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): TransactionObjectArgument

// Global presign
requestGlobalPresign<C extends Curve>({
    dwalletNetworkEncryptionKeyId: string,
    curve: C,
    signatureAlgorithm: ValidSignatureAlgorithmForCurve<C>,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): TransactionObjectArgument
```

### Message Approval

```typescript
approveMessage<C extends Curve, S extends ValidSignatureAlgorithmForCurve<C>>({
    dWalletCap: TransactionObjectArgument | string,
    curve: C,
    signatureAlgorithm: S,
    hashScheme: ValidHashForSignature<S>,
    message: Uint8Array,
}): TransactionObjectArgument

approveImportedKeyMessage<C extends Curve, S extends ValidSignatureAlgorithmForCurve<C>>({
    dWalletCap: TransactionObjectArgument | string,
    curve: C,
    signatureAlgorithm: S,
    hashScheme: ValidHashForSignature<S>,
    message: Uint8Array,
}): TransactionObjectArgument
```

### Verify Presign

```typescript
// From presign object
verifyPresignCap({ presign: Presign }): TransactionObjectArgument

// From unverified cap
verifyPresignCap({
    unverifiedPresignCap: TransactionObjectArgument,
}): TransactionObjectArgument
```

### Sign

```typescript
requestSign<S extends SignatureAlgorithm>({
    dWallet: ZeroTrustDWallet | SharedDWallet,
    messageApproval: TransactionObjectArgument,
    hashScheme: ValidHashForSignature<S>,
    verifiedPresignCap: TransactionObjectArgument,
    presign: Presign,
    message: Uint8Array,
    signatureScheme: S,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
    encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare,  // zero-trust option 1
    secretShare?: Uint8Array,                                   // zero-trust option 2 (requires publicOutput)
    publicOutput?: Uint8Array,                                  // zero-trust option 2
    // For shared: uses public_user_secret_key_share automatically
}): Promise<TransactionObjectArgument>

requestSignWithImportedKey<S extends SignatureAlgorithm>({
    dWallet: ImportedKeyDWallet | ImportedSharedDWallet,
    importedKeyMessageApproval: TransactionObjectArgument,
    hashScheme: ValidHashForSignature<S>,
    verifiedPresignCap: TransactionObjectArgument,
    presign: Presign,
    message: Uint8Array,
    signatureScheme?: S,  // optional, defaults to ECDSASecp256k1
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
    encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare,
    secretShare?: Uint8Array,
    publicOutput?: Uint8Array,
}): Promise<TransactionObjectArgument>
```

### Future Sign (Two-Phase)

```typescript
// Phase 1: Request partial signature
requestFutureSign<S extends SignatureAlgorithm>({
    dWallet: ZeroTrustDWallet | SharedDWallet,
    hashScheme: ValidHashForSignature<S>,
    verifiedPresignCap: TransactionObjectArgument,
    presign: Presign,
    message: Uint8Array,
    signatureScheme: S,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
    encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare,
    secretShare?: Uint8Array,
    publicOutput?: Uint8Array,
}): Promise<TransactionObjectArgument>

// Phase 2: Complete with approval
futureSign({
    partialUserSignatureCap: TransactionObjectArgument | string,
    messageApproval: TransactionObjectArgument,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): TransactionObjectArgument

// Imported key variants
requestFutureSignWithImportedKey<S>({...}): Promise<TransactionObjectArgument>
futureSignWithImportedKey({...}): TransactionObjectArgument
```

### Key Import

```typescript
requestImportedKeyDWalletVerification({
    importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput,
    curve: Curve,
    signerPublicKey: Uint8Array,
    sessionIdentifier: TransactionObjectArgument,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): Promise<TransactionObjectArgument>
```

### Transfer (Re-Encrypt)

```typescript
// With encrypted share (auto-decrypts internally)
requestReEncryptUserShareFor({
    dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
    sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    destinationEncryptionKeyAddress: string,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): Promise<IkaTransaction>

// With decrypted secret share
requestReEncryptUserShareFor({
    dWallet: ZeroTrustDWallet | ImportedKeyDWallet,
    sourceSecretShare: Uint8Array,
    sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    destinationEncryptionKeyAddress: string,
    ikaCoin: TransactionObjectArgument,
    suiCoin: TransactionObjectArgument,
}): Promise<IkaTransaction>
```

### Session Management

```typescript
createSessionIdentifier(): TransactionObjectArgument    // Random + register
registerSessionIdentifier(sessionIdentifier: Uint8Array): TransactionObjectArgument
```

### Utility

```typescript
hasDWallet({ dwalletId: string }): TransactionObjectArgument
getDWallet({ dwalletId: string }): TransactionObjectArgument
```

---

## Cryptography Functions

### DKG Preparation

```typescript
// Full async flow (fetches protocol params from network)
prepareDKGAsync(
    ikaClient: IkaClient, curve: Curve,
    userShareEncryptionKeys: UserShareEncryptionKeys,
    bytesToHash: Uint8Array, senderAddress: string,
): Promise<DKGRequestInput>
// Returns { userDKGMessage, userPublicOutput, encryptedUserShareAndProof, userSecretKeyShare }

// Lower-level (requires protocol params)
prepareDKG(
    protocolPublicParameters: Uint8Array, curve: Curve,
    encryptionKey: Uint8Array, bytesToHash: Uint8Array,
    senderAddress: string,
): Promise<DKGRequestInput>
```

### Key Import

```typescript
prepareImportedKeyDWalletVerification(
    ikaClient: IkaClient, curve: Curve,
    bytesToHash: Uint8Array, senderAddress: string,
    userShareEncryptionKeys: UserShareEncryptionKeys,
    privateKey: Uint8Array,
): Promise<ImportDWalletVerificationRequestInput>
// Returns { userPublicOutput, userMessage, encryptedUserShareAndProof }
```

### Signing

```typescript
// Create user's partial signature (with public DKG output)
createUserSignMessageWithPublicOutput<C, S, H>(
    protocolPublicParameters: Uint8Array,
    publicOutput: Uint8Array,
    userSecretKeyShare: Uint8Array,
    presign: Uint8Array,
    message: Uint8Array,
    hash: H, signatureAlgorithm: S, curve: C,
): Promise<Uint8Array>

// Create user's partial signature (with centralized DKG output)
createUserSignMessageWithCentralizedOutput<C, S, H>(
    protocolPublicParameters: Uint8Array,
    centralizedDkgOutput: Uint8Array,
    userSecretKeyShare: Uint8Array,
    presign: Uint8Array,
    message: Uint8Array,
    hash: H, signatureAlgorithm: S, curve: C,
): Promise<Uint8Array>
```

### Public Key Extraction

```typescript
publicKeyFromDWalletOutput(curve: Curve, dWalletOutput: Uint8Array): Promise<Uint8Array>
publicKeyFromCentralizedDKGOutput(curve: Curve, centralizedDkgOutput: Uint8Array): Promise<Uint8Array>
```

### Signature Parsing

```typescript
parseSignatureFromSignOutput<C extends Curve, S>(
    curve: C, signatureAlgorithm: S, signatureOutput: Uint8Array,
): Promise<Uint8Array>
```

### Verification

```typescript
verifyUserShare(
    curve: Curve, userSecretKeyShare: Uint8Array,
    userDKGOutput: Uint8Array, networkDkgPublicOutput: Uint8Array,
): Promise<boolean>

verifySecpSignature<C, S, H>(
    publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array,
    networkDkgPublicOutput: Uint8Array,
    hash: H, signatureAlgorithm: S, curve: C,
): Promise<boolean>

userAndNetworkDKGOutputMatch(
    curve: Curve, userPublicOutput: Uint8Array, networkDKGOutput: Uint8Array,
): Promise<boolean>

verifyAndGetDWalletDKGPublicOutput(
    dWallet: DWallet, encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    publicKey: PublicKey,
): Promise<Uint8Array>
```

### Encryption

```typescript
createClassGroupsKeypair(seed: Uint8Array, curve: Curve): Promise<{
    encryptionKey: Uint8Array; decryptionKey: Uint8Array;
}>

encryptSecretShare(
    curve: Curve, userSecretKeyShare: Uint8Array,
    encryptionKey: Uint8Array, protocolPublicParameters: Uint8Array,
): Promise<Uint8Array>
```

### Session

```typescript
createRandomSessionIdentifier(): Uint8Array        // 32 random bytes
sessionIdentifierDigest(
    bytesToHash: Uint8Array, senderAddressBytes: Uint8Array,
): Uint8Array                                        // KECCAK-256 digest
```

### Protocol Parameters Conversion

```typescript
networkDkgPublicOutputToProtocolPublicParameters(
    curve: Curve, network_dkg_public_output: Uint8Array,
): Promise<Uint8Array>

reconfigurationPublicOutputToProtocolPublicParameters(
    curve: Curve, reconfiguration_public_output: Uint8Array,
    network_dkg_public_output: Uint8Array,
): Promise<Uint8Array>
```

---

## UserShareEncryptionKeys

### Creation

```typescript
// From seed (deterministic, correct curve byte in hash)
static fromRootSeedKey(
    rootSeedKey: Uint8Array, curve: Curve
): Promise<UserShareEncryptionKeys>

// Legacy: for keys registered before the curve-byte fix (non-SECP256K1 only)
static fromRootSeedKeyLegacyHash(
    rootSeedKey: Uint8Array, curve: Curve
): Promise<UserShareEncryptionKeys>

// From serialized bytes (auto-detects legacy vs fixed)
static fromShareEncryptionKeysBytes(bytes: Uint8Array): UserShareEncryptionKeys
```

### Serialization

```typescript
toShareEncryptionKeysBytes(): Uint8Array  // Preserves legacy/fixed distinction via BCS variant
```

### Properties

```typescript
encryptionKey: Uint8Array       // Class-groups public key
decryptionKey: Uint8Array       // Class-groups private key
curve: Curve                     // Curve used for generation
readonly legacyHash: boolean     // true if derived with legacy hash (curve byte always 0)
```

### Identity

```typescript
getSuiAddress(): string                  // Sui address from Ed25519 signing key
getSigningPublicKeyBytes(): Uint8Array   // Ed25519 public key raw bytes
getPublicKey(): Ed25519PublicKey          // Full Ed25519 public key object
```

### Cryptographic Operations

```typescript
// Proof of encryption key ownership
getEncryptionKeySignature(): Promise<Uint8Array>

// Authorize dWallet after DKG (signs public output)
getUserOutputSignature(dWallet: DWallet, userPublicOutput: Uint8Array): Promise<Uint8Array>

// Authorize transferred dWallet (verifies source encryption)
getUserOutputSignatureForTransferredDWallet(
    dWallet: DWallet,
    sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    sourceEncryptionKey: EncryptionKey,
): Promise<Uint8Array>

// Decrypt encrypted secret share
decryptUserShare(
    dWallet: DWallet,
    encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
    protocolPublicParameters: Uint8Array,
): Promise<{ verifiedPublicOutput: Uint8Array; secretShare: Uint8Array; }>

// Verify a signature
verifySignature(message: Uint8Array, signature: Uint8Array): Promise<boolean>
```

---

## Low-Level Transaction Builders

```typescript
import { coordinatorTransactions, systemTransactions } from '@ika.xyz/sdk';
```

All coordinator functions follow: `(ikaConfig, coordinatorObjectRef, ...params, tx)`.

Key functions (50+):

```typescript
// DKG
registerSessionIdentifier(config, coordRef, sessionBytes, tx);
requestDWalletDKGWithPublicUserSecretKeyShare(config, coordRef, ...params, tx);
requestDWalletDKG(config, coordRef, ...params, tx);

// Presign
requestGlobalPresign(config, coordRef, ...params, tx);
requestPresign(config, coordRef, ...params, tx);

// Sign
requestSignAndReturnId(config, coordRef, ...params, tx);
requestSignWithImportedKey(config, coordRef, ...params, tx);

// Future Sign
requestFutureSignAndReturnId(config, coordRef, ...params, tx);
futureSign(config, coordRef, ...params, tx);

// Approval
approveMessage(config, coordRef, ...params, tx);
approveImportedKeyMessage(config, coordRef, ...params, tx);

// Verification
verifyPresignCap(config, coordRef, ...params, tx);

// Encryption
registerEncryptionKey(config, coordRef, ...params, tx);
getActiveEncryptionKey(config, coordRef, address, tx);

// Transfer
requestReEncryptUserShareFor(config, coordRef, ...params, tx);
acceptEncryptedUserShare(config, coordRef, ...params, tx);

// Convert
makeDWalletUserSecretKeySharesPublic(config, coordRef, ...params, tx);

// Import
requestImportedKeyDWalletVerification(config, coordRef, ...params, tx);
```

---

## PollingOptions

All `*InParticularState` methods accept:

```typescript
{
    timeout?: number,          // default: 30000ms
    interval?: number,         // default: 1000ms (initial)
    maxInterval?: number,      // default: 5000ms (max with backoff)
    backoffMultiplier?: number, // default: 1.5
    signal?: AbortSignal,      // for cancellation
}
```

## Error Classes

```typescript
IkaClientError              // Base error class
├── ObjectNotFoundError     // Object not found on chain
├── InvalidObjectError      // Object parsing/validation failed
├── NetworkError            // Network operation failure
└── CacheError              // Caching operation failure
```

---

## Plugin Layer (`@ika.xyz/plugins`)

The plugin layer composes onto a dedicated `IkaClient` exported from
`@ika.xyz/sdk/plugin`. Three plugin roles: source, destination, and
publisher.

### Plugin host

```typescript
import { IkaClient } from '@ika.xyz/sdk/plugin';
import type {
    BaseSignResult,
    DWallet,
    IkaContext,
    SignMessageInput,
} from '@ika.xyz/sdk/plugin';

const ika = await new IkaClient()
    .use(suiSource({ network: 'testnet', signer, suiClient }))
    .use(btc())
    .use(bitcoinPublisher({ network: 'testnet' }));
```

`use` returns the same client for chaining. The host enforces:
- One source maximum.
- Destinations and publishers are keyed by `chain`; registering a
  second plugin for the same chain throws.
- The decorate phase runs once per dWallet on first signing call,
  attaching per-chain namespaces to the dWallet handle.

`ika.publish({ chain, payload })` routes to the registered publisher.

### Source plugin: `suiSource`

```typescript
import { suiSource } from '@ika.xyz/plugins/sui/source';

const source = suiSource({
    network: 'testnet',                       // or 'mainnet'
    signer,                                   // Ed25519Keypair or SuiWalletSigner
    suiClient?,                               // override default
    config?,                                  // override IkaConfig (localnet)
    userShareEncryptionKeys?,                 // default USEK for zero-trust flows
    signerAddress?,                           // override sender address
    ikaFeePerOp?: bigint,                     // default 500_000_000 (0.5 IKA)
    suiGasPerOp?: bigint,                     // default 1_000_000
    postTxSleepMs?: number,                   // default 2_000
    timeouts?: { dkg?, presign?, sign?, shareVerify? },
    rpcUrl?: string,                          // custom Sui RPC
});
```

Surface exposed on `ika.sui`:

```typescript
// High-level
createDWallet(input: CreateDWalletInput): Promise<SuiDWallet>;
getDWallet(id: string): Promise<SuiDWallet>;

// DKG building blocks
prepareDKG(input: PrepareDKGInput): Promise<PrepareDKGOutput>;
requestDKG(input: RequestZeroTrustDKGInput): Promise<SuiDWallet>;
requestDKGWithPublicShare(input: RequestSharedDKGInput): Promise<SuiDWallet>;
requestImportedKeyVerification(input: RequestImportedKeyInput): Promise<RequestImportedKeyOutput>;
revealUserSecretShare(input: RevealUserSecretShareInput): Promise<SuiDWallet>;
acceptEncryptedShare(input: AcceptEncryptedShareInput): Promise<SuiDWallet>;

// Presign
requestPresign(input: RequestPresignInput): Promise<Presign>;
requestGlobalPresign(input: RequestGlobalPresignInput): Promise<Presign>;

// Sign
requestSign(input: SuiSignMessageInput): Promise<SuiSignResult>;
prepareSignMessage(input: PrepareSignInput): Promise<PrepareSignOutput>;

// Future-sign
requestFutureSign(input: RequestFutureSignInput): Promise<RequestFutureSignOutput>;
completeFutureSign(input: CompleteFutureSignInput): Promise<CompleteFutureSignOutput>;

// Composition
transaction<T>(build: (b: SuiTxBuilder) => Promise<T> | T, opts?): Promise<{ result, exec }>;
compose: {
    sign(args: ComposeSignArgs): Promise<void>;
    submitDKG(args): Promise<...>;
    submitSign(args): void;
    requestFutureSign(args: ComposeFutureSignArgs): TransactionObjectArgument;
    completeFutureSign(args: ComposeCompleteFutureSignArgs): void;
};

// Rebinding
withSigner(
    signer: SuiSigner,
    opts?: { signerAddress?: string; userShareEncryptionKeys?: UserShareEncryptionKeys },
): SuiSourceExtend['sui'];

// Plumbing
readonly address: string;
readonly config: IkaConfig;
readonly client: CoreIkaClient;
ready(): Promise<CoreIkaClient>;
```

`SuiSigner` is either an `Ed25519Keypair` or a `SuiWalletSigner`:

```typescript
interface SuiWalletSigner {
    address: string;
    signAndExecuteTransaction(tx: Transaction): Promise<SuiTxExecutionResult>;
}
```

`SuiTxExecutionResult` is the minimal shape the source needs to parse
events:

```typescript
interface SuiTxExecutionResult {
    digest?: string;
    events?: Array<{
        eventType: string;
        bcs?: number[] | Uint8Array | null;
    }> | null;
}
```

### Destination plugins

All four follow the same shape:

```typescript
// Bitcoin
import { btc, deriveBitcoinAddress, buildP2trScriptPath } from '@ika.xyz/plugins/bitcoin/destination';
import type { BitcoinMode, BitcoinSignInput, BitcoinSignedTx } from '@ika.xyz/plugins/bitcoin/destination';

// Ethereum
import { eth, deriveEthereumAddress } from '@ika.xyz/plugins/ethereum/destination';
import type { EthereumSignInput, EthereumSignedTx } from '@ika.xyz/plugins/ethereum/destination';

// Solana
import { solana, deriveSolanaPublicKey } from '@ika.xyz/plugins/solana/destination';
import type { SolanaSignInput, SolanaSignedTx } from '@ika.xyz/plugins/solana/destination';

// Sui (signing for Sui from a Sui-coordinated dWallet)
import { sui, deriveSuiAddress } from '@ika.xyz/plugins/sui/destination';
import type { SuiSignInput, SuiSignedTx, SuiSupportedCurve } from '@ika.xyz/plugins/sui/destination';
```

Each destination decorates the returned `SuiDWallet` with a
chain-specific namespace:

```typescript
dWallet.bitcoin.getAddress(opts): Promise<string>;
dWallet.bitcoin.prepareSign(input): Promise<{ prep, preimage, plan }>;
dWallet.bitcoin.assembleSign(prep, signature): Promise<SignedTx>;
dWallet.bitcoin.sign(input): Promise<SignedTx>;
```

(Replace `bitcoin` with `ethereum`, `solana`, `sui` for the
others.)

Per-chain input shapes:

```typescript
// Bitcoin
type BitcoinSignInput =
    | { kind: 'psbt'; psbt; inputIndex; mode; hashType?; network? }
    | { kind: 'preimage'; preimage; mode };
type BitcoinMode = 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh' | 'p2tr-script';

// Ethereum
type EthereumSignInput =
    | { kind: 'transaction'; tx: TransactionSerializable }
    | { kind: 'message'; message: string | Uint8Array }
    | { kind: 'typedData'; typedData: TypedData };

// Solana
type SolanaSignInput =
    | { kind: 'transaction'; tx: VersionedTransaction }
    | { kind: 'message'; message: Uint8Array };

// Sui
type SuiSignInput =
    | { kind: 'transaction'; tx: Transaction; suiClient: SuiJsonRpcClient }
    | { kind: 'message'; message: Uint8Array };
```

### Publisher plugins

```typescript
// Bitcoin
const pub = bitcoinPublisher({
    apiBaseUrl: defaultEsploraUrl('testnet'),
    broadcast?: (rawHex: string) => Promise<{ txid: string }>,
});

// Ethereum
const pub = ethPublisher({
    chain: sepolia,                          // viem chain
    url: 'https://...',
    confirm?: boolean,
    confirmations?: number,
    confirmTimeoutMs?: number,
});

// Solana
const pub = solanaDevnet({ confirm?, confirmTimeoutMs?, commitment? });
const pub = solanaMainnet({ ... });
const pub = solanaPublisher({ connection, confirm?, ... });

// Sui
const pub = suiPublisher({ suiClient });
```

All publishers implement:

```typescript
interface PublisherPlugin {
    chain: 'bitcoin' | 'ethereum' | 'solana' | 'sui';
    broadcast(signed: SignedTx): Promise<string>;
}
```

### `prepareSign` and `assembleSign`

Every destination exposes the two-phase form:

```typescript
const { prep, preimage, plan } = await dWallet.bitcoin.prepareSign(input);
// prep: assembleSign reads this
// preimage: bytes to send to the MPC's signMessage
// plan: { curve, signatureAlgorithm, hash }

const signed = await dWallet.bitcoin.assembleSign(prep, signature);
```

Use when the signature does not flow through `ctx.source.signMessage`:
multisig contracts, future-sign, sponsored relays, persisted-then-
replayed flows.

### Future-sign

```typescript
// Phase 1
const { capId, partialSignatureId } = await ika.sui.requestFutureSign({
    dWallet,
    message,
    signatureAlgorithm,
    hash,
    presign,
    capRecipient?: string,
});

// Phase 2 (must match all four fields)
const { signId } = await ika.sui.completeFutureSign({
    dWallet,
    partialUserSignatureCap: capId,
    message,
    signatureAlgorithm,
    hash,
    presign,
});
```

On-chain coordinator verifies `(dwallet_id, message,
signature_algorithm, hash_scheme)` match between the captured
partial-signature object and the supplied message approval. Phase 2
aborts with `EMessageApprovalMismatch` if any field differs.

### `withSigner` and `capRecipient`

```typescript
// DKG submitted by backend, capability routed to user
const dWallet = await ika.sui.createDWallet({
    kind: 'zero-trust',
    curve: Curve.SECP256K1,
    capRecipient: userSuiAddress,
});

// Subsequent ops as the user
const userView = ika.sui.withSigner(userSigner, {
    userShareEncryptionKeys: userKeys, // recommended for multi-tenant
});
```

`withSigner` shares the underlying `IkaClient`, init state, and
caches. If `userShareEncryptionKeys` is not supplied on the options,
the outer source's USEK is inherited. Make this explicit on
multi-tenant deployments.

### Subpath imports

The plugins package exposes per-chain subpaths so bundlers can drop
chains you do not use:

```
@ika.xyz/plugins/sui/source
@ika.xyz/plugins/sui/destination
@ika.xyz/plugins/sui/publisher

@ika.xyz/plugins/bitcoin/destination
@ika.xyz/plugins/bitcoin/publisher

@ika.xyz/plugins/ethereum/destination
@ika.xyz/plugins/ethereum/publisher

@ika.xyz/plugins/solana/destination
@ika.xyz/plugins/solana/publisher
```

The root `@ika.xyz/plugins` re-exports everything. Prefer subpath
imports unless you genuinely need everything.

### Per-chain destination notes

- **Bitcoin**: P2TR is script-path only (NUMS internal pubkey). The
  plugin re-normalizes ECDSA signatures to low-S before DER encoding.
- **Ethereum**: yParity recovered empirically by trying both. The
  plugin re-normalizes ECDSA to low-S; viem's `recoverAddress`
  accepts both forms so the parity flip is handled. EIP-712 with
  caller-omitted `EIP712Domain` falls back to
  `getTypesForEIP712Domain({ domain })`. Legacy txs detected via
  viem's `getTransactionType`.
- **Solana**: 32-byte Ed25519 pubkey is the address. No pre-hash;
  Ed25519 internally consumes the message via SHA-512.
- **Sui**: 64-byte signature length checked. PersonalMessage
  signatures BCS-wrap the message before applying the intent prefix,
  matching `@mysten/sui` `Signer.signPersonalMessage` so
  `PublicKey.verifyPersonalMessage` accepts the result.
