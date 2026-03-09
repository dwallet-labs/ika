# Types and Validation

Type system, enums, curve/signature/hash validation, and state narrowing.

## Enums

### Curve

```typescript
const Curve = {
    SECP256K1: 'SECP256K1',    // Bitcoin, Ethereum (curveNumber: 0)
    SECP256R1: 'SECP256R1',    // WebAuthn, P-256 (curveNumber: 1)
    ED25519: 'ED25519',        // Solana, Substrate-Ed25519 (curveNumber: 2)
    RISTRETTO: 'RISTRETTO',   // Schnorrkel/Substrate (curveNumber: 3)
} as const;
type Curve = (typeof Curve)[keyof typeof Curve];
```

### SignatureAlgorithm

```typescript
const SignatureAlgorithm = {
    ECDSASecp256k1: 'ECDSASecp256k1',         // absoluteNumber: 0
    Taproot: 'Taproot',                         // absoluteNumber: 1
    ECDSASecp256r1: 'ECDSASecp256r1',          // absoluteNumber: 2
    EdDSA: 'EdDSA',                             // absoluteNumber: 3
    SchnorrkelSubstrate: 'SchnorrkelSubstrate', // absoluteNumber: 4
} as const;
type SignatureAlgorithm = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];
```

### Hash

```typescript
const Hash = {
    KECCAK256: 'KECCAK256',       // absoluteNumber: 0
    SHA256: 'SHA256',             // absoluteNumber: 1
    DoubleSHA256: 'DoubleSHA256', // absoluteNumber: 2
    SHA512: 'SHA512',             // absoluteNumber: 3
    Merlin: 'Merlin',            // absoluteNumber: 4
} as const;
type Hash = (typeof Hash)[keyof typeof Hash];
```

## Valid Combinations (Full Config)

```
SECP256K1 (curve=0):
├── ECDSASecp256k1 (sigAlgo=0):
│   ├── KECCAK256 (hash=0)  ← Ethereum
│   ├── SHA256 (hash=1)
│   └── DoubleSHA256 (hash=2)  ← Bitcoin Legacy
└── Taproot (sigAlgo=1):
    └── SHA256 (hash=0)  ← Bitcoin Taproot

SECP256R1 (curve=1):
└── ECDSASecp256r1 (sigAlgo=0):
    └── SHA256 (hash=0)  ← WebAuthn

ED25519 (curve=2):
└── EdDSA (sigAlgo=0):
    └── SHA512 (hash=0)  ← Solana

RISTRETTO (curve=3):
└── SchnorrkelSubstrate (sigAlgo=0):
    └── Merlin (hash=0)  ← Substrate
```

**Important**: Signature algorithm numbers are relative to curve. Hash numbers are relative to curve+sigAlgo. Absolute numbers are global.

## Compile-Time Type Safety

### ValidSignatureAlgorithmForCurve

```typescript
type ValidSignatureAlgorithmForCurve<C extends Curve> =
    C extends 'SECP256K1' ? 'ECDSASecp256k1' | 'Taproot' :
    C extends 'SECP256R1' ? 'ECDSASecp256r1' :
    C extends 'ED25519' ? 'EdDSA' :
    C extends 'RISTRETTO' ? 'SchnorrkelSubstrate' :
    never;
```

### ValidHashForSignature

```typescript
type ValidHashForSignature<S extends SignatureAlgorithm> =
    S extends 'ECDSASecp256k1' ? 'KECCAK256' | 'SHA256' | 'DoubleSHA256' :
    S extends 'Taproot' ? 'SHA256' :
    S extends 'ECDSASecp256r1' ? 'SHA256' :
    S extends 'EdDSA' ? 'SHA512' :
    S extends 'SchnorrkelSubstrate' ? 'Merlin' :
    never;
```

### ValidatedSigningParams

```typescript
type ValidatedSigningParams<S extends SignatureAlgorithm> = {
    hashScheme: ValidHashForSignature<S>;
    signatureAlgorithm: S;
};

// Creates compile-time + runtime validated params
createValidatedSigningParams(Hash.SHA256, SignatureAlgorithm.ECDSASecp256k1); // OK
createValidatedSigningParams(Hash.SHA512, SignatureAlgorithm.ECDSASecp256k1); // Compile error
```

## Runtime Validation Functions

### Validators (throw on invalid)

```typescript
validateHashSignatureCombination(hash: Hash, signatureAlgorithm: SignatureAlgorithm): void
validateCurveSignatureAlgorithm(curve: Curve, signatureAlgorithm: SignatureAlgorithm): void
```

### Type Guards (return boolean)

```typescript
isValidHashForSignature<S>(hash: Hash, signatureAlgorithm: S): hash is ValidHashForSignature<S>
isValidSignatureAlgorithmForCurve(curve: Curve, signatureAlgorithm: SignatureAlgorithm): boolean
isValidHashForCurveAndSignature(curve: Curve, signatureAlgorithm: SignatureAlgorithm, hash: Hash): boolean
```

### Query Functions

```typescript
getValidSignatureAlgorithmsForCurve(curve: Curve): SignatureAlgorithm[]
getValidHashesForCurveAndSignature(curve: Curve, signatureAlgorithm: SignatureAlgorithm): Hash[]
getValidHashesForSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm): string[]
```

### Display Names

```typescript
getCurveName(curve: Curve): string                              // e.g., 'secp256k1'
getSignatureAlgorithmName(signatureAlgorithm: SignatureAlgorithm): string
getHashName(hash: Hash): string                                  // e.g., 'KECCAK256 (SHA3)'
```

## Number Conversion

Two numbering schemes:
- **Relative**: Numbers within their parent (sigAlgo relative to curve, hash relative to curve+sigAlgo)
- **Absolute**: Global unique numbers

### Enum → Number

```typescript
fromCurveToNumber(curve: Curve): number
fromSignatureAlgorithmToNumber(curve: Curve, signatureAlgorithm: SignatureAlgorithm): number  // relative
fromHashToNumber(curve: Curve, signatureAlgorithm: SignatureAlgorithm, hash: Hash): number    // relative
fromSignatureAlgorithmToAbsoluteNumber(signatureAlgorithm: SignatureAlgorithm): number
fromHashToAbsoluteNumber(hash: Hash): number

// Batch conversions
fromCurveAndSignatureAlgorithmToNumbers(curve, sigAlgo): { curveNumber, signatureAlgorithmNumber }
fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, sigAlgo, hash): { curveNumber, signatureAlgorithmNumber, hashNumber }
```

### Number → Enum

```typescript
fromNumberToCurve(curveNumber: number): Curve
fromNumberToSignatureAlgorithm(curve: Curve, signatureAlgorithmNumber: number): SignatureAlgorithm  // relative
fromNumberToHash(curve: Curve, signatureAlgorithm: SignatureAlgorithm, hashNumber: number): Hash    // relative
fromAbsoluteNumberToSignatureAlgorithm(absoluteNumber: number): SignatureAlgorithm
fromAbsoluteNumberToHash(absoluteNumber: number): Hash

// Batch conversions
fromNumbersToCurveAndSignatureAlgorithm(curveNum, sigAlgoNum): { curve, signatureAlgorithm }
fromNumbersToCurveAndSignatureAlgorithmAndHash(curveNum, sigAlgoNum, hashNum): { curve, signatureAlgorithm, hash }
```

---

## DWallet Types

### DWalletKind

```typescript
const DWalletKind = {
    ZeroTrust: 'zero-trust',
    ImportedKey: 'imported-key',
    ImportedKeyShared: 'imported-key-shared',
    Shared: 'shared',
} as const;
type DWalletKind = (typeof DWalletKind)[keyof typeof DWalletKind];
```

### DWallet Discriminated Union

```typescript
type DWallet = ZeroTrustDWallet | ImportedKeyDWallet | ImportedSharedDWallet | SharedDWallet;

type ZeroTrustDWallet = DWalletInternal & { kind: 'zero-trust' };
type SharedDWallet = DWalletInternal & { kind: 'shared' };
type ImportedKeyDWallet = DWalletInternal & { kind: 'imported-key' };
type ImportedSharedDWallet = DWalletInternal & { kind: 'imported-key-shared' };
```

Kind is determined by:
- Has `public_user_secret_key_share`? → shared or imported-key-shared
- Has imported key markers? → imported-key or imported-key-shared
- Otherwise → zero-trust

### DWalletInternal Key Fields

```typescript
interface DWalletInternal {
    id: string;
    created_at_epoch: string;                         // bigint as string
    curve: number;                                    // Use fromNumberToCurve()
    public_user_secret_key_share: number[] | null;    // null for zero-trust
    dwallet_cap_id: string;
    dwallet_network_encryption_key_id: string;
    is_imported_key_dwallet: boolean;
    state: DWalletState;                              // Discriminated union
    // public_output is inside state (Active or AwaitingKeyHolderSignature)
    // Access as: dWallet.state.Active.public_output
}
```

## State Types

### DWalletState

```typescript
type DWalletState =
    | 'DKGRequested'                              // DKG first round requested
    | 'NetworkRejectedDKGRequest'                  // Network rejected DKG first round
    | 'AwaitingUserDKGVerificationInitiation'      // DKG first round done, has first_round_output
    | 'AwaitingNetworkDKGVerification'             // DKG second round requested
    | 'NetworkRejectedDKGVerification'             // Network rejected DKG second round
    | 'AwaitingNetworkImportedKeyVerification'     // Imported key verification requested
    | 'NetworkRejectedImportedKeyVerification'     // Network rejected imported key
    | 'AwaitingKeyHolderSignature'                 // DKG/import done, has public_output
    | 'Active';                                    // Fully operational, has public_output
```

States with data:
- `AwaitingUserDKGVerificationInitiation`: `{ first_round_output: number[] }`
- `AwaitingKeyHolderSignature`: `{ public_output: number[] }`
- `Active`: `{ public_output: number[] }`

**`$kind` discriminator**: State objects use a `$kind` string field to identify which variant is active. Use `dWallet.state.$kind` to check the current state (e.g., `dWallet.state.$kind === 'Active'`). This applies to all state types (`DWalletState`, `PresignState`, `SignState`, `PartialUserSignatureState`, `EncryptedUserSecretKeyShareState`).

### PresignState

```typescript
type PresignState =
    | 'Requested'       // Presign requested, awaiting network
    | 'NetworkRejected' // Network rejected the request
    | 'Completed';      // Ready for signing, has presign data
```

States with data:
- `Completed`: `{ presign: number[] }`

### SignState

```typescript
type SignState =
    | 'Requested'       // Sign requested, awaiting network
    | 'NetworkRejected' // Network rejected the request
    | 'Completed';      // Signature available
```

States with data:
- `Completed`: `{ signature: number[] }`

### PartialUserSignatureState

```typescript
type PartialUserSignatureState =
    | 'AwaitingNetworkVerification'       // Awaiting network verification
    | 'NetworkVerificationCompleted'      // Network verified successfully
    | 'NetworkVerificationRejected';      // Network rejected verification
```

### EncryptedUserSecretKeyShareState

```typescript
type EncryptedUserSecretKeyShareState =
    | 'AwaitingNetworkVerification'       // Awaiting network verification
    | 'NetworkVerificationCompleted'      // Network verified successfully
    | 'NetworkVerificationRejected'       // Network rejected verification
    | 'KeyHolderSigned';                  // Key holder signed and accepted
```

States with data:
- `KeyHolderSigned`: `{ user_output_signature: number[] }`

## State Narrowing Generics

```typescript
// Narrow any object type to a specific state
type DWalletWithState<S extends DWalletState>
type PresignWithState<S extends PresignState>
type SignWithState<S extends SignState>
type PartialUserSignatureWithState<S extends PartialUserSignatureState>
type EncryptedUserSecretKeyShareWithState<S extends EncryptedUserSecretKeyShareState>
```

Example:

```typescript
// Typed as DWalletWithState<'Active'> - guaranteed to have Active state
const dWallet = await ikaClient.getDWalletInParticularState(id, 'Active');
// dWallet.state.Active.public_output is type-safe accessible

// Typed as PresignWithState<'Completed'>
const presign = await ikaClient.getPresignInParticularState(id, 'Completed');
// presign.state.Completed.presign is type-safe accessible
```

---

## Config Types

### IkaConfig

```typescript
interface IkaConfig {
    packages: IkaPackageConfig;
    objects: IkaObjectsConfig;
}

interface IkaPackageConfig {
    ikaPackage: string;
    ikaCommonPackage: string;
    ikaSystemOriginalPackage: string;
    ikaDwallet2pcMpcOriginalPackage: string;
    ikaDwallet2pcMpcPackage: string;
    ikaSystemPackage: string;
}

interface IkaObjectsConfig {
    ikaSystemObject: { objectID: string; initialSharedVersion: number; };
    ikaDWalletCoordinator: { objectID: string; initialSharedVersion: number; };
}
```

### IkaClientOptions

```typescript
interface IkaClientOptions {
    config: IkaConfig;
    suiClient: ClientWithCoreApi;      // @mysten/sui client
    timeout?: number;
    cache?: boolean;                    // default: true
    encryptionKeyOptions?: EncryptionKeyOptions;
}
```

### EncryptionKeyOptions

```typescript
interface EncryptionKeyOptions {
    encryptionKeyID?: string;   // Use specific key
    autoDetect?: boolean;       // Auto-detect from dWallet (default: true)
}
```

### NetworkEncryptionKey

```typescript
interface NetworkEncryptionKey {
    id: string;
    epoch: number;
    networkDKGOutputID: string;
    reconfigurationOutputID: string | undefined;
}
```

### UserSignatureInputs

```typescript
type UserSignatureInputs = {
    activeDWallet?: DWallet;
    publicOutput?: Uint8Array;
    secretShare?: Uint8Array;
    encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
    presign: Presign;
    message: Uint8Array;
    hash: Hash;
    signatureScheme: SignatureAlgorithm;
    curve: Curve;
    createWithCentralizedOutput?: boolean;
};
```

---

## Import Summary

```typescript
// Core
import { IkaClient, IkaTransaction, getNetworkConfig } from '@ika.xyz/sdk';

// Keys
import { UserShareEncryptionKeys } from '@ika.xyz/sdk';

// Enums
import { Curve, SignatureAlgorithm, Hash } from '@ika.xyz/sdk';

// Crypto functions
import {
    prepareDKGAsync, prepareDKG,
    createRandomSessionIdentifier, sessionIdentifierDigest,
    createUserSignMessageWithPublicOutput, createUserSignMessageWithCentralizedOutput,
    publicKeyFromDWalletOutput, publicKeyFromCentralizedDKGOutput,
    parseSignatureFromSignOutput,
    prepareImportedKeyDWalletVerification,
    verifyUserShare, verifySecpSignature, userAndNetworkDKGOutputMatch,
    createClassGroupsKeypair, encryptSecretShare,
} from '@ika.xyz/sdk';

// Types
import type {
    DWallet, ZeroTrustDWallet, SharedDWallet, ImportedKeyDWallet, ImportedSharedDWallet,
    DWalletCap, DWalletInternal, DWalletKind, DWalletState, DWalletWithState,
    Presign, PresignState, PresignWithState,
    Sign, SignState, SignWithState,
    EncryptedUserSecretKeyShare, EncryptedUserSecretKeyShareState, EncryptedUserSecretKeyShareWithState,
    PartialUserSignature, PartialUserSignatureState, PartialUserSignatureWithState,
    EncryptionKey, NetworkEncryptionKey, EncryptionKeyOptions,
    IkaConfig, IkaClientOptions, IkaPackageConfig, IkaObjectsConfig,
    UserSignatureInputs,
} from '@ika.xyz/sdk';

// Validation
import {
    validateHashSignatureCombination, validateCurveSignatureAlgorithm,
    isValidHashForSignature, isValidSignatureAlgorithmForCurve, isValidHashForCurveAndSignature,
    getValidSignatureAlgorithmsForCurve, getValidHashesForCurveAndSignature,
    createValidatedSigningParams,
    fromCurveToNumber, fromSignatureAlgorithmToNumber, fromHashToNumber,
    fromNumberToCurve, fromNumberToSignatureAlgorithm, fromNumberToHash,
    fromSignatureAlgorithmToAbsoluteNumber, fromAbsoluteNumberToSignatureAlgorithm,
    fromHashToAbsoluteNumber, fromAbsoluteNumberToHash,
    fromCurveAndSignatureAlgorithmToNumbers, fromCurveAndSignatureAlgorithmAndHashToNumbers,
    fromNumbersToCurveAndSignatureAlgorithm, fromNumbersToCurveAndSignatureAlgorithmAndHash,
} from '@ika.xyz/sdk';
import type {
    ValidSignatureAlgorithmForCurve, ValidHashForSignature, ValidatedSigningParams,
} from '@ika.xyz/sdk';

// Low-level
import { coordinatorTransactions, systemTransactions } from '@ika.xyz/sdk';

// Errors
import {
    IkaClientError, ObjectNotFoundError, InvalidObjectError, NetworkError, CacheError,
} from '@ika.xyz/sdk';
```
