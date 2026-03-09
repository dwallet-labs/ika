# TypeScript Integration Reference

Complete patterns for TypeScript SDK interaction with Move contracts.

## SDK Setup

```typescript
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

const suiClient = new SuiJsonRpcClient({
    url: getJsonRpcFullnodeUrl('testnet'),
    network: 'testnet',
});

const ikaClient = new IkaClient({
    suiClient,
    config: getNetworkConfig('testnet'),
    cache: true,
});
await ikaClient.initialize();

// Key references
const coordinatorId = ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID;
const networkKey = await ikaClient.getLatestNetworkEncryptionKey();
```

## DKG: Prepare and Call Move

```typescript
import {
    createRandomSessionIdentifier, Curve, prepareDKGAsync, UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { Transaction } from '@mysten/sui/transactions';

// 1. Create encryption keys from seed
const keys = await UserShareEncryptionKeys.fromRootSeedKey(
    new TextEncoder().encode('your-seed'), Curve.SECP256K1,
);

// 2. Create bytes to hash (hashed internally to derive the session identifier)
const bytesToHash = createRandomSessionIdentifier();

// 3. Prepare DKG data
const dkgData = await prepareDKGAsync(
    ikaClient, Curve.SECP256K1, keys, bytesToHash, signerAddress,
);
// dkgData contains:
//   .userDKGMessage (= centralized_public_key_share_and_proof)
//   .userPublicOutput
//   .encryptedUserShareAndProof
//   .userSecretKeyShare (= public_user_secret_key_share for shared mode, SAVE for later conversion)

// 4. Get network encryption key
const networkKey = await ikaClient.getLatestNetworkEncryptionKey();

// 5. Call Move function
const tx = new Transaction();
tx.moveCall({
    target: `${PACKAGE_ID}::treasury::create_treasury`,
    arguments: [
        tx.object(coordinatorId),
        tx.object(ikaCoinId),                                           // Coin<IKA>
        tx.splitCoins(tx.gas, [1000000]),                               // Coin<SUI>
        tx.pure.id(networkKey.id),                                      // encryption key ID
        tx.pure.vector('u8', Array.from(dkgData.userDKGMessage)),       // DKG message
        tx.pure.vector('u8', Array.from(dkgData.userPublicOutput)),     // public output
        tx.pure.vector('u8', Array.from(dkgData.userSecretKeyShare)),   // secret share (public for shared mode)
        tx.pure.vector('u8', Array.from(bytesToHash)),                   // bytes to hash for session
        tx.pure.vector('address', members),                             // members
        tx.pure.u64(threshold),                                         // threshold
    ],
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

## Accept Encrypted User Share (Zero-Trust / Imported Key Only)

After zero-trust DKG or key import, the dWallet is in `AwaitingKeyHolderSignature` state. The user must call `acceptEncryptedUserShare` to transition it to `Active`:

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';

// Wait for dWallet to reach AwaitingKeyHolderSignature state
const awaitingDWallet = await ikaClient.getDWalletInParticularState(dwalletId, 'AwaitingKeyHolderSignature');
// The encrypted user secret key share ID comes from the DKG transaction event,
// NOT from the dWallet ID.
const encryptedShare = await ikaClient.getEncryptedUserSecretKeyShare(encryptedUserSecretKeyShareId);

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.acceptEncryptedUserShare({
    dWallet: awaitingDWallet,
    encryptedUserSecretKeyShareId: encryptedShare.id,
    userPublicOutput: new Uint8Array(dkgData.userPublicOutput),
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });

// dWallet is now Active
const activeDWallet = await ikaClient.getDWalletInParticularState(dwalletId, 'Active');
```

This step is NOT needed for shared dWallets (created with `request_dwallet_dkg_with_public_user_secret_key_share`).

## Get dWallet Public Key After DKG

```typescript
import { publicKeyFromDWalletOutput, Curve } from '@ika.xyz/sdk';

const dWallet = await ikaClient.getDWallet(dwalletId);
const publicKey = await publicKeyFromDWalletOutput(Curve.SECP256K1, dWallet.state.Active!.public_output);
// Use publicKey to derive Bitcoin/Ethereum address
```

## Signing: Prepare User Signature and Call Move

```typescript
import {
    createUserSignMessageWithPublicOutput, Curve,
    SignatureAlgorithm, Hash, parseSignatureFromSignOutput,
} from '@ika.xyz/sdk';

// 1. Wait for presign completion
const completedPresign = await ikaClient.getPresignInParticularState(presignId, 'Completed');

// 2. Create user's partial signature (for shared dWallets)
const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, Curve.SECP256K1);
const msgSig = await createUserSignMessageWithPublicOutput(
    protocolPublicParameters,
    dWallet.state.Active!.public_output,
    dWallet.public_user_secret_key_share,   // available because shared mode
    completedPresign.presign,
    message,                            // the message bytes to sign
    Hash.SHA256,                        // hash scheme
    SignatureAlgorithm.Taproot,         // signature algorithm
    Curve.SECP256K1,                    // curve
);

// 3. Call Move sign function
const tx = new Transaction();
tx.moveCall({
    target: `${PACKAGE_ID}::treasury::sign_message`,
    arguments: [
        tx.object(treasuryId),
        tx.object(coordinatorId),
        tx.pure.vector('u8', Array.from(message)),
        tx.pure.vector('u8', Array.from(msgSig)),
    ],
});
const result = await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });

// 4. Extract sign ID from transaction events
const signId = extractSignIdFromEvents(result.events);
```

## Retrieve Completed Signature

```typescript
// Poll for sign completion
const signSession = await ikaClient.getSignInParticularState(
    signId, Curve.SECP256K1, SignatureAlgorithm.Taproot, 'Completed',
);

// Parse the raw signature
const signature = await parseSignatureFromSignOutput(
    Curve.SECP256K1,
    SignatureAlgorithm.Taproot,
    signSession.signature,
);

// signature is now ready to broadcast on target chain (Bitcoin, Ethereum, etc.)
```

## Key Import: TypeScript Side

```typescript
import { prepareImportedKeyDWalletVerification, Curve } from '@ika.xyz/sdk';

const importData = await prepareImportedKeyDWalletVerification(
    ikaClient,
    Curve.SECP256K1,
    bytesToHash,      // bytes hashed to derive the session identifier
    signerAddress,
    keys,
    privateKey,       // Uint8Array of existing private key
);
// importData contains:
//   .userPublicOutput
//   .userMessage (= centralized_party_message)
//   .encryptedUserShareAndProof (= encrypted_centralized_secret_share_and_proof)

const tx = new Transaction();
tx.moveCall({
    target: `${PACKAGE_ID}::imported_wallet::import_wallet`,
    arguments: [
        tx.object(coordinatorId),
        tx.object(ikaCoinId),
        tx.splitCoins(tx.gas, [1000000]),
        tx.pure.id(networkKey.id),
        tx.pure.vector('u8', Array.from(importData.userMessage)),
        tx.pure.vector('u8', Array.from(importData.encryptedUserShareAndProof)),
        tx.pure.address(keys.getSuiAddress()),
        tx.pure.vector('u8', Array.from(importData.userPublicOutput)),
        tx.pure.vector('u8', Array.from(keys.getSigningPublicKeyBytes())),
        tx.pure.vector('u8', Array.from(bytesToHash)),
    ],
});
```

## Convert to Shared Mode: TypeScript Side

```typescript
import { IkaTransaction } from '@ika.xyz/sdk';

// You must have saved userSecretKeyShare from original DKG or import
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
ikaTx.makeDWalletUserSecretKeySharesPublic({
    dWallet: zeroTrustDWallet,           // ZeroTrustDWallet or ImportedKeyDWallet
    secretShare: savedUserSecretKeyShare, // Uint8Array from original DKG
    ikaCoin: tx.object(ikaCoinId),       // Coin<IKA> object
    suiCoin: tx.splitCoins(tx.gas, [1_000_000]),  // Coin<SUI> from gas
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

## Polling dWallet State

```typescript
// Wait for dWallet to reach specific state
const dWallet = await ikaClient.getDWalletInParticularState(dwalletId, 'Completed');

// Check dWallet type
// Returns: 'zero-trust' | 'shared' | 'imported-key' | 'imported-key-shared'

// Check if converted to shared
if (dWallet.public_user_secret_key_share) {
    // dWallet is in shared mode
}
```

## IkaTransaction (High-Level API)

For SDK-only flows (no custom Move), use `IkaTransaction`:

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });

// DKG
await ikaTx.requestDWalletDKG({ dkgInput, sessionIdentifier, ... });

// Presign
await ikaTx.requestPresign({ dWallet, ... });
await ikaTx.requestGlobalPresign({ ... });

// Sign
await ikaTx.requestSign({
    dWallet, messageApproval, hashScheme: Hash.KECCAK256,
    verifiedPresignCap, presign, encryptedUserSecretKeyShare,
    message, signatureScheme: SignatureAlgorithm.ECDSASecp256k1, ...
});

// Future Sign
await ikaTx.requestFutureSign({ ... });

// Accept encrypted user share (zero-trust / imported key DKG only)
await ikaTx.acceptEncryptedUserShare({ dWallet, encryptedUserSecretKeyShareId, userPublicOutput });

// Session identifiers
const session = ikaTx.createSessionIdentifier();                    // auto-generate random session
const session2 = ikaTx.registerSessionIdentifier(bytesToHash);      // register specific bytes as session
```

## Common TypeScript Argument Patterns

```typescript
// Pass bytes
tx.pure.vector('u8', Array.from(uint8Array))

// Pass ID
tx.pure.id(objectIdString)

// Pass u32/u64
tx.pure.u32(0)
tx.pure.u64(3)

// Pass address
tx.pure.address('0x...')

// Pass vector of addresses
tx.pure.vector('address', ['0x...', '0x...'])

// Split coins for payment
tx.splitCoins(tx.gas, [amount])  // Split SUI from gas
tx.object(coinObjectId)           // Use existing coin object

// Pass shared object
tx.object(sharedObjectId)
```

## Network Config

```typescript
import { getNetworkConfig } from '@ika.xyz/sdk';

const config = getNetworkConfig('testnet'); // or 'mainnet'
// config.packages.ikaPackage
// config.packages.ikaCommonPackage
// config.packages.ikaSystemPackage
// config.packages.ikaDwallet2pcMpcPackage
// config.objects.ikaSystemObject.objectID
// config.objects.ikaDWalletCoordinator.objectID
// config.objects.ikaDWalletCoordinator.initialSharedVersion
```

## Encryption Keys

```typescript
import { UserShareEncryptionKeys, Curve } from '@ika.xyz/sdk';

// Create from seed
const keys = await UserShareEncryptionKeys.fromRootSeedKey(
    new TextEncoder().encode('seed'), Curve.SECP256K1,
);

// Serialize for storage
const bytes = keys.toShareEncryptionKeysBytes();

// Deserialize
const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(bytes);

// Properties
keys.getSuiAddress()              // address for registration
keys.getSigningPublicKeyBytes()   // ed25519 public key
keys.getEncryptionKeySignature()  // proof of ownership
```

## KeySpring Pattern (Cross-Chain Wallet from Any Auth)

Architecture: Use any wallet signature or passkey as seed -> derive encryption keys -> DKG creates Ethereum address.

```
Wallet/Passkey -> sign message -> seed bytes -> UserShareEncryptionKeys -> DKG -> ETH address
```

Key insight: The seed for `UserShareEncryptionKeys.fromRootSeedKey()` can come from any deterministic source:
- Wallet signature of a fixed message
- WebAuthn PRF extension output
- Any deterministic 32+ byte secret

The resulting dWallet public key maps to an Ethereum/Bitcoin address via standard derivation.
