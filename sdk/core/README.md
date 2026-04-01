### @ika.xyz/core — Chain-Agnostic Core for Ika dWallet Protocol

## Overview

Chain-agnostic cryptographic core for the Ika dWallet 2PC-MPC protocol. This package provides all
the protocol-level operations needed to create and use dWallets, without any blockchain-specific
dependencies.

Use this package directly if you're building a chain adapter, or use a chain-specific SDK (e.g.,
`@ika.xyz/sui`) which re-exports everything from core.

## Install

```bash
npm install @ika.xyz/core
```

## What's included

- 2PC-MPC cryptographic operations (DKG, signing, verification)
- User share encryption key management
- Ed25519 keypair utilities
- Curve, hash, and signature algorithm validation
- WASM bindings for class-groups and protocol math

## Key generation

```ts
import { createClassGroupsKeypair, Curve } from '@ika.xyz/core';

const { encryptionKey, decryptionKey } = await createClassGroupsKeypair(seed, Curve.SECP256K1);
```

## User share encryption keys

`UserShareEncryptionKeys` derives class-groups and Ed25519 keypairs from a single 32-byte root seed.

```ts
import { Curve, UserShareEncryptionKeys } from '@ika.xyz/core';

const keys = await UserShareEncryptionKeys.fromRootSeedKey(rootSeed, Curve.SECP256K1);

// Serialize (contains secret material — store encrypted!)
const bytes = keys.toShareEncryptionKeysBytes();
const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(bytes);

// Sign and verify
const signature = await keys.sign(message);
const valid = await keys.verifySignature(message, signature);

// Proof-of-ownership for on-chain registration
const encKeySig = await keys.getEncryptionKeySignature();

// Decrypt a secret share (low-level — chain SDKs wrap this with verification)
const secretShare = await keys.decryptSecretShare(publicOutput, encryptedShare, protocolParams);
```

## DKG preparation

```ts
import { Curve, prepareDKG } from '@ika.xyz/core';

// Chain-agnostic: takes raw address bytes, not a chain-specific address string
const dkgInput = await prepareDKG(
	protocolPublicParameters,
	Curve.SECP256K1,
	encryptionKey,
	bytesToHash,
	senderAddressBytes, // Uint8Array — chain SDK converts address format to bytes
);
```

## Signature creation and verification

```ts
import {
	createUserSignMessageWithPublicOutput,
	Curve,
	Hash,
	parseSignatureFromSignOutput,
	SignatureAlgorithm,
	verifySecpSignature,
} from '@ika.xyz/core';

const signMsg = await createUserSignMessageWithPublicOutput(
	protocolPublicParameters,
	publicOutput,
	userSecretKeyShare,
	presign,
	message,
	Hash.KECCAK256,
	SignatureAlgorithm.ECDSASecp256k1,
	Curve.SECP256K1,
);

const signature = await parseSignatureFromSignOutput(
	Curve.SECP256K1,
	SignatureAlgorithm.ECDSASecp256k1,
	signOutput,
);

const valid = await verifySecpSignature(
	publicKey,
	signature,
	message,
	networkDkgPublicOutput,
	Hash.KECCAK256,
	SignatureAlgorithm.ECDSASecp256k1,
	Curve.SECP256K1,
);
```

## Supported curves, signature algorithms, and hashes

| Curve     | Signature Algorithm | Valid Hashes                    |
| --------- | ------------------- | ------------------------------- |
| SECP256K1 | ECDSASecp256k1      | KECCAK256, SHA256, DoubleSHA256 |
| SECP256K1 | Taproot             | SHA256                          |
| SECP256R1 | ECDSASecp256r1      | SHA256                          |
| ED25519   | EdDSA               | SHA512                          |
| RISTRETTO | SchnorrkelSubstrate | Merlin                          |

Compile-time type safety and runtime validation:

```ts
import { validateCurveSignatureAlgorithm, validateHashSignatureCombination } from '@ika.xyz/core';
```

## Ed25519 keypair

Chain-agnostic Ed25519 using `@noble/curves`. Supports both hex and Bech32 secret key formats for
backward compatibility.

```ts
import { Ed25519Keypair } from '@ika.xyz/core';

const keypair = Ed25519Keypair.fromSeed(seed);
const signature = await keypair.sign(message);
const valid = await keypair.verify(message, signature);
```

## Building a chain adapter

Chain SDKs should:

1. Depend on `@ika.xyz/core` and re-export everything from their index
2. Provide chain-specific address derivation (e.g., `getSuiAddress(keys)`)
3. Wrap `prepareDKG` to convert chain address formats to raw bytes
4. Wrap `decryptSecretShare` with chain-specific dWallet state verification
5. Provide transaction builders for the chain's smart contract calls

See `@ika.xyz/sui` for a reference implementation.

## Testing

```bash
pnpm test:unit
```

### License

BSD-3-Clause-Clear (c) dWallet Labs, Ltd.
