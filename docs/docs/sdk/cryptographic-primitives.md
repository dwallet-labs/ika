---
id: cryptographic-primitives
title: Cryptographic Primitives
description: Reference guide for supported curves, signature algorithms, and hash schemes in the Ika SDK
sidebar_position: 5
sidebar_label: Cryptographic Primitives
---

# Cryptographic Primitives

The Ika SDK supports a variety of cryptographic primitives for creating and managing dWallets. This guide provides a comprehensive reference for supported curves, signature algorithms, and hash schemes, along with their valid combinations.

## Overview

The SDK provides three main categories of cryptographic primitives:

- **Curves**: The elliptic curves used for key generation
- **Signature Algorithms**: The cryptographic signature schemes
- **Hash Schemes**: The hashing algorithms used before signing

Not all combinations are valid. Each signature algorithm is tied to a specific curve and supports specific hash schemes.

## Supported Curves

The Ika SDK supports four elliptic curves:

### `Curve.SECP256K1`

The secp256k1 curve, widely used in blockchain applications.

- **Used by**: Bitcoin, Ethereum
- **Signature Algorithms**: ECDSASecp256k1, Taproot
- **Key Size**: 256 bits

```typescript
import { Curve } from '@dwallet-network/dwallet.js';

const curve = Curve.SECP256K1;
```

### `Curve.SECP256R1`

The secp256r1 curve (also known as P-256 or prime256v1), standardized by NIST.

- **Used by**: WebAuthn, Apple Secure Enclave, many enterprise systems
- **Signature Algorithms**: ECDSASecp256r1
- **Key Size**: 256 bits

```typescript
const curve = Curve.SECP256R1;
```

### `Curve.ED25519`

The Ed25519 curve, designed for high performance and security.

- **Used by**: Solana, many modern cryptographic systems
- **Signature Algorithms**: EdDSA
- **Key Size**: 256 bits

```typescript
const curve = Curve.ED25519;
```

### `Curve.RISTRETTO`

The Ristretto group, built on top of Curve25519 to provide a prime-order group.

- **Used by**: Polkadot, Substrate-based chains
- **Signature Algorithms**: SchnorrkelSubstrate
- **Key Size**: 256 bits

```typescript
const curve = Curve.RISTRETTO;
```

## Supported Signature Algorithms

The SDK supports five signature algorithms:

### `SignatureAlgorithm.ECDSASecp256k1`

Elliptic Curve Digital Signature Algorithm using the secp256k1 curve.

- **Curve**: `Curve.SECP256K1`
- **Supported Hashes**: `KECCAK256`, `SHA256`, `DoubleSHA256`
- **Use Cases**: Bitcoin transactions, Ethereum transactions

```typescript
import { Hash, SignatureAlgorithm } from '@dwallet-network/dwallet.js';

const signatureAlgorithm = SignatureAlgorithm.ECDSASecp256k1;
const hash = Hash.KECCAK256; // or Hash.SHA256, Hash.DoubleSHA256
```

### `SignatureAlgorithm.Taproot`

Schnorr signatures as specified in Bitcoin's Taproot upgrade (BIP-340/341/342).

- **Curve**: `Curve.SECP256K1`
- **Supported Hashes**: `SHA256` only
- **Use Cases**: Bitcoin Taproot transactions

```typescript
const signatureAlgorithm = SignatureAlgorithm.Taproot;
const hash = Hash.SHA256; // SHA256 is the only valid hash for Taproot
```

### `SignatureAlgorithm.ECDSASecp256r1`

Elliptic Curve Digital Signature Algorithm using the secp256r1 (P-256) curve.

- **Curve**: `Curve.SECP256R1`
- **Supported Hashes**: `SHA256`
- **Use Cases**: WebAuthn, enterprise applications, Apple devices

```typescript
const signatureAlgorithm = SignatureAlgorithm.ECDSASecp256r1;
const hash = Hash.SHA256; // SHA256 is the only valid hash for ECDSASecp256r1
```

### `SignatureAlgorithm.EdDSA`

Edwards-curve Digital Signature Algorithm using the Ed25519 curve.

- **Curve**: `Curve.ED25519`
- **Supported Hashes**: `SHA512` only
- **Use Cases**: Solana transactions, modern cryptographic systems

```typescript
const signatureAlgorithm = SignatureAlgorithm.EdDSA;
const hash = Hash.SHA512; // SHA512 is the only valid hash for EdDSA
```

### `SignatureAlgorithm.SchnorrkelSubstrate`

Schnorr signatures using the Ristretto group, as implemented in Substrate.

- **Curve**: `Curve.RISTRETTO`
- **Supported Hashes**: `Merlin` only
- **Use Cases**: Polkadot, Substrate-based blockchain transactions

```typescript
const signatureAlgorithm = SignatureAlgorithm.SchnorrkelSubstrate;
const hash = Hash.Merlin; // Merlin is the only valid hash for SchnorrkelSubstrate
```

## Supported Hash Schemes

The SDK supports five hash schemes:

### `Hash.KECCAK256`

KECCAK-256, also known as SHA-3.

- **Compatible with**: `ECDSASecp256k1`
- **Output Size**: 256 bits
- **Primary Use**: Ethereum transactions

```typescript
const hash = Hash.KECCAK256;
```

### `Hash.SHA256`

SHA-256, part of the SHA-2 family.

- **Compatible with**: `ECDSASecp256k1`, `Taproot`, `ECDSASecp256r1`
- **Output Size**: 256 bits
- **Primary Use**: Bitcoin transactions, general purpose signing

```typescript
const hash = Hash.SHA256;
```

### `Hash.DoubleSHA256`

Double SHA-256: h(x) = SHA256(SHA256(x)).

- **Compatible with**: `ECDSASecp256k1`
- **Output Size**: 256 bits
- **Primary Use**: Legacy Bitcoin transactions

```typescript
const hash = Hash.DoubleSHA256;
```

### `Hash.SHA512`

SHA-512, part of the SHA-2 family.

- **Compatible with**: `EdDSA`
- **Output Size**: 512 bits
- **Primary Use**: EdDSA signatures (Solana, etc.)

```typescript
const hash = Hash.SHA512;
```

### `Hash.Merlin`

Merlin, a STROBE-based transcript construction protocol.

- **Compatible with**: `SchnorrkelSubstrate`
- **Primary Use**: Substrate-based chains (Polkadot, etc.)

```typescript
const hash = Hash.Merlin;
```

## Best Practices

1. **Choose the Right Curve**: Select the curve based on your target blockchain or application:

   - Use `SECP256K1` for Bitcoin and Ethereum
   - Use `SECP256R1` for WebAuthn and enterprise applications
   - Use `ED25519` for Solana and high-performance applications
   - Use `RISTRETTO` for Polkadot and Substrate chains

2. **Use Appropriate Hash Schemes**: Each blockchain expects signatures with specific hash schemes:

   - Ethereum requires `KECCAK256`
   - Bitcoin Legacy requires `DoubleSHA256`
   - Bitcoin Taproot requires `SHA256`
   - Most other applications use `SHA256`

3. **Validate Before Signing**: Always ensure your combination of curve, signature algorithm, and hash scheme is valid before attempting to sign.

## Related Documentation

- [Zero-Trust dWallet](./ika-transaction/zero-trust.md) - Learn about creating and using zero-trust dWallets
- [Presign](./ika-transaction/presign.md) - Understand presign operations
- [User Share Encryption Keys](./user-share-encryption-keys.md) - Learn about encryption key management

## Additional Resources

For more details on the cryptographic implementations, refer to:

- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) - Schnorr Signatures for secp256k1 (Taproot)
- [RFC 8032](https://tools.ietf.org/html/rfc8032) - Edwards-Curve Digital Signature Algorithm (EdDSA)
- [SEC 2](https://www.secg.org/sec2-v2.pdf) - Recommended Elliptic Curve Domain Parameters
- [Ristretto](https://ristretto.group/) - The Ristretto Group
