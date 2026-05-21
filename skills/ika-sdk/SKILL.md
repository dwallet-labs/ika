---
name: ika-sdk
version: 2.0.0
description: Guide for building with the Ika TypeScript SDK and plugin layer (@ika.xyz/sdk and @ika.xyz/plugins) on Mysten Sui v2. Use when creating dWallets, signing cross-chain transactions, managing encryption keys, or integrating with the Ika network from TypeScript/JavaScript. Triggers on tasks involving @ika.xyz/sdk, @ika.xyz/plugins, dWallet operations, IkaClient, IkaTransaction, source/destination/publisher composition, prepareSign/assembleSign, future-sign, or Ika cross-chain signing.
metadata:
  openclaw:
    requires:
      bins:
        - node
    emoji: '⚡'
    homepage: 'https://ika.xyz'
    tags:
      - typescript
      - sdk
      - plugins
      - dwallet
      - sui
      - cross-chain
      - signing
---

# Ika TypeScript SDK and Plugin Layer

Build cross-chain signing applications on Sui with `@ika.xyz/sdk` (the
protocol client and Sui transaction builder) and `@ika.xyz/plugins`
(chain-aware ergonomics on top).

For most applications the plugin layer is the recommended entry
point. Drop down to the bare SDK only when you need Move-call-level
control.

## References

- `references/api-reference.md`: complete API for IkaClient,
  IkaTransaction, cryptography helpers, UserShareEncryptionKeys,
  and the plugin layer.
- `references/flows.md`: end-to-end flows. Shared dWallet,
  zero-trust, imported key, transfer, future-sign, prepareSign /
  assembleSign, backend-funds-user-signs.
- `references/types-and-validation.md`: type system, enums,
  curve/sig/hash validation, state narrowing.

## Two layers

```
@ika.xyz/sdk       Protocol client + transaction builder + crypto helpers
@ika.xyz/plugins   source / destination / publisher composition
```

The plugin layer is a thin wrapper. Nothing in it is hidden from you;
you can read every Move call it emits.

## Install

```bash
pnpm add @ika.xyz/sdk @ika.xyz/plugins @mysten/sui
# Plus per-chain peer deps (all optional):
pnpm add bitcoinjs-lib @bitcoinerlab/secp256k1   # bitcoin
pnpm add viem                                     # ethereum
pnpm add @solana/web3.js                          # solana
```

Node 18 or later.

## Plugin-layer quickstart (recommended)

```typescript
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Curve } from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher, defaultEsploraUrl } from '@ika.xyz/plugins/bitcoin/publisher';

const suiClient = new SuiJsonRpcClient({
	url: getJsonRpcFullnodeUrl('testnet'),
	network: 'testnet',
});

const signer = Ed25519Keypair.fromSecretKey(process.env.SUI_PRIVATE_KEY!);

const ika = await new IkaClient()
	.use(suiSource({ network: 'testnet', signer, suiClient }))
	.use(btc())
	.use(bitcoinPublisher({ apiBaseUrl: defaultEsploraUrl('testnet') }));

// Chain-led sugar (recommended for most flows):
const dWallet = await ika.bitcoin.createDWallet({ kind: 'shared' });

// Equivalent source-level call when you need full DKG-input control:
//   await ika.sui.createDWallet({ kind: 'shared', curve: Curve.SECP256K1 })

const address = await dWallet.bitcoin.getAddress({
	mode: 'p2wpkh',
	network: 'testnet',
});

// Build a PSBT, then:
const signed = await dWallet.bitcoin.sign({ kind: 'psbt', psbt, inputIndex: 0, mode: 'p2wpkh' });
const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

## Three plugin roles

| Role | Purpose | Today's plugins |
|------|---------|-----------------|
| **Source** | Manages dWallets on the coordination chain. DKG, presign, sign, future-sign. | `suiSource` |
| **Destination** | Knows the wire format of a target chain. Builds the chain-specific preimage at sign time and assembles the signed payload. | `btc`, `eth`, `solana`, `sui` |
| **Publisher** | Broadcasts to the target chain. | `bitcoinPublisher`, `ethPublisher`, `solanaDevnet`/`solanaMainnet`/`solanaPublisher`, `suiPublisher` |

Compose them on one `IkaClient`. One source. Any number of
destinations. Any number of publishers.

## prepareSign / assembleSign

Every destination exposes two-phase signing:

```typescript
const { prep, preimage, plan } = await dWallet.bitcoin.prepareSign({
	kind: 'psbt',
	psbt,
	inputIndex: 0,
	mode: 'p2tr-script',
});

// Custom gating sits here: Move multisig, sponsored relay, future-sign, ...

const signed = await dWallet.bitcoin.assembleSign(prep, signature);
```

`prep` is what `assembleSign` reads. `preimage` is the bytes that go to
the MPC. `plan` is `{ curve, signatureAlgorithm, hash }`.

Use the two-phase form when the signature does not flow through the
source's normal `signMessage` path. Use the one-shot
`dWallet.<chain>.sign(input)` for everything else.

## Future-sign

Phase 1 issues a partial cap; Phase 2 redeems it.

```typescript
const { capId, partialSignatureId } = await ika.sui.requestFutureSign({
	dWallet,
	message,
	signatureAlgorithm: SignatureAlgorithm.Taproot,
	hash: Hash.SHA256,
	presign,
	capRecipient: contractOrUserAddress,
});

// Later, after gating:
const { signId } = await ika.sui.completeFutureSign({
	dWallet,
	partialUserSignatureCap: capId,
	message,
	signatureAlgorithm: SignatureAlgorithm.Taproot,
	hash: Hash.SHA256,
	presign,
});
```

The on-chain coordinator binds Phase 1 to `(dwallet, message,
signatureAlgorithm, hash_scheme)`. Phase 2 must present an approval
that matches all four fields exactly. A cap holder cannot redeem
against a different message.

## withSigner and capRecipient

For "backend funds DKG, user signs" deployments:

```typescript
// Backend side:
const dWallet = await ika.sui.createDWallet({
	kind: 'zero-trust',
	curve: Curve.SECP256K1,
	capRecipient: userSuiAddress,
});

// Later, user side:
const userView = ika.sui.withSigner(userSigner, {
	userShareEncryptionKeys: userKeys, // recommended on multi-tenant backends
});

await userView.someOperation(...);
```

`capRecipient` routes the dWallet capability to a different address
than the DKG submitter. `withSigner` rebinds the source surface for
subsequent operations.

If you build the outer source with `userShareEncryptionKeys`, the
default `withSigner` call inherits that USEK. On multi-tenant
backends, always supply the per-user USEK explicitly via the
`withSigner` options object to avoid using the wrong USEK at sign
time.

## Enums

```typescript
import { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';

// Curves (one per dWallet)
Curve.SECP256K1; // Bitcoin, Ethereum
Curve.SECP256R1; // WebAuthn, P-256
Curve.ED25519;   // Solana, Sui (default)
Curve.RISTRETTO; // Substrate / Schnorrkel

// Signature algorithms
SignatureAlgorithm.ECDSASecp256k1;
SignatureAlgorithm.Taproot;            // BIP-340 Schnorr on secp256k1
SignatureAlgorithm.ECDSASecp256r1;
SignatureAlgorithm.EdDSA;
SignatureAlgorithm.SchnorrkelSubstrate;

// Hashes
Hash.KECCAK256;
Hash.SHA256;
Hash.DoubleSHA256;
Hash.SHA512;
Hash.Merlin;
```

## Valid combinations

| Chain           | Curve     | SignatureAlgorithm  | Hash         |
| --------------- | --------- | ------------------- | ------------ |
| Ethereum        | SECP256K1 | ECDSASecp256k1      | KECCAK256    |
| Bitcoin Taproot | SECP256K1 | Taproot             | SHA256       |
| Bitcoin Legacy / SegWit | SECP256K1 | ECDSASecp256k1 | DoubleSHA256 |
| Solana          | ED25519   | EdDSA               | SHA512       |
| Sui (Ed25519)   | ED25519   | EdDSA               | SHA512       |
| Sui (secp256k1) | SECP256K1 | ECDSASecp256k1      | SHA256       |
| Sui (secp256r1) | SECP256R1 | ECDSASecp256r1      | SHA256       |
| WebAuthn        | SECP256R1 | ECDSASecp256r1      | SHA256       |
| Substrate       | RISTRETTO | SchnorrkelSubstrate | Merlin       |

## dWallet kinds

| Kind | User share location | Sign-time participants |
|------|---------------------|------------------------|
| `zero-trust` | Encrypted on chain (under USEK) plus plaintext on user device | User + validators |
| `shared` | Plaintext on chain | Validators only |
| `imported-key` | Encrypted on chain (under USEK) plus plaintext on user device | User + validators |
| `imported-key-shared` | Plaintext on chain | Validators only |

`shared` and `imported-key-shared` are irreversible once published; do
not promote to them lightly.

## Cryptographic invariants

The following hold across the implementation. Do not write code that
depends on the opposite.

1. **Class-groups TAHE.** The implementation uses class groups
   exclusively for threshold encryption. No Paillier.
2. **Hash applied inside the MPC.** Plugin destinations build the
   preimage; the network applies the hash scheme. The client never
   pre-hashes before calling `createUserSignMessageWith*`.
3. **ECDSA not guaranteed low-S.** Bitcoin and Ethereum plugins
   normalize defensively. Other consumers should normalize too.
4. **Bitcoin Taproot is script-path only.** No key-path. NUMS
   internal pubkey by construction.
5. **Network public key is stable across reconfigurations.** Only
   validator-side shares rotate.

## Bare-SDK quickstart (full control)

Use this when you need to compose multiple coordinator calls into one
PTB or otherwise drop down past the plugin layer.

### 1. USEK setup (zero-trust / imported-key)

```typescript
const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.registerEncryptionKey({ curve: Curve.SECP256K1 });
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### 2. DKG

```typescript
const sessionIdBytes = createRandomSessionIdentifier();
const dkgData = await prepareDKGAsync(
	ikaClient,
	Curve.SECP256K1,
	keys,
	sessionIdBytes,
	senderAddress,
);
const networkKey = await ikaClient.getLatestNetworkEncryptionKey();

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
const [dWalletCap, signId] = await ikaTx.requestDWalletDKG({
	dkgRequestInput: dkgData,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
	sessionIdentifier: sessionId,
	dwalletNetworkEncryptionKeyId: networkKey.id,
	curve: Curve.SECP256K1,
});
```

### 3. Sign

```typescript
const presign = await ikaClient.getPresignInParticularState(presignId, 'Completed');
const pp = await ikaClient.getProtocolPublicParameters(dWallet);

const msgSig = await createUserSignMessageWithPublicOutput(
	pp,
	Uint8Array.from(dWallet.state.Active.public_output),
	Uint8Array.from(dWallet.public_user_secret_key_share),
	Uint8Array.from(presign.state.Completed.presign),
	message,
	Hash.SHA256,
	SignatureAlgorithm.Taproot,
	Curve.SECP256K1,
);

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.requestSign({
	dWallet,
	messageApproval: ikaTx.approveMessage({
		dWalletCap,
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.Taproot,
		hashScheme: Hash.SHA256,
		message,
	}),
	hashScheme: Hash.SHA256,
	verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
	presign,
	message,
	signatureScheme: SignatureAlgorithm.Taproot,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
});
```

## IkaClient key methods

```typescript
await ikaClient.initialize();

const dWallet = await ikaClient.getDWallet(id);
const dWallet = await ikaClient.getDWalletInParticularState(id, 'Active', { timeout: 60_000 });
const caps = await ikaClient.getOwnedDWalletCaps(address);

const presign = await ikaClient.getPresignInParticularState(id, 'Completed');
const sign = await ikaClient.getSignInParticularState(
	id, Curve.SECP256K1, SignatureAlgorithm.Taproot, 'Completed',
);

const key = await ikaClient.getLatestNetworkEncryptionKey();
const pp = await ikaClient.getProtocolPublicParameters(dWallet);

ikaClient.invalidateCache();
```

All `*InParticularState` methods accept:

```typescript
{
	timeout?: number;          // default 30_000 ms
	interval?: number;         // default 1_000 ms
	maxInterval?: number;      // default 5_000 ms after backoff
	backoffMultiplier?: number;// default 1.5
	signal?: AbortSignal;
}
```

## UserShareEncryptionKeys

```typescript
// Fresh derivation
const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, curve);

// Legacy: for keys registered before the curve-byte fix (non-SECP256K1 only)
const legacyKeys = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(seed, curve);

// Serialize for storage (the variant tag preserves legacy/fixed distinction)
const bytes = keys.toShareEncryptionKeysBytes();
const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(bytes);

keys.getSuiAddress();
keys.getSigningPublicKeyBytes();
keys.encryptionKey;     // class-groups public
keys.decryptionKey;     // class-groups private
keys.curve;
keys.legacyHash;        // true if legacy derivation

await keys.getEncryptionKeySignature();
await keys.getUserOutputSignature(dWallet, userPublicOutput);
await keys.decryptUserShare(dWallet, encShare, pp);
```

`decryptUserShare` verifies four invariants before returning: the
dWallet is Active, the Ed25519 acceptance signature on the public
output verifies, the class-groups decryption succeeds, and the
recovered share is consistent with the public output. If any check
fails, the call throws.

## Plugin imports summary

```typescript
// Plugin host (extends @ika.xyz/sdk):
import { IkaClient } from '@ika.xyz/sdk/plugin';
import type { DWallet, IkaContext, BaseSignResult, SignMessageInput } from '@ika.xyz/sdk/plugin';

// Source
import { suiSource } from '@ika.xyz/plugins/sui/source';
import type { SuiSigner, SuiWalletSigner, SuiDWallet } from '@ika.xyz/plugins/sui/source';

// Destinations
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import { eth } from '@ika.xyz/plugins/ethereum/destination';
import { solana } from '@ika.xyz/plugins/solana/destination';
import { sui } from '@ika.xyz/plugins/sui/destination';

// Publishers
import { bitcoinPublisher, defaultEsploraUrl } from '@ika.xyz/plugins/bitcoin/publisher';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';
import { solanaDevnet, solanaMainnet, solanaPublisher } from '@ika.xyz/plugins/solana/publisher';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
```

## Network config

```typescript
import { getNetworkConfig } from '@ika.xyz/sdk';

const config = getNetworkConfig('testnet'); // or 'mainnet'
```

For localnet, construct an `IkaConfig` from the `ika_config.json` your
local stack writes. See the operator docs for the exact shape.

## Error classes

```typescript
import {
	CacheError,
	IkaClientError,
	InvalidObjectError,
	NetworkError,
	ObjectNotFoundError,
} from '@ika.xyz/sdk';
```

## When not to use this skill

- Pure Move contract work without the SDK: load `ika-move` instead.
- Pure CLI work: load `ika-cli`.
- Operating a validator: load `ika-operator`.

For combined SDK + plugin work, this skill is the right one.
