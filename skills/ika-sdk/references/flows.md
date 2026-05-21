# End-to-End Flows

Complete flows for every dWallet operation type.

## Prerequisites (All Flows)

```typescript
import {
	createRandomSessionIdentifier,
	createUserSignMessageWithPublicOutput,
	Curve,
	getNetworkConfig,
	Hash,
	IkaClient,
	IkaTransaction,
	parseSignatureFromSignOutput,
	prepareDKGAsync,
	prepareImportedKeyDWalletVerification,
	publicKeyFromDWalletOutput,
	SignatureAlgorithm,
	UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Transaction } from '@mysten/sui/transactions';

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
const networkKey = await ikaClient.getLatestNetworkEncryptionKey();
```

---

## Flow 1: Shared dWallet (Full Lifecycle)

Most common flow. Network signs autonomously - no user participation at sign time.

### Step 1: Create Encryption Keys

```typescript
const keys = await UserShareEncryptionKeys.fromRootSeedKey(
	new TextEncoder().encode('your-deterministic-seed'),
	Curve.SECP256K1,
);
```

### Step 2: Register Encryption Key

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.registerEncryptionKey({ curve: Curve.SECP256K1 });
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### Step 3: DKG (Create dWallet with Public Share)

```typescript
const sessionIdBytes = createRandomSessionIdentifier();
const dkgData = await prepareDKGAsync(
	ikaClient,
	Curve.SECP256K1,
	keys,
	sessionIdBytes,
	senderAddress,
);

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
const [dwalletCap, signId] = await ikaTx.requestDWalletDKGWithPublicUserShare({
	publicKeyShareAndProof: dkgData.userDKGMessage,
	publicUserSecretKeyShare: dkgData.userSecretKeyShare,
	userPublicOutput: dkgData.userPublicOutput,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
	sessionIdentifier: sessionId,
	dwalletNetworkEncryptionKeyId: networkKey.id,
	curve: Curve.SECP256K1,
});
const result = await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
// Extract dwalletId from result events
```

### Step 4: Wait for DKG Completion & Get Public Key

```typescript
const dWallet = await ikaClient.getDWalletInParticularState(dwalletId, 'Active');
const publicKey = await publicKeyFromDWalletOutput(
	Curve.SECP256K1,
	Uint8Array.from(dWallet.state.Active.public_output),
);
// publicKey → derive ETH/BTC address
```

### Step 5: Request Presign

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
const presignRef = ikaTx.requestGlobalPresign({
	dwalletNetworkEncryptionKeyId: networkKey.id,
	curve: Curve.SECP256K1,
	signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
});
const result = await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
// Extract presignId from result events
```

### Step 6: Create User Signature & Request Sign

```typescript
const presign = await ikaClient.getPresignInParticularState(presignId, 'Completed');
const pp = await ikaClient.getProtocolPublicParameters(dWallet);

const msgSig = await createUserSignMessageWithPublicOutput(
	pp,
	Uint8Array.from(dWallet.state.Active.public_output),
	Uint8Array.from(dWallet.public_user_secret_key_share),
	Uint8Array.from(presign.state.Completed.presign),
	message,
	Hash.KECCAK256,
	SignatureAlgorithm.ECDSASecp256k1,
	Curve.SECP256K1,
);

const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
const signRef = await ikaTx.requestSign({
	dWallet,
	messageApproval: ikaTx.approveMessage({
		dWalletCap,
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hashScheme: Hash.KECCAK256,
		message,
	}),
	hashScheme: Hash.KECCAK256,
	verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
	presign,
	message,
	signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### Step 7: Retrieve Final Signature

```typescript
const sign = await ikaClient.getSignInParticularState(
	signId,
	Curve.SECP256K1,
	SignatureAlgorithm.ECDSASecp256k1,
	'Completed',
);
// sign.state.Completed.signature is already parsed, ready for broadcast
```

---

## Flow 2: Zero-Trust dWallet

User must participate in every signing operation. Maximum security.

### DKG (uses requestDWalletDKG instead of WithPublicUserShare)

```typescript
const [dwalletCap, signId] = await ikaTx.requestDWalletDKG({
	dkgRequestInput: dkgData,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
	sessionIdentifier: sessionId,
	dwalletNetworkEncryptionKeyId: networkKey.id,
	curve: Curve.SECP256K1,
});
```

### Accept Encrypted Share (required for zero-trust)

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.acceptEncryptedUserShare({
	dWallet,
	userPublicOutput: dkgData.userPublicOutput,
	encryptedUserSecretKeyShareId: encShareId,
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### Decrypt User Share (for signing)

```typescript
const encShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
	encShareId,
	'KeyHolderSigned',
);
const pp = await ikaClient.getProtocolPublicParameters(dWallet);
const { secretShare, verifiedPublicOutput } = await keys.decryptUserShare(dWallet, encShare, pp);
// Use secretShare in createUserSignMessageWithPublicOutput
```

### Sign (pass secretShare or encryptedUserSecretKeyShare)

```typescript
await ikaTx.requestSign({
    dWallet,
    messageApproval: ikaTx.approveMessage({ ... }),
    hashScheme: Hash.KECCAK256,
    verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
    presign, message,
    signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
    encryptedUserSecretKeyShare: encShare,  // OR secretShare: decryptedShare
    ikaCoin: ..., suiCoin: ...,
});
```

---

## Flow 3: Imported Key dWallet

Import an existing private key into the Ika network.

### Prepare Import Data

```typescript
const sessionIdBytes = createRandomSessionIdentifier();
const importData = await prepareImportedKeyDWalletVerification(
	ikaClient,
	Curve.SECP256K1,
	sessionIdBytes,
	senderAddress,
	keys,
	privateKey,
);
// importData: { userPublicOutput, userMessage, encryptedUserShareAndProof }
```

### Request Import Verification

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);
await ikaTx.requestImportedKeyDWalletVerification({
	importDWalletVerificationRequestInput: importData,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
	sessionIdentifier: sessionId,
	signerPublicKey: keys.getSigningPublicKeyBytes(),
	curve: Curve.SECP256K1,
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### Sign with Imported Key

```typescript
await ikaTx.requestSignWithImportedKey({
    dWallet: importedKeyDWallet,
    importedKeyMessageApproval: ikaTx.approveImportedKeyMessage({
        dWalletCap: activeDWallet.dwallet_cap_id, curve: Curve.SECP256K1,
        signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
        hashScheme: Hash.KECCAK256, message,
    }),
    hashScheme: Hash.KECCAK256,
    verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
    presign, message,
    signatureScheme: SignatureAlgorithm.ECDSASecp256k1,
    ikaCoin: ..., suiCoin: ...,
});
```

---

## Flow 4: Transfer dWallet

Re-encrypt user share for a different address.

### Sender: Re-Encrypt Share

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: senderKeys });

// With encrypted share (auto-decrypts internally)
await ikaTx.requestReEncryptUserShareFor({
    dWallet,
    sourceEncryptedUserSecretKeyShare: encShare,
    destinationEncryptionKeyAddress: recipientAddress,
    ikaCoin: ..., suiCoin: ...,
});

// OR with decrypted secret share
await ikaTx.requestReEncryptUserShareFor({
    dWallet,
    sourceSecretShare: decryptedSecretShare,
    sourceEncryptedUserSecretKeyShare: encShare,
    destinationEncryptionKeyAddress: recipientAddress,
    ikaCoin: ..., suiCoin: ...,
});

await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

### Recipient: Accept Transferred Share

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({
	ikaClient,
	transaction: tx,
	userShareEncryptionKeys: recipientKeys,
});
await ikaTx.acceptEncryptedUserShare({
	dWallet,
	sourceEncryptionKey: senderEncryptionKey, // MUST be known out-of-band, not fetched
	sourceEncryptedUserSecretKeyShare: sourceEncShare,
	destinationEncryptedUserSecretKeyShare: destEncShare,
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

**Security**: `sourceEncryptionKey` must be known to the recipient beforehand (not fetched from network) to prevent MITM.

---

## Flow 5: Future Sign (Two-Phase Signing)

Compute partial signature first, approve message later. Useful for DAOs/governance where approval is separate from computation.

### Phase 1: Request Future Sign (off-chain computation)

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
const futureSignRef = await ikaTx.requestFutureSign({
	dWallet,
	hashScheme: Hash.SHA256,
	verifiedPresignCap: ikaTx.verifyPresignCap({ presign }),
	presign,
	message,
	signatureScheme: SignatureAlgorithm.Taproot,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
});
const result = await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
// Extract partialUserSignatureId from events
```

### Wait for Partial Signature

```typescript
const partialSig = await ikaClient.getPartialUserSignatureInParticularState(
	partialUserSignatureId,
	'NetworkVerificationCompleted',
);
```

### Phase 2: Complete Sign (with approval)

```typescript
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx });
const signRef = ikaTx.futureSign({
    partialUserSignatureCap: partialSig.cap_id,
    messageApproval: ikaTx.approveMessage({
        dWalletCap, curve: Curve.SECP256K1,
        signatureAlgorithm: SignatureAlgorithm.Taproot,
        hashScheme: Hash.SHA256, message,
    }),
    ikaCoin: ..., suiCoin: ...,
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

---

## Flow 6: Convert Zero-Trust to Shared

```typescript
// Must have saved userSecretKeyShare from original DKG
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient, transaction: tx, userShareEncryptionKeys: keys });
ikaTx.makeDWalletUserSecretKeySharesPublic({
	dWallet: zeroTrustDWallet,
	secretShare: savedUserSecretKeyShare,
	ikaCoin: tx.splitCoins(tx.object(ikaCoinId), [1_000_000]),
	suiCoin: tx.splitCoins(tx.gas, [1_000_000]),
});
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer: keypair });
```

---

## Chain-Specific Configurations

| Target Chain    | Curve     | SignatureAlgorithm  | Hash         | Notes           |
| --------------- | --------- | ------------------- | ------------ | --------------- |
| Ethereum        | SECP256K1 | ECDSASecp256k1      | KECCAK256    | Standard ECDSA  |
| Bitcoin Legacy  | SECP256K1 | ECDSASecp256k1      | DoubleSHA256 | P2PKH/P2SH      |
| Bitcoin Taproot | SECP256K1 | Taproot             | SHA256       | BIP-340 Schnorr |
| Solana          | ED25519   | EdDSA               | SHA512       | Ed25519 signing |
| WebAuthn/P-256  | SECP256R1 | ECDSASecp256r1      | SHA256       | Passkeys        |
| Substrate       | RISTRETTO | SchnorrkelSubstrate | Merlin       | Polkadot/Kusama |

---

## KeySpring Pattern

Derive cross-chain wallet from any authentication source.

```typescript
// Any deterministic seed source works:
// - Wallet signature: await wallet.signMessage('ika-keyspring-v1')
// - WebAuthn PRF: prf.results.first (from navigator.credentials.get)
// - KDF output: any 32+ byte deterministic secret

const seed = await wallet.signMessage('ika-keyspring-v1');
const keys = await UserShareEncryptionKeys.fromRootSeedKey(new Uint8Array(seed), Curve.SECP256K1);
// Proceed with DKG → the resulting dWallet public key maps to an ETH address
```

Key insight: `fromRootSeedKey` is deterministic. Same seed always produces same keys. The dWallet's public key deterministically maps to addresses on target chains.

---

## Plugin Layer Flows

The flows above use the bare SDK. The plugin layer (`@ika.xyz/plugins`)
is the recommended path for most applications. It wraps the same
operations with chain-aware ergonomics: address derivation, preimage
construction, signature assembly, and broadcasting.

### Plugin host setup

```typescript
import { Curve } from '@ika.xyz/sdk';
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher, defaultEsploraUrl } from '@ika.xyz/plugins/bitcoin/publisher';

const ika = await new IkaClient()
    .use(suiSource({ network: 'testnet', signer, suiClient }))
    .use(btc())
    .use(bitcoinPublisher({ apiBaseUrl: defaultEsploraUrl('testnet') }));
```

### Shared dWallet to Bitcoin (one-shot)

```typescript
const dWallet = await ika.sui.createDWallet({
    kind: 'shared',
    curve: Curve.SECP256K1,
});

const address = await dWallet.bitcoin.getAddress({ mode: 'p2wpkh', network: 'testnet' });

// Build a PSBT against `address` ...

const signed = await dWallet.bitcoin.sign({
    kind: 'psbt',
    psbt,
    inputIndex: 0,
    mode: 'p2wpkh',
});

const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

### Zero-trust dWallet (USEK threaded through source)

```typescript
const keys = await UserShareEncryptionKeys.fromRootSeedKey(seed, Curve.SECP256K1);

const ika = await new IkaClient()
    .use(suiSource({
        network: 'testnet',
        signer,
        suiClient,
        userShareEncryptionKeys: keys,
    }))
    .use(eth())
    .use(ethPublisher({ chain: sepolia, url: process.env.SEPOLIA_RPC! }));

// register encryption key once per (user, curve)
const tx = new Transaction();
const ikaTx = new IkaTransaction({ ikaClient: ika.sui.client, transaction: tx, userShareEncryptionKeys: keys });
await ikaTx.registerEncryptionKey({ curve: Curve.SECP256K1 });
await suiClient.core.signAndExecuteTransaction({ transaction: tx, signer });

// DKG. The source automatically encrypts the user share under the USEK,
// submits the on-chain DKG request, polls, and signs the acceptance.
const dWallet = await ika.sui.createDWallet({
    kind: 'zero-trust',
    curve: Curve.SECP256K1,
});

const signed = await dWallet.ethereum.sign({ kind: 'transaction', tx: { type: 'eip1559', ... } });
const txHash = await ika.publish({ chain: 'ethereum', payload: signed.payload });
```

### Two-phase signing (prepareSign / assembleSign)

```typescript
// Phase 1: derive preimage and plan
const { prep, preimage, plan } = await dWallet.bitcoin.prepareSign({
    kind: 'psbt',
    psbt,
    inputIndex: 0,
    mode: 'p2tr-script',
});

// Custom gating: Move multisig vote, sponsored relay, persistence, ...
const signature = await yourCustomFlow(preimage, plan);

// Phase 2: assemble with the signature
const signed = await dWallet.bitcoin.assembleSign(prep, signature);
const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

`prep` is what the destination needs to reassemble the signed payload.
`preimage` is what the MPC consumes. `plan` is `{ curve,
signatureAlgorithm, hash }`.

### Future-sign with a Move multisig

```typescript
// Phase 1: user authorizes a specific message and transfers cap to contract.
const { prep, preimage, plan } = await dWallet.bitcoin.prepareSign({ ... });
const presign = await ika.sui.requestGlobalPresign({
    curve: plan.curve,
    signatureAlgorithm: plan.signatureAlgorithm,
});

const { capId, partialSignatureId } = await ika.sui.requestFutureSign({
    dWallet,
    message: preimage,
    signatureAlgorithm: plan.signatureAlgorithm,
    hash: plan.hash,
    presign,
    capRecipient: multisigContractAddress,
});

// Persist prep, capId, partialSignatureId.

// Phase 2: the multisig contract gates the redemption. Once quorum:
//   coordinator::request_sign_with_partial_user_signature(coordinator, cap, approval, ctx)
// is called from inside Move. The watcher then:
const sign = await ika.sui.client.getSignInParticularState(
    signId,
    plan.curve,
    plan.signatureAlgorithm,
    'Completed',
);
const signed = await dWallet.bitcoin.assembleSign(prep, sign.state.Completed.signature);
const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

The coordinator binds Phase 1 to `(dwallet, message, sig_algo,
hash_scheme)`. Phase 2 must present an approval matching all four
fields exactly. A cap holder cannot redeem against a different
message.

### Backend funds DKG, user signs

```typescript
// Backend, holding a funding signer:
const dWallet = await ika.sui.createDWallet({
    kind: 'zero-trust',
    curve: Curve.SECP256K1,
    capRecipient: userSuiAddress,
});

// Later, user side:
const userView = ika.sui.withSigner(userSigner, {
    userShareEncryptionKeys: userKeys, // explicit on multi-tenant backends
});

const signed = await dWallet.ethereum.sign({ kind: 'transaction', tx });
```

`capRecipient` routes the dWallet capability without changing who
submits the DKG transaction. `withSigner` rebinds the source for
subsequent operations.

### Hash-application invariant

Across every plugin destination:

- The destination builds the chain-specific preimage.
- The destination passes `{ preimage, hash, signatureAlgorithm,
  curve }` to the source's `signMessage`.
- The MPC applies the hash internally and signs.
- The destination assembles the signed payload from the returned 64-byte
  signature.

The client never pre-hashes before calling
`createUserSignMessageWithPublicOutput`. The single exception is Sui:
the plugin pre-digests to 32-byte blake2b client-side because Sui's
signature scheme treats the digest itself as the input to the inner
hash. Both the plugin's pre-digest and the MPC's inner hash form the
preimage that Sui validators replicate.

### ECDSA low-S normalization

The Bitcoin and Ethereum destinations re-normalize ECDSA signatures
to low-S before assembly. The live MPC may or may not emit canonical
signatures; the plugins do not depend on that. Consumers building
their own chain support should normalize the same way.

### Bitcoin Taproot constraint

P2TR support is script-path only. The plugin builds addresses with a
NUMS internal pubkey so key-path spending is provably impossible by
construction. Spending always reveals the
`OP_PUSHBYTES_32 <xOnly> OP_CHECKSIG` leaf and signs with the Schnorr
key. This is a permanent property of the MPC scheme; the protocol
cannot tweak the MPC key.
