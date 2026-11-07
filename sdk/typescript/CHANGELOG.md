# @ika.xyz/sdk

## 0.6.0

### Minor Changes

- Add `createClassGroupsKeypairV2` and `UserShareEncryptionKeys.fromRootSeedKeyV2`, which derive
  class-groups encryption keys with portable sampling that matches the native Rust implementation.
  Use them for all new registrations. `createClassGroupsKeypair` and
  `UserShareEncryptionKeys.fromRootSeedKey` are deprecated but unchanged, so existing keys still
  recover byte-for-byte; to move an existing registration to the portable derivation, register fresh
  keys from `fromRootSeedKeyV2`.

### Patch Changes

- c3d5c9d: Fix `requestPresign` refusing ECDSA presigns for V1 zero-trust secp256k1 dWallets and
  allowing them for V2 ones: an operator-precedence bug made the dWallet version check read the
  version one too low.
- c3d5c9d: Fix the `IkaClient` network encryption key cache: a fetch that fails partway no longer
  leaves a partial key list for later calls, callers wait for an in-progress fetch instead of
  reading its cache, and `getLatestNetworkEncryptionKey` returns the highest-epoch key.
- Updated dependencies
  - @ika.xyz/ika-wasm@0.4.0

## 0.5.0

### Minor Changes

- 7d10043: Release 0.5.0 — repairs the published SDK against the live networks, and renames
  `SchnorrkelSubstrate`.

  **Breaking**

  - `SignatureAlgorithm.SchnorrkelSubstrate` is renamed to `SignatureAlgorithm.Schnorrkel`. Both the
    enum key AND its runtime string value changed from `'SchnorrkelSubstrate'` to `'Schnorrkel'`.
    Update every reference; a value persisted or transmitted as `'SchnorrkelSubstrate'` is no longer
    recognized.

  **Required — `0.4.x` is broken against mainnet and testnet today**

  - The bundled WASM is rebuilt to parse the current network reconfiguration outputs. Both networks
    now write V4-tagged reconfiguration outputs each epoch; the WASM shipped in
    `@ika.xyz/ika-wasm@0.2.x` understands only V1/V2 and throws
    ``invalid value: integer `3`, expected variant index 0 <= i < 2`` from
    `getProtocolPublicParameters`. Plain object reads still succeed, so the failure surfaces only
    once a dApp reaches an actual dWallet operation. Every dApp on `0.4.x` is affected and must
    upgrade.

  **Transport**

  - Public Sui fullnodes no longer serve JSON-RPC. `IkaClient` accepts any `ClientWithCoreApi`
    implementation and needs no change, but the documented setup now builds a `SuiGrpcClient`; a
    `SuiJsonRpcClient` pointed at a public fullnode fails with `Method not found`. JSON-RPC stays
    valid for a localnet or a private fullnode.

  **Behavior change**

  - The default poll timeout for the `*InParticularState` waiters increased from 30s to 600s. Flows
    that relied on the old 30s default failing fast will now wait longer before timing out; pass an
    explicit timeout to restore the previous behavior.
  - Requesting the secp256k1 protocol public parameters from a network key that has no
    reconfiguration output yet now returns an error instead of silently succeeding. No deployed
    network key is in this state; the reconfiguration-output path that live keys use is unaffected.

### Patch Changes

- Updated dependencies [7d10043]
  - @ika.xyz/ika-wasm@0.3.0
