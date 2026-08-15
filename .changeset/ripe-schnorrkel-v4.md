---
'@ika.xyz/sdk': minor
'@ika.xyz/ika-wasm': minor
---

Release 0.5.0 — repairs the published SDK against the live networks, and renames `SchnorrkelSubstrate`.

**Breaking**

- `SignatureAlgorithm.SchnorrkelSubstrate` is renamed to `SignatureAlgorithm.Schnorrkel`. Both the enum key AND its runtime string value changed from `'SchnorrkelSubstrate'` to `'Schnorrkel'`. Update every reference; a value persisted or transmitted as `'SchnorrkelSubstrate'` is no longer recognized.

**Required — `0.4.x` is broken against mainnet and testnet today**

- The bundled WASM is rebuilt to parse the current network reconfiguration outputs. Both networks now write V4-tagged reconfiguration outputs each epoch; the WASM shipped in `@ika.xyz/ika-wasm@0.2.x` understands only V1/V2 and throws ``invalid value: integer `3`, expected variant index 0 <= i < 2`` from `getProtocolPublicParameters`. Plain object reads still succeed, so the failure surfaces only once a dApp reaches an actual dWallet operation. Every dApp on `0.4.x` is affected and must upgrade.

**Transport**

- Public Sui fullnodes no longer serve JSON-RPC. `IkaClient` accepts any `ClientWithCoreApi` implementation and needs no change, but the documented setup now builds a `SuiGrpcClient`; a `SuiJsonRpcClient` pointed at a public fullnode fails with `Method not found`. JSON-RPC stays valid for a localnet or a private fullnode.

**Behavior change**

- The default poll timeout for the `*InParticularState` waiters increased from 30s to 600s. Flows that relied on the old 30s default failing fast will now wait longer before timing out; pass an explicit timeout to restore the previous behavior.
- Requesting the secp256k1 protocol public parameters from a network key that has no reconfiguration output yet now returns an error instead of silently succeeding. No deployed network key is in this state; the reconfiguration-output path that live keys use is unaffected.
