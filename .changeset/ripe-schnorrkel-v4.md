---
'@ika.xyz/sdk': minor
'@ika.xyz/ika-wasm': minor
---

Release 0.5.0 — protocol-v4 readiness and the `SchnorrkelSubstrate` rename.

**Breaking**

- `SignatureAlgorithm.SchnorrkelSubstrate` is renamed to `SignatureAlgorithm.Schnorrkel`. Both the enum key AND its runtime string value changed from `'SchnorrkelSubstrate'` to `'Schnorrkel'`. Update every reference; a value persisted or transmitted as `'SchnorrkelSubstrate'` is no longer recognized.

**Required before protocol v4 activates**

- The bundled WASM is rebuilt to parse V3-tagged network reconfiguration outputs. When the network advances to protocol v4, validators write V3-tagged reconfiguration outputs each epoch; the WASM shipped in `@ika.xyz/ika-wasm@0.2.x` only understands V1/V2 and throws a BCS "unknown variant" error from `getProtocolPublicParameters`. dApps must be on this release before v4 activates on their network, or user-side dWallet operations stop until they upgrade.

**Behavior change**

- The default poll timeout for the `*InParticularState` waiters increased from 30s to 600s. Flows that relied on the old 30s default failing fast will now wait longer before timing out; pass an explicit timeout to restore the previous behavior.
- Requesting the secp256k1 protocol public parameters from a network key that has no reconfiguration output yet now returns an error instead of silently succeeding. No deployed network key is in this state; the reconfiguration-output path that live keys use is unaffected.
