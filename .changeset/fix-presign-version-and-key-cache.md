---
'@ika.xyz/sdk': patch
---

- Fix `requestPresign` refusing ECDSA presigns for V1 zero-trust secp256k1 dWallets and allowing them for V2 ones: an operator-precedence bug made the dWallet version check read the version one too low.
- Fix the `IkaClient` network encryption key cache: a fetch that fails partway no longer leaves a partial key list for later calls, callers wait for an in-progress fetch instead of reading its cache, and `getLatestNetworkEncryptionKey` returns the highest-epoch key.
