# @fesal-packages/ikavery-core

Shared crypto, passkey, and dWallet helpers used by the Ikavery
[Sui SDK](https://www.npmjs.com/package/@fesal-packages/ikavery-sui-sdk) and
[Solana SDK](https://www.npmjs.com/package/@fesal-packages/ikavery-solana-sdk).

Most consumers want one of the chain-specific SDKs above. Reach for this package
directly only if you're building primitives outside those flows (raw passkey
ceremonies, share-encryption identity derivation, sweep-bundle utilities).

## Install

```bash
bun add @fesal-packages/ikavery-core
# or
pnpm add @fesal-packages/ikavery-core
```

## Status

Pre-alpha. Mock signer; not for production custody.

## License

[BSD-3-Clause](./LICENSE)
