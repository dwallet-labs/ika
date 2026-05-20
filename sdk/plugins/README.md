### @ika.xyz/plugins — First-party plugins for the Ika SDK

**v0.1.0**

## Overview

Source / destination / publisher plugin packages that wrap `@ika.xyz/sdk` with chain-specific
ergonomics. The plugins handle address derivation, message preimage construction, signature
assembly, and (optionally) broadcasting — so application code only deals with high-level intents:

- "Create a dWallet on Sui, sign a Bitcoin PSBT, broadcast on testnet."
- "Backend funds the DKG, end user receives the cap and signs from their wallet."
- "Prepare a sign request now, gate it on a Move multisig, assemble the signature later."

### Architecture

Three plugin roles, each addressing one concern:

| Role            | Job                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| **Source**      | Manages the dWallet on Sui (DKG, encryption keys, presign requests, sign coordination).                |
| **Destination** | Knows how a target chain encodes addresses + sighashes (BTC/ETH/SOL/SUI). Owns `prepareSign` + `assembleSign`. |
| **Publisher**   | Broadcasts the assembled, signed transaction to the destination chain's network.                       |

Compose them on a single `IkaClient` instance:

```ts
import { IkaClient } from '@ika.xyz/sdk/plugin';
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher } from '@ika.xyz/plugins/bitcoin/publisher';

const ika = await new IkaClient()
	.use(suiSource({ network: 'testnet', signer }))
	.use(btc())
	.use(bitcoinPublisher({ network: 'testnet' }));

const dWallet = await ika.sui.createDWallet({ kind: 'shared', curve: 'SECP256K1' });
const signed = await dWallet.bitcoin.sign({ kind: 'psbt', psbt, inputIndex: 0, mode: 'p2tr-script' });
const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

## Install

```bash
pnpm add @ika.xyz/plugins @ika.xyz/sdk @mysten/sui
# plus the per-chain peer deps you actually use:
pnpm add bitcoinjs-lib @bitcoinerlab/secp256k1   # bitcoin
pnpm add viem                                     # ethereum
pnpm add @solana/web3.js                          # solana
```

Peers `bitcoinjs-lib`, `viem`, and `@solana/web3.js` are declared **optional** — install only what
your application needs. Node >= 18.

## Subpath imports

Each plugin is reachable via its own subpath so bundlers can tree-shake the chains you don't use:

```ts
import { suiSource } from '@ika.xyz/plugins/sui/source';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
import { sui } from '@ika.xyz/plugins/sui/destination';

import { btc, deriveBitcoinAddress, buildP2trScriptPath } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher } from '@ika.xyz/plugins/bitcoin/publisher';

import { eth } from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';

import { solana } from '@ika.xyz/plugins/solana/destination';
import { solanaDevnet, solanaMainnet } from '@ika.xyz/plugins/solana/publisher';
```

The root `@ika.xyz/plugins` re-exports everything, but prefer the subpaths to avoid pulling in
unused peer dependencies at bundle time.

## prepareSign / assembleSign

Every destination exposes two-phase signing for callers that need to gate the signing decision on
something other than "submit the PTB immediately":

```ts
// 1. Prepare — derive preimage, address, plan; choose a hash + algorithm.
const { prep, preimage, plan } = await dWallet.bitcoin.prepareSign({
	kind: 'psbt',
	psbt,
	inputIndex: 0,
	mode: 'p2tr-script',
});

// 2. Run your own gating logic (Move multisig, sponsored tx, future-sign, etc.)
//    and produce a 64-byte (r || s) signature from the MPC network.
const signature = await yourCustomFlow(preimage, plan);

// 3. Assemble the signed payload.
const signed = await dWallet.bitcoin.assembleSign(prep, signature);
const txid = await ika.publish({ chain: 'bitcoin', payload: signed.payload });
```

For the default "request → wait → assemble" flow use `dWallet.<chain>.sign(...)`; it composes the
above for you.

### Future-sign on Sui

The Sui source exposes `requestFutureSign` and `completeFutureSign` so the cap holder can pre-issue
a `PartialUserSignatureCap` ahead of time and another party can redeem it later:

```ts
const partial = await ika.sui.requestFutureSign({ dWallet, message });
// ... time passes, gating logic runs ...
const signed = await ika.sui.completeFutureSign({ dWallet, partialUserSignatureCap: partial.cap });
```

## Development

```bash
pnpm install
pnpm run build        # esbuild + tsc → dist/cjs + dist/esm
pnpm run typecheck    # src + test
pnpm run lint         # eslint + prettier
pnpm run test         # unit tests (no network)
pnpm run test:testnet # against Sui testnet (requires IKA_TESTNET_PRIVATE_KEY)
pnpm run test:localnet
```

### Directory layout

```
sdk/plugins/
├── src/
│   ├── bitcoin/{destination,publisher,index.ts}
│   ├── ethereum/{destination,publisher,index.ts}
│   ├── solana/{destination,publisher,index.ts}
│   ├── sui/{source,destination,publisher,index.ts}
│   ├── internal/         # cache + small shared utilities
│   └── index.ts          # aggregate re-exports
├── test/
│   ├── unit/             # vitest unit tests (mocked source)
│   ├── testnet/          # plugin e2e against Sui testnet
│   └── localnet/         # full docker-localnet matrix (one test per destination)
├── examples/             # standalone runnable examples
├── bitcoin/, ethereum/, solana/, sui/   # subpath shim package.json files
├── tsconfig.json         # build config
├── tsconfig.esm.json     # ESM build variant
└── vitest.config.ts      # workspace-source aliases for in-tree tests
```

### Localnet

The localnet stack lives in `test/localnet/`. It builds an Ika validator image alongside an Anvil
EVM, a Bitcoin Core regtest node, and a Solana test-validator. Bring it up with:

```bash
pnpm run localnet:up
pnpm run test:localnet
pnpm run localnet:down
```

## License

BSD-3-Clause-Clear
