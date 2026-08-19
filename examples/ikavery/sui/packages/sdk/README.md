# @fesal-packages/ikavery-sui-sdk

Sui-side SDK for the [Ikavery](https://sui.ikavery.com) dWallet recovery
protocol — passkey-gated key import, threshold approval, and cross-chain sweep
flows backed by Ika 2PC-MPC.

## Install

```bash
bun add @fesal-packages/ikavery-sui-sdk @mysten/sui
# or
pnpm add @fesal-packages/ikavery-sui-sdk @mysten/sui
```

`@fesal-packages/ikavery-core` is a transitive dep — installed automatically.

## Quick start

```ts
import {
	buildRecoveryClient,
	importSolanaKey,
	readRecoveryState,
} from '@fesal-packages/ikavery-sui-sdk';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

const suiClient = new SuiJsonRpcClient({
	url: getJsonRpcFullnodeUrl('testnet'),
	network: 'testnet',
});

const client = buildRecoveryClient(suiClient, /* recoveryId */ '0x...');
const state = await readRecoveryState(client);
```

See [sui.ikavery.com](https://sui.ikavery.com) for the full flow.

## Status

Pre-alpha. Mock signer; not for production custody. Sui testnet only.

## License

[BSD-3-Clause](./LICENSE)
