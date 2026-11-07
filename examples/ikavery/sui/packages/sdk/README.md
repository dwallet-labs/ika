# @ika-examples/ikavery-sui-sdk

Sui-side SDK for the Ikavery dWallet recovery
protocol — passkey-gated key import, threshold approval, and cross-chain sweep
flows backed by Ika 2PC-MPC.

## In this repository

A private workspace package of the Ikavery example, consumed through
`workspace:*`; it depends on `@ika-examples/ikavery-core` the same way. It is
not published.

## Quick start

```ts
import {
	buildRecoveryClient,
	importSolanaKey,
	readRecoveryState,
} from '@ika-examples/ikavery-sui-sdk';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

const suiClient = new SuiJsonRpcClient({
	url: getJsonRpcFullnodeUrl('testnet'),
	network: 'testnet',
});

const client = buildRecoveryClient(suiClient, /* recoveryId */ '0x...');
const state = await readRecoveryState(client);
```

## Status

Pre-alpha. Mock signer; not for production custody. Sui testnet only.

## License

[BSD-3-Clause-Clear](./LICENSE)
