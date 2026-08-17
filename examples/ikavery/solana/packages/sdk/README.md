# @fesal-packages/ikavery-solana-sdk

Solana-side SDK for the [Ikavery](https://solana.ikavery.com) dWallet recovery
program — passkey-gated propose / approve / execute flows for sweep, roster
change, and enrollment proposals.

## Install

```bash
bun add @fesal-packages/ikavery-solana-sdk @solana/web3.js
# or
pnpm add @fesal-packages/ikavery-solana-sdk @solana/web3.js
```

`@fesal-packages/ikavery-core` is a transitive dep — installed automatically.

## Quick start

```ts
import { decodeRecovery, listAllRecoveries } from '@fesal-packages/ikavery-solana-sdk';
import { Connection } from '@solana/web3.js';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const recoveries = await listAllRecoveries(connection);
for (const r of recoveries) {
	console.log(r.recovery.toBase58(), r.account.threshold, 'of', r.account.members.length);
}
```

See [solana.ikavery.com](https://solana.ikavery.com) for the full flow.

## Status

Pre-alpha. Mock signer; not for production custody. Solana devnet only.

## License

[BSD-3-Clause](./LICENSE)
