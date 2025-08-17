---
id: ika-client
title: Ika Client
description: Ika Client
sidebar_position: 1
sidebar_label: Ika Client
---

import { Construction, Info } from '../../../src/components/InfoBox';

# Ika Client

<Construction />

Ika Client is the main entry point for interacting with the Ika protocol. It provides an easy way to query for the Ika protocol state and objects.

<Info title="Info">
We recommend you to have a single instance of Ika Client for your application. This enables caching of the Ika protocol state and objects.
</Info>

## Create a Ika Client

```typescript
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';

const client = new SuiClient({ url: getFullnodeUrl('testnet') }); // mainnet / testnet / localnet

const ikaClient = new IkaClient({
	suiClient: client,
	config: getNetworkConfig('testnet'), // mainnet / testnet / localnet
});

await ikaClient.initialize(); // This will initialize the Ika Client and fetch the Ika protocol state and objects.
```
