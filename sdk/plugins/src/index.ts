// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * No symbols are re-exported at the package root. A root barrel would pull
 * every chain's web3 SDK (Solana, Bitcoin, ...) into every consumer's bundle
 * even when only one chain is used, forcing Sui-only consumers to depend on
 * `@solana/web3.js` despite `peerDependenciesMeta` declaring it optional.
 *
 * Import the subpath you need:
 *   import { suiSource } from '@ika.xyz/plugins/sui/source';
 *   import { sui } from '@ika.xyz/plugins/sui/destination';
 *   import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';
 *   import { solana } from '@ika.xyz/plugins/solana/destination';
 *   import { solanaDevnet } from '@ika.xyz/plugins/solana/publisher';
 *
 * To pull everything for a single chain in one import, use the chain barrel:
 *   import { ... } from '@ika.xyz/plugins/sui';
 */
export {};
