---
id: install
title: Install Ika TypeScript SDK
description: Install Ika TypeScript SDK
sidebar_position: 1
sidebar_label: Install Ika TypeScript SDK
---

import { Construction, Info, Note } from '../../src/components/InfoBox';

# Install the Ika SDK

<Construction />

The Ika TypeScript SDK is available in the dwallet-labs/ika repository and as a package on npm.

## Install from npm

To use the Ika TypeScript SDK, you can install it from npm:

<Info title="Info">
You can use bun, pnpm, yarn, or npm to install the SDK.
</Info>

```bash
pnpm add @ika.xyz/sdk
```

## Install from the repository

To use the Ika TypeScript SDK from the repository, you can clone the repository and install the dependencies:

```bash
git clone https://github.com/dwallet-labs/ika.git
```

To build the SDK, you must have pnpm, Sui CLI, Rust, and `wasm-binding-cli` installed. After you have cloned the repository, you can build the SDK by running the following command:

```bash
cd sdk/typescript
pnpm install && pnpm build
```

With the SDK built, you can use it in your project by adding the following to your `package.json`:

```json
"dependencies": {
  "@ika.xyz/sdk": "file:../sdk/typescript/dist"
}
```

<Note title="Note">
The `file:../sdk/typescript/dist` path assumes you're adding this dependency from the root of the cloned repository. Adjust this path based on your project's directory structure relative to the SDK location.
</Note>
