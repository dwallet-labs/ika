---
id: install
title: Install Ika TypeScript SDK
description: Install Ika TypeScript SDK
sidebar_position: 1
sidebar_label: Install Ika TypeScript SDK
---

import { Construction, Info, Note } from '../../src/components/InfoBox';
import Prerequisites from '../../src/components/Prerequisites';

# Install the Ika SDK

<Construction />

The Ika TypeScript SDK is available in the [dwallet-labs/ika](https://github.com/dwallet-labs/ika) repository and as a package on npm.

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

To build the SDK, you must have the following tools installed:

<Prerequisites items={[
{
name: "🦀 Rust",
description: "The programming language and toolchain required to build Ika",
link: { url: "https://rustup.rs/", text: "Install Guide" },
command: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
},
{
name: "🔧 Sui CLI",
description: "The command-line interface for interacting with Sui blockchain",
link: { url: "https://docs.sui.io/guides/developer/getting-started/sui-install", text: "Sui Documentation" },
methods: [
{
name: "Homebrew",
description: "Recommended for macOS and Linux users",
command: "brew install sui"
},
{
name: "Chocolatey",
description: "Recommended for Windows users",
command: "choco install sui"
},
{
name: "Cargo",
description: "Install from source (all platforms)",
command: "cargo install --locked --git https://github.com/MystenLabs/sui.git --branch mainnet sui"
},
{
name: "Download Binary",
description: "Download pre-built binaries for your operating system",
link: {
url: "https://docs.sui.io/guides/developer/getting-started/sui-install#download-binaries-from-github",
text: "View Installation Guide"
}
}
]
},
{
name: "📦 pnpm",
description: "Fast, disk space efficient package manager",
link: { url: "https://pnpm.io/installation", text: "Installation Guide" },
methods: [
{
name: "npm",
description: "Using npm (most common)",
command: "npm install -g pnpm"
},
{
name: "Homebrew",
description: "For macOS and Linux users",
command: "brew install pnpm"
},
{
name: "PowerShell",
description: "For Windows users",
command: "iwr https://get.pnpm.io/install.ps1 -useb | iex"
},
{
name: "Standalone Script",
description: "Using standalone installer",
command: "curl -fsSL https://get.pnpm.io/install.sh | sh -"
}
]
},
{
name: "🕸️ wasm-pack",
description: "WebAssembly packager for building and packaging Rust-generated WebAssembly",
command: "curl https://drager.github.io/wasm-pack/installer/init.sh -sSf | sh"
},
{
name: "🔗 wasm-bindgen-cli",
description: "WebAssembly binding generator for creating JavaScript bindings",
command: "cargo install wasm-bindgen-cli --version 0.2.100"
}
]} />

After you have installed these prerequisites and cloned the repository, you can build the SDK by running the following command:

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
