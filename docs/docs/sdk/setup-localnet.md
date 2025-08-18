---
id: setup-localnet
title: Setup Ika Localnet
description: Setup Ika Localnet
sidebar_position: 2
sidebar_label: Setup Ika Localnet
---

import { Construction } from '../../src/components/InfoBox';
import Prerequisites from '../../src/components/Prerequisites';

# Setup Ika Localnet

<Construction />

## Prerequisites

Before setting up the Ika localnet, ensure you have the following software installed on your system:

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
}
]} />

## Clone the Ika Repository

First, you need to clone the Ika repository to your local machine. This will download all the necessary source code and configuration files.

```bash
git clone https://github.com/dwallet-labs/ika.git
cd ika
```

## Start the Sui Localnet

The Ika localnet depends on a running Sui localnet instance. This command starts a local Sui blockchain with a faucet for testing purposes.

```bash
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 1000000000000000
```

**Parameters explained:**

- `--with-faucet`: Enables the faucet service for obtaining test tokens
- `--force-regenesis`: Forces a new genesis block creation
- `--epoch-duration-ms 1000000000000000`: Sets a very long epoch duration for testing

## Start the Ika Localnet

Once the Sui localnet is running, you can start the Ika localnet in a separate terminal. This will launch the Ika node that connects to the Sui localnet.

```bash
cargo run --bin ika --release --no-default-features -- start
```

**Parameters explained:**

- `--bin ika`: Specifies which binary to run from the workspace (the main Ika node executable)
- `--release`: Builds and runs the binary with optimizations enabled for better performance
- `--no-default-features`: Disables default Cargo features to run only the core functionality needed for localnet, for example removes min 16 cpu cores requirement
- `start`: Command passed to the Ika binary to initialize and start the local node
