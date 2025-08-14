---
id: setup-localnet
title: Setup Ika Localnet
description: Setup Ika Localnet
sidebar_position: 2
sidebar_label: Setup Ika Localnet
---

import { Construction } from '../../src/components/InfoBox';

# Setup Ika Localnet

<Construction />

## Prerequisites

Before setting up the Ika localnet, ensure you have the following software installed on your system:

- **Rust**: The programming language and toolchain required to build Ika
- **Sui CLI**: The command-line interface for interacting with Sui blockchain

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

- `--release`: Builds the binary in release mode for better performance
- `--no-default-features`: Disables default features to ensure clean compilation
- `start`: The command to start the Ika node
