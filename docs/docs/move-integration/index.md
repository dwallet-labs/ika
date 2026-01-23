---
id: move-integration
title: Move Contract Integration
description: Build Move contracts that integrate with Ika's dWallet 2PC-MPC protocol for programmable cross-chain signing
sidebar_position: 0
sidebar_label: Overview
---

# Move Contract Integration

Build Move smart contracts that integrate with Ika's distributed wallet (dWallet) protocol to enable programmable, decentralized signing for cross-chain operations.

## What is Move Integration?

Move integration allows you to embed dWallet functionality directly into your Sui Move smart contracts. This enables:

- **Programmable Signing**: Define custom logic that controls when and how signatures are created
- **Cross-Chain Operations**: Sign transactions for Bitcoin, Ethereum, and other chains from Sui contracts
- **Decentralized Custody**: Build DAOs, treasuries, and governance systems with distributed key management
- **Automated Workflows**: Create smart contracts that can sign without user interaction (using shared dWallets)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Move Contract                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ DWalletCap  │  │  Presigns   │  │ Business Logic          │ │
│  │  (stored)   │  │  (pooled)   │  │ (governance, approvals) │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
└─────────┼────────────────┼─────────────────────┼───────────────┘
          │                │                     │
          ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DWalletCoordinator                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │   DKG    │  │ Presign  │  │  Sign    │  │  Future Sign     ││
│  │ Protocol │  │ Protocol │  │ Protocol │  │  Protocol        ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Ika Network                                 │
│              (2PC-MPC Protocol Execution)                       │
└─────────────────────────────────────────────────────────────────┘
```

## When to Use Move Integration

### Use Move Integration When:

- Building **DAOs or treasuries** that need distributed signing authority
- Creating **governance systems** with approval workflows before signing
- Implementing **multi-signature wallets** with custom voting logic
- Building **automated trading bots** or DeFi protocols that sign on other chains
- Developing **custody solutions** with programmable access controls

### Use SDK-Only When:

- Building **user-facing wallets** where users hold their own keys
- Creating **simple signing flows** without on-chain logic
- Prototyping before committing to on-chain architecture

## Key Concepts

| Concept | Description |
|---------|-------------|
| **DWalletCoordinator** | The shared object that manages all dWallet operations on Ika |
| **DWalletCap** | Capability object that authorizes signing operations for a dWallet |
| **Presign** | Pre-computed cryptographic material required before signing |
| **MessageApproval** | Authorization for signing a specific message |
| **SessionIdentifier** | Unique identifier for each protocol operation |

## Protocol Lifecycle

```
1. DKG (Create dWallet)
   └── Generates DWalletCap + network key shares

2. Presign (Prepare to Sign)
   └── Creates cryptographic nonces for signature operations

3. Sign (Create Signature)
   └── Combines presign + message approval → signature

   OR

3. Future Sign (Two-Phase Signing)
   └── Phase 1: Create partial signature (can be stored)
   └── Phase 2: Complete signature (when approved)
```

## Quick Example

Here's a minimal example of a contract that creates a shared dWallet:

```rust
module my_protocol::treasury;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{DWalletCap, UnverifiedPresignCap},
    sessions_manager::SessionIdentifier
};
use sui::{balance::Balance, coin::Coin, sui::SUI};

public struct Treasury has key, store {
    id: UID,
    dwallet_cap: DWalletCap,
    presigns: vector<UnverifiedPresignCap>,
    ika_balance: Balance<IKA>,
    sui_balance: Balance<SUI>,
}
```

## Documentation Structure

- **[Getting Started](./getting-started.md)** - Set up your Move project with Ika dependencies
- **[Core Concepts](./core-concepts/)** - Understand the coordinator, capabilities, and payments
- **[Protocols](./protocols/)** - Deep dive into DKG, presigning, signing, and future signing
- **[Integration Patterns](./integration-patterns/)** - Common patterns for building with Ika
- **[Examples](./examples/)** - Full example walkthroughs including Bitcoin multisig

## Next Steps

1. Start with [Getting Started](./getting-started.md) to set up your project
2. Read [Core Concepts](./core-concepts/) to understand the building blocks
3. Follow the [Protocols](./protocols/) guides for each operation type
4. Check [Examples](./examples/) for complete implementations
