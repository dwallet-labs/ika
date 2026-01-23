---
id: core-concepts-overview
title: Core Concepts
description: Understand the fundamental building blocks of Ika Move integration
sidebar_position: 2
sidebar_label: Core Concepts
---

# Core Concepts

This section covers the fundamental building blocks you need to understand when integrating Ika dWallet functionality into your Move contracts.

## Overview

Ika's Move integration is built around several key concepts:

| Concept | Description |
|---------|-------------|
| **[Coordinator Architecture](/move-integration/core-concepts/coordinator-architecture)** | The `DWalletCoordinator` is the central shared object that manages all dWallet operations |
| **[Capabilities and Approvals](/move-integration/core-concepts/capabilities-and-approvals)** | Capability objects control authorization for dWallet operations |
| **[Session Management](/move-integration/core-concepts/session-management)** | Unique identifiers ensure each protocol operation is processed exactly once |
| **[Payment Handling](/move-integration/core-concepts/payment-handling)** | All operations require IKA and SUI fees |

## How They Work Together

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Move Contract                          │
│                                                                 │
│  1. Store DWalletCap (from DKG)                                │
│  2. Manage presign pool (UnverifiedPresignCap)                 │
│  3. Handle IKA/SUI balances for fees                           │
│  4. Generate SessionIdentifiers for operations                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DWalletCoordinator                            │
│                                                                 │
│  - Validates capabilities and approvals                        │
│  - Deducts fees from payment coins                             │
│  - Emits events for the Ika network                            │
│  - Returns results (capabilities, IDs)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Ika Network                                 │
│                                                                 │
│  - Processes MPC protocol sessions                             │
│  - Creates signatures, presigns, DKG outputs                   │
│  - Stores results back to coordinator                          │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Reference

### Essential Imports

```rust
use ika::ika::IKA;
use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{
        DWalletCap,
        ImportedKeyDWalletCap,
        UnverifiedPresignCap,
        VerifiedPresignCap,
        UnverifiedPartialUserSignatureCap,
        VerifiedPartialUserSignatureCap,
        MessageApproval,
        ImportedKeyMessageApproval
    },
    sessions_manager::SessionIdentifier
};
use sui::{balance::Balance, coin::Coin, sui::SUI};
```

### Typical Contract Structure

```rust
public struct MyContract has key, store {
    id: UID,

    // Authorization
    dwallet_cap: DWalletCap,

    // Presign pool
    presigns: vector<UnverifiedPresignCap>,

    // Payment balances
    ika_balance: Balance<IKA>,
    sui_balance: Balance<SUI>,

    // Network key reference
    dwallet_network_encryption_key_id: ID,
}
```

## Next Steps

Start with [Coordinator Architecture](/move-integration/core-concepts/coordinator-architecture) to understand how the coordinator works, then move through the other concepts in order.
