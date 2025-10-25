---
id: dwallet-types
title: dWallet Types Overview
description: Understanding the three types of dWallets - Zero-Trust, Shared, and Imported - their security models and use cases
sidebar_position: 1
sidebar_label: dWallet Types Overview
---

import { Info, Warning, Tip } from '../../../src/components/InfoBox';

# dWallet Types Overview

dWallets use 2PC-MPC (Two-Party Computation Multi-Party Computation) to split cryptographic keys into shares. There are three main types, each with different trust and control models.

## Zero-Trust dWallets

<Tip title="Two-Share Model">
The key is split between you (user share) and the network (network share). Both shares are required to create signatures.
</Tip>

A Zero-Trust dWallet has two shares:

- **User share**: Encrypted and controlled by you
- **Network share**: Held by the Ika network

**Why both shares matter:**
Without your user share, the network cannot create any signatures. You maintain control because your share is always required for signing operations.

---

## Shared dWallets

<Info title="Network-Controlled">
The user share is public, meaning the network can create signatures on your behalf.
</Info>

A Shared dWallet has a public user share, allowing anyone to provide it. This means:

- **User share**: Public and accessible by anyone
- **Network share**: Held by the Ika network

**What this means:**
Since the user share is public, the network can create signatures without your participation. You fully trust the Ika network to manage signing operations.

---

## Imported Key dWallets

<Warning title="Existing Key Import">
Import an existing private key into the dWallet system, with options for Zero-Trust or Shared configurations.
</Warning>

An Imported Key dWallet brings an existing private key into the dWallet system. You can import it as:

**Zero-Trust Imported Key:**

- Split into user share (encrypted, controlled by you) and network share
- Both shares required for signing
- Original private key remains a potential security concern

**Shared Imported Key:**

- User share is public, network can sign on your behalf
- Original private key remains a potential security concern

**The security consideration:**
Your original private key still exists outside the dWallet system. If compromised, it bypasses the dWallet security model entirely.

---

## Which One Should You Pick?

**Go with Zero-Trust if:**
You want to maintain control over signing operations. Both your user share and the network share are required, so the network cannot sign without your participation.

**Pick Shared if:**
You want the network to handle signing on your behalf. Good for DAOs, automated systems, or scenarios where you fully trust the network to manage signatures.

**Choose Imported Key if:**
You need to bring existing keys into the dWallet system. You can configure it as Zero-Trust (both shares required) or Shared (network can sign on your behalf). Be aware that your original private key remains a security consideration.

## Ready to Get Started?

1. **[Get your dev environment set up](../setup-localnet.md)** - Set up a local network for development
2. **[Set up encryption keys](../user-share-encryption-keys.md)** - Required for Zero-Trust and Zero-Trust Imported Key dWallets
