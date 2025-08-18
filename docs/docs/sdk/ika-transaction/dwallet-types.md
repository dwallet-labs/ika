---
id: dwallet-types
title: dWallet Types Overview
description: Understanding the three types of dWallets - Zero-Trust, Shared, and Imported - their security models and use cases
sidebar_position: 1
sidebar_label: dWallet Types Overview
---

import { Info, Warning, Tip } from '../../../src/components/InfoBox';

# dWallet Types Overview

Think of dWallets like different types of safes, each designed for different situations and security needs. There are three main types, and picking the right one depends on what you're trying to protect and how you want to work with it.

## Zero-Trust dWallets

<Tip title="Fort Knox Level Security">
This is the gold standard, maximum security with your private key shares locked away behind your own encryption.
</Tip>

Here's how it actually works: your user share is encrypted with your personal encryption key. When you want to sign something, you decrypt your share and use it to create the signature. The network never sees your unencrypted share, it stays locked behind your encryption.

**Why this matters:**
Even if someone gets access to the dWallet system, they can't use your share without your encryption key. It's like having a safe deposit box where you need YOUR key to open YOUR box, and nobody else can peek inside.

**[→ Learn more about Zero-Trust dWallets](./zero-trust)**

---

## Shared dWallets

<Info title="Cap Owner Controls Everything">
Your user share is public, but the real power is with whoever owns the dWalletCap.
</Info>

Whoever owns the dWalletCap can initiate transactions without even needing your user share, they have full signing control.

**What this means in practice:**
The dWalletCap owner is in complete control. They can sign transactions whenever they want. This action is not reversible. You FULLY trust Ika network.

**[→ Learn more about Shared dWallets](./shared)**

---

## Imported dWallets

<Warning title="Security Trade-off">
Import existing keys, but know that you're creating two ways to control the same wallet.
</Warning>

Here's what actually happens: you import your existing keypair into the dWallet system. Now both the dWallet AND your original private key can control the same wallet. It's encrypted like Zero-Trust, but there's a catch, it's inherently less secure.

**The security problem:**
You still have your original private key sitting around, and the dWallet also has control. So now there are two ways to control the same wallet. If someone gets your original key, they can bypass the entire dWallet security model.

**[→ Learn more about Imported dWallets](./imported)**

---

## Which One Should You Pick?

**Go with Zero-Trust if:**
You want actual security where you control your own signing. This is the only option where you truly control your piece of the key.

**Pick Shared if:**
You want to give full control to a dWalletCap owner. Good when you specifically want someone else to have complete signing control. For example DAOs and automated smart contract systems.

**Choose Imported if:**
You're stuck with existing keys and accept the security trade-off. Remember, your original keypair is still a weak point, but sometimes convenience wins over perfect security.

## Ready to Get Started?

Alright, you've picked your flavor of dWallet. Here's what to do next:

1. **[Get your dev environment set up](../setup-localnet.md)** - You'll need a local network to play with
2. **[Set up encryption keys](../user-share-encryption-keys.md)** - This is important for Zero-Trust and Imported dWallets
3. **Jump into your chosen guide:**
   - **[Zero-Trust dWallets](./zero-trust)**
   - **[Shared dWallets](./shared)**
   - **[Imported dWallets](./imported)**
