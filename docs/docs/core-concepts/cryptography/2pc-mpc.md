---
id: 2pc-mpc
title: 2PC-MPC
description: Ika's innovative protocol combining Two-Party Computation with Multi-Party Computation for blockchain-optimized security.
sidebar_position: 1
sidebar_label: 2PC-MPC
---

# 2PC-MPC

## Overview

2PC-MPC, as described in the ["2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC"](https://eprint.iacr.org/2024/253)
paper by the dWallet
Labs research team, is a novel [MPC](mpc.md) protocol designed specifically for [dWallets](../dwallets.md), and Ika.

## Advantage

These are some of the key features setting 2PC-MPC apart from the preceding TSS protocols used in Web3:

- _**Non-collusive**_: both a user and a threshold of the network are required to participate in signing.
- _**Scalable & Massively Decentralized**_: can support hundreds or thousands of nodes on the network side.
- _**Locality**_: communication and computation complexities of the user remain independent of the size of the network
  (This is not fully implemented yet due to a restriction in Bulletproofs, and coming soon).
- _**Identifiable Abort**_: malicious behavior of one of the nodes aborts the protocol identifiably, which is an
  important requirement in a permissionless and trustless setting.

## Structure and Performance

The 2PC-MPC protocol can be thought of as a "nested" MPC, where a user and a network are always required to generate a
signature (2PC — 2 party computation), and the network participation is managed by an MPC process between the nodes,
requiring a threshold on par with the consensus threshold.
This structure creates non-collusivity, as the user is always required to generate a signature, but also allows the
network to be completely autonomous and flexible, as it is transparent to the users of the network.

2PC-MPC exhibits superior performance as well, with its linear-scaling in communication - `O(n)` - and due to novel
aggregation & amortization techniques, an amortized cost per-party that remains constant up to thousands of parties —
practically `O(1)` in computation for the network, whilst being asymptotically `O(1)` for the user: meaning the size of
the network doesn't have any impact on the user as its computation and communication is constant.

The goal of Ika is to support millions of users, and tens of thousands of signatures per second, with thousands of
validators.
2PC-MPC, and its future improvements and optimizations planned, are how that ambitious goal will be achieved.

## Implementation

The 2PC-MPC protocol's pure-rust implementation can be found [here](https://github.com/dwallet-labs/2pc-mpc).
