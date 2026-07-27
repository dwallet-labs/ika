<p align="center">
<img src="./dashboards/logo.svg" alt="Ika Logo" width="500" height="300">
</p>

# Welcome to Ika

Ika is the fastest zero-trust MPC network - a decentralized signature network
that lets Web3 builders create protocols operating natively across any
blockchain, with no bridging, wrapping, or trusted intermediaries. Ika is live
on mainnet in beta, coordinated on [Sui](https://sui.io), and live in
pre-alpha for builders on [Solana](https://solana.com).

> **Ika is currently in live beta.** Using it involves many risks. We strongly
> recommend reading the [Ika Whitepaper](https://docs.ika.xyz/whitepaper.pdf)
> before building on or using the network.

At the core of Ika is the **_dWallet_** - a decentralized, programmable, and
transferable signing mechanism with an address on any network. Every signature
requires both the user and a 2/3 threshold of the Ika network, so user consent
is cryptographically enforced and no party, not even the network itself, can
sign alone.

## Unique Value of dWallets

- _Noncollusive_: the user is always required to generate a signature.
- _Massively decentralized_: besides the user, a 2/3 threshold of a network
  that can scale to hundreds of nodes is required to generate a signature.
- _Multi-chain_: using the default authentication method of every blockchain -
  the signature - dWallets offer universal, native interoperability without
  the cross-chain risks of wrapping, bridging, or messaging. With ECDSA and
  EdDSA support, dWallets natively control assets and accounts on Bitcoin,
  Ethereum, Solana, and virtually any other chain.
- _Cryptographically secure_: security is based on cryptography, not hardware
  or trust assumptions.

Builders on [Sui](https://sui.io) and [Solana](https://solana.com) can use
dWallets natively, utilizing Ika as a composable modular signature network
that adds powerful multi-chain capabilities to their protocols: native-asset
DeFi, multi-chain custody, treasury management, wallet infrastructure, and
policy enforcement for AI agents.

## Cryptography of dWallets: 2PC-MPC

dWallets utilize [2PC-MPC](https://eprint.iacr.org/2024/253), a two-party
threshold signing protocol designed specifically for dWallets, where the
second party is fully emulated by a network of n parties. Ika's open-source
cryptography libraries live in
[dwallet-labs/inkrypto](https://github.com/dwallet-labs/inkrypto).

Beyond its novel structure, which enables the zero-trust nature of dWallets
and the autonomy of a permissionless network, 2PC-MPC dramatically improves
on the state of the art: linear-scaling O(n) communication and, through novel
aggregation & amortization techniques, practically O(1) amortized computation
per party up to thousands of parties. For the user it is asymptotically O(1):
network size has no impact on the user's computation or communication. This is
what lets Ika deliver sub-second signing latency at scale while remaining
massively decentralized.

## Ika Overview

Ika was originally forked from [Sui](https://github.com/MystenLabs/sui), and
while much of the codebase has since diverged, like Sui it is maintained by a
permissionless set of authorities that play a role similar to validators or
miners in other blockchain systems. Changes made to Ika include disabling
smart contracts, implementing 2PC-MPC, and using
[Sui's Mysticeti consensus](https://github.com/MystenLabs/sui/tree/main/consensus)
for the MPC protocol communication between nodes.

Ika is natively coordinated on Sui: dWallets are controlled by objects on Sui
and can be governed by Sui smart contracts. Solana coordination is live in
pre-alpha for builders, bringing dWallets under the control of Solana
programs.

Ika has a native token, IKA, used to pay network fees and as delegated stake
on authorities. Authorities are periodically reconfigured according to the
stake delegated to them; within any epoch the authority set is
[Byzantine fault tolerant](http://pmg.csail.mit.edu/papers/osdi99.pdf). Fees
collected during an epoch are distributed to authorities according to their
contribution, and authorities can share rewards with their delegators.

Sui is based on a number of state-of-the-art
[peer-reviewed works](https://github.com/MystenLabs/sui/blob/main/docs/content/concepts/research-papers.mdx)
and years of open-source development that Ika builds upon.

## More About Ika

- [Ika Whitepaper](https://docs.ika.xyz/whitepaper.pdf) - read before using
  the network.
- [Ika Documentation](https://docs.ika.xyz) - learn to build with dWallets.
- [ika.xyz](https://ika.xyz) - the Ika website.
- [@ikadotxyz](https://x.com/ikadotxyz) - follow Ika on X.

## Acknowledgement

As a fork of Sui, much of Ika's code base is heavily based on the code created
by [Mysten Labs, Inc.](https://mystenlabs.com) & [Facebook, Inc.](https://facebook.com)
and its affiliates, including in this very file. We are grateful for the high
quality and serious work that allowed us to build Ika upon this
infrastructure.

## Code Flow Diagrams

Diagrams of the dWallet MPC flows:
https://www.figma.com/board/ISrirOSeSr9YyS6U4MTUyT/Flows-Diagrams?node-id=0-1&t=lZ0v3xQtJhWreFuf-1

Diagrams of the State Sync mechanism:
https://www.figma.com/board/uzpZ7ToOQ8DWcID2vOUlwt/State-Sync-Overview?node-id=0-1&t=fnWiOtTlWT7ZYV93-1
