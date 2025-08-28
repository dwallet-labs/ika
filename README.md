<p align="center">
<img src="https://github.com/dwallet-labs/dwallet-network/blob/main/dashboards/logo.svg" alt="Logo" width="500" height="300">
</p>

# Welcome to Ika

Ika is a decentralized platform empowering Web3 builders to create protocols that operate natively across any blockchain
with zero-trust security (eliminating the risk of trusted third parties that can be hacked or act maliciously). At the
core of this architecture is the ***dWallet***, a programmable and transferable zero-trust signing mechanism that ensures user
consent is cryptographically enforced, allowing developers to build secure, decentralized applications that operate
across the entire Web3 ecosystem.

## Unique Value of dWallets

The dWallet is an innovative Web3 building block that has the following attributes:

* _Noncollusive_: The user is always required to generate a signature.
* _Massively decentralized_: Beside the user, a 2/3 threshold of a network that can include hundreds of
  nodes, is also required to generate a signature.
* _Multi-Chain_: Using the default authentication method of blockchains - the signature - dWallets can offer universal
  and native multi-chain interoperability, without the cross-chain risks of wrapping, bridging or messaging.
* _cryptographically secure_: The security of dWallets is based on cryptography, instead of hardware or trust
  assumptions.

dWallets are the only way that exists today for Web3 builders to achieve secure, multi-chain interoperability, without
compromising on the core Web3 values of user ownership and decentralization.

Builders on [Sui Network](https://sui.io) can use dWallets natively and utilize Ika as a composable
modular signature network, adding powerful multi-chain access control capabilities to their protocol.

## Cryptography of dWallets - 2PC-MPC

dWallets utilize the [2PC-MPC protocol](https://github.com/dwallet-labs/crypto/tree/main?tab=readme-ov-file#2pc-mpc),
a two-party ECDSA protocol we designed specifically for dWallets, where the second party is fully emulated by a
network of n parties.

Besides its novel structure, enabling the zero-trust nature of dWallets, and the autonomy and flexibility of a
permissionless Ika, the 2PC-MPC protocol also dramatically improves upon the state of the art, allowing Ika to be
scalable & massively-decentralized.

The 2PC-MPC protocol achieves linear-scaling in communication - O(n) - and due to novel aggregation & amortization
techniques, an amortized cost per-party that remains constant up to thousands of parties - _practically_ O(1) in
computation for the network, allowing it to scale and achieve decentralization, whilst being _asymptotically_ O(1) for
the user: meaning the size of the network doesn't have any impact on the user as its computation and communication is
constant.

## Ika Overview

Ika is a decentralized platform, that was forked from [Sui](https://github.com/MystenLabs/sui), and similarly to Sui it
is maintained by a permissionless set of authorities that play a role similar to validators or miners in other
blockchain systems. Changes that were made to Ika include disabling smart contracts, implementing 2PC-MPC, and using the
communication in [Sui's consensus Mysticeti](https://github.com/MystenLabs/mysticeti) for the MPC protocol between the
nodes.

Ika is natively coordinated on Sui, and dWallets on Ika are controlled by DWalletCap objects on Sui.

Ika has a native token on Sui called IKA that is used (much like SUI) to pay for gas, and is also used as delegated stake
on authorities within an epoch. Authorities are periodically reconfigured according to the stake delegated to them. In any
epoch, the set of authorities is [Byzantine fault tolerant](http://pmg.csail.mit.edu/papers/osdi99.pdf). At the end of the
epoch, fees collected through all transactions processed are distributed to authorities according to their contribution to
the operation of the system. Authorities can in turn share some of the fees as rewards to users that delegated stakes to them.

Sui is based on a number of state-of-the-art
[peer-reviewed works](https://github.com/MystenLabs/sui/blob/main/docs/content/concepts/research-papers.mdx)
and years of open source development that we are building upon with the Ika.

## More About Ika

Use the following links to learn more about Ika and its ecosystem:

* Learn more about working with dWallets in the [Ika Documentation](https://docs.dwallet.io/).
* Find out more about the Ika community on the [community](https://ika.xyz/community/) page.

## Acknowledgement

As a fork of Sui, much of Ika's code base is heavily based on the code created
by [Mysten Labs, Inc.](https://mystenlabs.com) & [Facebook, Inc.](https://facebook.com) and its affiliates, including in
this very file. We are grateful for the high quality and serious work that allowed us to build our Ika technology upon
this infrastructure.

## Code Flow Diagrams

We created a few Figma diagrams to help auditors make sense of our code:

Diagrams of the different dWallet MPC flows can be found
here: https://www.figma.com/board/ISrirOSeSr9YyS6U4MTUyT/Flows-Diagrams?node-id=0-1&t=lZ0v3xQtJhWreFuf-1.

Diagrams of our State Sync mechanism can be found
here: https://www.figma.com/board/uzpZ7ToOQ8DWcID2vOUlwt/State-Sync-Overview?node-id=0-1&t=fnWiOtTlWT7ZYV93-1.
