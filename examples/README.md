# IKA Project Examples

This directory contains example applications demonstrating the capabilities of the IKA protocol and its integration with blockchain networks.

## ⚠️ IMPORTANT WARNING

**These examples are provided for developer testing and educational purposes only.**

All examples in this directory:

- **MUST be used on testnet ONLY** (never on mainnet)
- **Have NOT been audited** and may contain bugs or unexpected behavior
- **Should NOT be used with real funds** or production wallets
- Should only be used with test keys and disposable test amounts

**You assume all risk by proceeding. Use at your own risk.**

---

## Installing

Every example here is a **pnpm workspace member of this repository**, so
dependencies are installed once from the repository root — not per app:

```bash
# from the repository root
pnpm install
```

The examples consume `@ika.xyz/sdk` as `workspace:*`, meaning they build against
the SDK in this checkout rather than a published version, and shared library
versions come from the `catalog:` in `pnpm-workspace.yaml`. Node 24+ (the Active
LTS line) is required.

## Available Examples

### 🪙 bitisi - Bitcoin Multisig on Sui

**Location:** `multisig-bitcoin/`

A full-featured Bitcoin multisig wallet application built on the Sui blockchain using IKA's MPC protocol for distributed key management.

**Features:**

- Create flexible multisig wallets with customizable thresholds
- Manage Bitcoin transactions through on-chain governance
- Add/remove members and adjust thresholds dynamically
- Full integration with Sui wallets and IKA protocol
- Modern, responsive web interface

**Tech Stack:**

- **Smart Contracts:** Move on Sui blockchain
- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind CSS
- **Sui access:** `@mysten/sui` v2 over gRPC with dApp Kit 2
  (`@mysten/dapp-kit-react`)
- **Integration:** IKA 2PC MPC protocol for key generation

**Quick Start:**

```bash
pnpm install                          # from the repository root
pnpm --filter frontend dev
```

[View detailed documentation →](multisig-bitcoin/README.md)

---

### 🔑 KeySpring - Cross-Chain Wallet Demo

**Location:** `keyspring/`

A cross-chain wallet demo that creates an Ethereum wallet from any browser wallet or passkey and sends ETH on Base Sepolia — all non-custodially using Ika's distributed key generation.

**Features:**

- Create Ethereum wallets using any existing wallet (MetaMask, Phantom, etc.) or passkeys (Face ID, Touch ID, Windows Hello)
- Send ETH transactions on Base Sepolia testnet
- Non-custodial — secret key share never leaves the browser
- Cross-chain — use a Solana wallet to control an Ethereum address
- Passkey authentication via WebAuthn PRF extension

**Tech Stack:**

- **Backend:** Bun (runtime), TypeScript, Ika SDK
- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind CSS
- **Sui access:** `@mysten/sui` v2 over gRPC
- **Integration:** Ika 2PC-MPC protocol for distributed key generation

**Quick Start:**

```bash
pnpm install                          # from the repository root

# Backend (still runs under bun; pnpm installs it)
export SUI_ADMIN_SECRET_KEY="your-base64-encoded-key"
export IKA_COIN_ID="your-ika-coin-id"
pnpm --filter @demo/backend dev

# Frontend
pnpm --filter @demo/frontend dev
```

[View detailed documentation →](keyspring/README.md)

---

### 🔐 ikavery - Quorum-Gated Key Custody

**Location:** `ikavery/`

Import an existing private key into an Ika dWallet, put it behind a t-of-N
roster of passkeys or wallet credentials, and recover the assets by sweeping
them once a quorum signs. Ships parallel Sui and Solana deployments over a
shared design layer.

**Features:**

- Import an existing private key into an Ika 2PC-MPC dWallet
- Enrol WebAuthn passkeys (Face ID, Touch ID, Windows Hello), connected wallets,
  or zkLogin identities via Enoki
- Change the roster and threshold later, under the same quorum rules
- Propose a sweep and approve it with t of N credentials
- Sweep native and token balances to a recovery address

**Tech Stack:**

- **Smart Contracts:** Move on Sui, Quasar program on Solana
- **Frontend:** Next.js 16, React 19, Tailwind v4
- **Sui access:** `@mysten/sui` v2 over gRPC with dApp Kit 2, Enoki, WebAuthn
- **Integration:** Ika 2PC-MPC for key import, quorum-gated signing

**Quick Start:**

```bash
pnpm install                          # from the repository root
pnpm --filter ikavery-frontend dev
```

[View detailed documentation →](ikavery/README.md)

---

## Getting Help

- **Documentation:** See individual example README files
- **IKA Docs:** Check the main [IKA documentation](https://docs.ika.xyz/)
- **Issues:** Open a GitHub issue for bugs or questions

## Contributing

Want to add a new example or improve existing ones?

1. Fork the repository
2. Create your example in a new directory
3. Include a comprehensive README
4. Add security warnings for testnet-only usage
5. Submit a pull request

**Requirements for New Examples:**

- Clear documentation with setup instructions
- Security warnings prominently displayed
- Testnet-only configuration
- Well-structured code with comments
- Example usage and screenshots
