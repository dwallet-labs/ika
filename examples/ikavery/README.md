# ikavery - Quorum-Gated Key Custody on Sui

> **Reference example, for educational purposes only.** This example shows how
> to use Ika; it is not a production app. It has not been security audited and is not meant to be deployed or
> relied on. See the disclaimer in the [examples README](../README.md).

Import an existing private key into an Ika 2PC-MPC dWallet, put it behind a
t-of-N roster of WebAuthn passkeys or wallet credentials, and recover the assets
by sweeping them once a quorum signs.

---

> ⚠️ **Testnet Only — Developer Warning**
>
> This example is provided for **developer testing and educational purposes
> only** and must be used on **testnet only** (not mainnet).
>
> Never import a key that holds real funds. The contract has not been
> independently audited.
>
> **You assume all risk by proceeding.**

---

## What This Demo Shows

Most key-recovery stories end at "write down a seed phrase". This one replaces
the phrase with a **quorum**: the key lives in an Ika dWallet, and moving funds
requires t of N enrolled credentials to approve — no single device, and no
custodian.

**Features:**

- Import an existing private key into an Ika 2PC-MPC dWallet
- Enrol a roster of credentials: WebAuthn passkeys (Face ID, Touch ID, Windows
  Hello) or connected Sui wallets, including zkLogin via Enoki
- Change the roster and threshold after the fact, under the same quorum rules
- Propose and approve a sweep; the network signs only once the quorum is met
- Sweep native and token balances (SUI, SPL) to a recovery address

It runs as a Move package on Sui testnet, passkey-first via WebAuthn PRF.

## Getting Started

### Prerequisites

- Node.js 24+ (the Active LTS line) and pnpm
- The `sui` CLI, to build the Move package
- A Sui testnet wallet with test SUI and IKA

### Installation

Dependencies are installed from the **monorepo root**, not from this directory —
these packages are pnpm workspace members:

```bash
# from the repository root
pnpm install
```

### Run the Sui app

```bash
pnpm --filter ikavery-frontend dev        # http://localhost:3000
```

### Build the Move package

```bash
cd examples/ikavery && pnpm run move:build
```

Each app ships a `.env.example` documenting the public env variables it needs
(RPC endpoints, deployed package ids, Enoki/Dynamic credentials).

## How It Works

1. **Import.** The user's existing private key is encrypted to the Ika network's
   encryption key and imported as a dWallet. The user keeps a share; the network
   holds the rest.
2. **Enrol.** Each roster member registers a credential — a passkey (WebAuthn,
   with the PRF extension deriving a stable encryption seed) or a wallet
   signature. The member's share of the dWallet is re-encrypted to them.
3. **Propose.** Anyone can propose a sweep to a recovery address. The proposal
   records the destination and the assets to move.
4. **Approve.** Members approve by signing a challenge with their credential.
   The Move package verifies each signature on chain and counts approvals.
5. **Sweep.** Once t of N have approved, the dWallet signs the sweep transaction
   and the assets move — without any single party ever holding the whole key.

## Architecture

```
packages/
├── core/              @ika-examples/ikavery-core         shared cross-chain logic
└── frontend-ui/       @ika-examples/ikavery-frontend-ui  design system + primitives
sui/packages/
├── contracts/recovery/  Move package (recovery::*)
├── sdk/                 @ika-examples/ikavery-sui-sdk
└── frontend/            ikavery-frontend (Next.js)
```

The app is built on `@ika-examples/ikavery-frontend-ui`, the shared design
system. Further detail: [`sui/README.md`](sui/README.md).

### Technology Stack

- TypeScript, Tailwind v4, shadcn-derived primitives, framer-motion
- `@ika.xyz/sdk`
- Move (`framework/testnet`), Next.js 16, React 19
- `@mysten/sui` v2 over **gRPC** — public Sui fullnodes no longer serve JSON-RPC
- `@mysten/dapp-kit-react` (dApp Kit 2, the gRPC-capable rewrite),
  `@mysten/enoki` for zkLogin, `@simplewebauthn/browser` for passkeys

## End-to-End Scripts

`sui/packages/sdk/scripts/` ships scripts that drive the full lifecycle against
live testnet: `e2e-recover`, `e2e-recover-spl`, `e2e-roster-change`,
`e2e-multi-member`, `e2e-enrollment-spl` and `e2e-retry-spl`.

See [`sui/README.md`](sui/README.md) for the env vars each script needs.

## Status

Pre-alpha, testnet only. Built on the Sui SDK v2 gRPC stack.

## Learn More

- [Ika documentation](https://docs.ika.xyz/)
- [Sui SDK v2 migration guides](https://sdk.mystenlabs.com/sui/migrations/sui-2.0)
