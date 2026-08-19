# sui — Move recovery layer

The Sui-deployed half of Ikavery. A Move package (`recovery`) plus a
TypeScript SDK and a Next.js frontend that imports a Solana private key
into an Ika 2PC-MPC dWallet, places it behind a passkey-gated quorum, and
sweeps it to a destination wallet on demand.

Live at `sui.ikavery.com` (testnet).

## Layout

```
sui/packages/
├── contracts/
│   └── recovery/        Move package (`recovery::*`)
├── sdk/                 @fesal-packages/ikavery-sui-sdk
└── frontend/            ikavery-frontend (Next.js)
```

The frontend pulls shared design primitives from
[`packages/frontend-ui/`](../packages/frontend-ui) at the repo root.

## Stack

- Sui Move (testnet · `framework/testnet` rev) + Ika dWallet 2PC-MPC
- `@ika.xyz/sdk`, `@mysten/sui` v2, `@mysten/dapp-kit`, `@mysten/enoki`
- WebAuthn passkeys via `@simplewebauthn/browser`
- `@solana/web3.js` + `@solana/spl-token` for sweep tx construction
- Bun + Turborepo + Tailwind v4

## Quickstart

```bash
bun install                                # from repo root
bun run move:build                         # sui move build → packages/contracts/recovery
bun --cwd sui/packages/sdk run codegen     # one-shot: generate BCS bindings
bun run typecheck                          # turbo typecheck across packages
bun --cwd sui/packages/frontend run dev    # localhost:3000
```

The `codegen` step runs `sui move summary` against the recovery package and
then `sui-ts-codegen generate` in the SDK. Both outputs
(`packages/contracts/recovery/package_summaries/` and `packages/sdk/src/generated/`)
are gitignored — re-run after any Move package change.

## End-to-end scripts

`packages/sdk/scripts/` runs against testnet + Solana devnet:

| Script                  | What it proves                                              |
| ----------------------- | ----------------------------------------------------------- |
| `e2e-recover.ts`        | Import key → propose → t-of-N approve → broadcast SOL sweep |
| `e2e-recover-spl.ts`    | Same, with multi-mint SOL+SPL sweep bundle                  |
| `e2e-roster-change.ts`  | Add/remove members + change threshold mid-life              |
| `e2e-multi-member.ts`   | 5-member, 3-of-5 provisioning + share segregation           |
| `e2e-enrollment-spl.ts` | New device enrollment + SPL recovery in one run             |
| `e2e-retry-spl.ts`      | Replay the recovery half against an existing dWallet        |

Each script needs a `.env.local` with `SUI_KEYPAIR_*`, `RECOVERY_PACKAGE_ID`,
`RECOVERY_REGISTRY_ID`, and Solana paths — see headers in each file for the
exact env vars.

## Move package

Published in: `sui/packages/contracts/recovery/`

| Module                   | Purpose                                                       |
| ------------------------ | ------------------------------------------------------------- |
| `recovery::recovery`     | `Recovery` shared object, propose / approve / execute         |
| `recovery::sweep_intent` | Parse + hash structural intent of a Solana sweep tx           |
| `recovery::auth`         | Per-scheme credential verification (passkey / ed25519 / etc.) |
| `recovery::registry`     | Owner → `Recovery` index for vault-list pages                 |

## Frontend

`packages/frontend/` is a Next.js App Router app with Tailwind v4 + framer +
shadcn-derived primitives. The shared design system (Shell, Bento,
DisclaimerModal, VaultDial, motion presets) lives in the workspace package
`@fesal-packages/ikavery-frontend-ui` and is consumed identically by the
Solana frontend at `solana/packages/frontend/`.

The Sui-specific surface is in `components/` (wallet-connect via dapp-kit,
app-shell-header, app-disclaimer-modal) and `lib/` (recovery-client,
session, sponsored-sign, passkey discovery, etc).
