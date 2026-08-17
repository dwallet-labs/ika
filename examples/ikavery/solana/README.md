# solana — Quasar recovery layer

The Solana-deployed half of Ikavery. A Quasar program (`ikavery`) plus a
TypeScript SDK and a Next.js frontend that imports a Solana private key
into an Ika dWallet (pre-alpha mock signer), places it behind a wallet-
or passkey-gated quorum, and sweeps it to a destination wallet on demand.

Live at `solana.ikavery.com` (devnet · pre-alpha).

## Layout

```
solana/packages/
├── program/             ikavery, Quasar program (Rust)
│   ├── Cargo.toml       crate manifest + [profile.release]
│   ├── Quasar.toml      Quasar project config
│   └── src/
├── sdk/                 @fesal-packages/ikavery-solana-sdk
└── frontend/            ikavery-solana-frontend (Next.js)
```

The frontend pulls shared design primitives from
[`packages/frontend-ui/`](../packages/frontend-ui) at the repo root, so the
visual layer is byte-identical to `sui.ikavery.com`.

## Stack

- Quasar program — Solana mainnet runtime, deployed to devnet
- Ika dWallet pre-alpha (mock signer) at
  `pre-alpha-dev-1.ika.ika-network.net` — see [Ika Solana pre-alpha
  docs](https://solana-pre-alpha.ika.xyz/)
- `@ika.xyz/pre-alpha-solana-client` (gRPC) + raw BCS for variants the
  wrapper doesn't expose (Curve25519/EdDSA `Presign` / `Sign`)
- `@solana/web3.js` + `@solana/spl-token`
- [dynamic.xyz](https://dynamic.xyz) for wallet auth in the frontend
  (env id `9dd6152b-680a-4322-bee8-69fced543f9a`)
- Bun + Turborepo + Tailwind v4

## Pre-alpha disclaimer

This runs on Ika's **pre-alpha mock signer**, not production MPC. Devnet
resets without warning, the protocol is not final, and the network is not
distributed. Devnet keys only — never import a key that holds real funds.

## Quickstart

```bash
bun install                                          # from repo root
cd solana/packages/program
quasar build                                         # → target/deploy/ikavery.so
solana program deploy target/deploy/ikavery.so \
  --program-id target/deploy/ikavery-keypair.json    # deploy to devnet
cd -
bun run typecheck                                    # turbo typecheck across packages
bun --cwd solana/packages/frontend run dev           # localhost:3000
```

Currently deployed program id:
**`6kdyWi8FJah4xt2SyL2fEBFYacQ7iaDsgQjKCDhgEbCi`** — keep
[`packages/program/src/lib.rs`](packages/program/src/lib.rs)'s
`declare_id!` and the SDK's `IKAVERY_PROGRAM_ID` in lock-step with this.

## Program

Quasar / Cargo crate at `packages/program/`. Mirrors the Sui-side
`recovery::*` modules:

| Path                    | Purpose                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `src/lib.rs`            | `declare_id!` + ix dispatch                                                                 |
| `src/state.rs`          | `Recovery`, `Proposal`, `RosterChangeProposal`, `EnrollmentProposal`, `*Approval`           |
| `src/instructions/*.rs` | propose / approve / execute for recovery, roster-change, enrollment                         |
| `src/auth/*.rs`         | Per-scheme credential verification: ed25519, secp256k1, secp256r1, webauthn, solana-address |
| `src/sweep/intent.rs`   | Re-parse + Keccak-256 hash a v0 message's _structural_ intent (compute-budget filtered)     |
| `tests/integration.rs`  | litesvm coverage                                                                            |

`MAX_MEMBERS = 8` — Solana's 1232-byte tx packet cap forces this lower
than Sui's 16.

## SDK

`@fesal-packages/ikavery-solana-sdk` lives at `packages/sdk/`. Reads,
codecs, ix builders, send-and-confirm flows, and a `dwallet/` namespace
for the ika pre-alpha CPI surface (PDA derivation, `TransferOwnership`).

| Section                | What's there                                                                   |
| ---------------------- | ------------------------------------------------------------------------------ |
| `src/constants.ts`     | Program id, ix discs, scheme tags, status flags                                |
| `src/pda.ts`           | All on-chain PDA helpers                                                       |
| `src/codec/`           | Account decoders for Recovery / Proposal / etc.                                |
| `src/ix/`              | Per-instruction wire encoders                                                  |
| `src/flows/`           | Send-and-confirm wrappers (recovery, roster-change, enrollment, state readers) |
| `src/sweep/message.ts` | Build v0 sweep messages (SOL / SPL / ATA / close-account)                      |
| `src/dwallet/`         | Ika pre-alpha PDAs + `TransferOwnership` ix                                    |

## End-to-end scripts

`packages/sdk/scripts/` — all runs against devnet + Ika pre-alpha gRPC:

| Script                 | What it proves                                                                     |
| ---------------------- | ---------------------------------------------------------------------------------- |
| `e2e-recover.ts`       | DKG → import → propose → approve → execute (CPI) → gRPC sign → broadcast SOL sweep |
| `e2e-recover-spl.ts`   | Same flow with a SOL+SPL bundle in one tx                                          |
| `e2e-roster-change.ts` | 3-member roster, propose/approve drop + threshold lower, execute                   |
| `e2e-enrollment.ts`    | Add a new member via the enrollment flow                                           |
| `e2e-multi-member.ts`  | 3-of-5 threshold mechanics + double-approve rejection                              |
| `e2e-retry-spl.ts`     | Same Recovery PDA replayed across two proposals                                    |

Each script needs `SOLANA_KEYPAIR=...` (devnet-funded) and optionally
`SOLANA_RPC` / `IKA_GRPC` overrides — see headers in each file.

## Frontend

`packages/frontend/` is a Next.js App Router app consuming
`@fesal-packages/ikavery-frontend-ui` from the repo root. Auth is brokered
by dynamic.xyz; the connected wallet's pubkey is the
`SCHEME_SOLANA_ADDRESS` credential the program verifies via its on-chain
ed25519 precompile gate. No passkey ceremony — that scheme stays
available in the program for future enrollment paths but isn't on the
default ramp.
