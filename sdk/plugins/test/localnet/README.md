# Localnet tests

End-to-end plugin tests against real localnet chains. Validates that what each destination produces
is byte-for-byte accepted by the chain's state-transition rules, and that the Ika source plugin can
resolve a live local network.

## What runs locally

| Chain    | Service                   | Port            | What's tested                                                          |
| -------- | ------------------------- | --------------- | ---------------------------------------------------------------------- |
| Bitcoin  | `bitcoin-core` regtest    | `18443`         | P2WPKH + P2TR script-path sign → broadcast → confirm                   |
| Ethereum | `anvil`                   | `8545`          | EIP-1559 tx sign → broadcast → receipt; EIP-191 personal_sign recovery |
| Solana   | `solana-test-validator`   | `8899`          | airdrop → versioned tx sign → broadcast → confirm                      |
| Sui      | `sui start --with-faucet` | `9000` / `9123` | faucet → tx sign → publisher broadcast                                 |
| Ika      | `ika start` (in-process)  | (internal)      | swarm boots, publishes contracts, `ika_config.json` is readable        |

The destination tests still use a mocked source keypair (see `_helpers/source.ts`) — fast,
deterministic, doesn't depend on Ika being up. The Ika container exists for the **source** tests
(`sui-source.localnet.test.ts`), which verify that the SDK can talk to a real running Ika MPC
network.

## Running

### One-time setup (first run only)

The `ika` service builds the Rust workspace from source — the crypto deps live in a private GitHub
repo, so the build needs a token:

```bash
export GITHUB_TOKEN=<token with repo:dwallet-labs/inkrypto read>
docker compose -f sdk/typescript/test/localnet/docker-compose.yml build ika
```

Expect **15–25 minutes** the first time. Layer caching keeps rebuilds fast unless `crates/` changes.

### Start the stack

```bash
docker compose -f sdk/typescript/test/localnet/docker-compose.yml up -d
```

Wait ~60s after this returns. The Ika container takes a while to publish the Move packages and run
network DKG; `ika_config.json` only appears once it's done. Track progress with:

```bash
docker compose -f sdk/typescript/test/localnet/docker-compose.yml logs -f ika
```

### Run the tests

```bash
cd sdk/typescript
pnpm vitest run test/localnet
```

To target one chain:

```bash
pnpm vitest run test/localnet/bitcoin.localnet.test.ts
pnpm vitest run test/localnet/ethereum.localnet.test.ts
pnpm vitest run test/localnet/solana.localnet.test.ts
pnpm vitest run test/localnet/sui.localnet.test.ts
pnpm vitest run test/localnet/sui-source.localnet.test.ts
```

When a chain's endpoint isn't reachable the suite **skips** with a warning rather than failing — you
can run a single chain's tests without booting the others.

### Tear down

```bash
docker compose -f sdk/typescript/test/localnet/docker-compose.yml down -v
rm -rf sdk/typescript/test/localnet/ika-state  # wipes the published config
```

## Endpoint overrides

| Variable              | Default                                                  | Notes                                   |
| --------------------- | -------------------------------------------------------- | --------------------------------------- |
| `BITCOIN_RPC_URL`     | `http://test:test@127.0.0.1:18443/`                      | bitcoind JSON-RPC (basic auth in URL)   |
| `ANVIL_URL`           | `http://127.0.0.1:8545`                                  | anvil JSON-RPC                          |
| `SOLANA_RPC_URL`      | `http://127.0.0.1:8899`                                  | solana-test-validator JSON-RPC          |
| `SUI_LOCALNET_URL`    | `http://127.0.0.1:9000`                                  | sui localnet JSON-RPC                   |
| `SUI_FAUCET_URL`      | `http://127.0.0.1:9123/v2/gas`                           | sui faucet HTTP                         |
| `IKA_LOCALNET_CONFIG` | `sdk/typescript/test/localnet/ika-state/ika_config.json` | Ika network config written by the swarm |

## How the Ika container works

`ika start --force-reinitiation` runs the whole network in one process:

1. Generates a fresh publisher keypair, requests SUI from the faucet.
2. Publishes `ika`, `ika_common`, `ika_dwallet_2pc_mpc`, `ika_system` to the local Sui chain.
3. Runs `ika_system::initialize` + a network-DKG bootstrap.
4. Writes the published package + object IDs to `ika_config.json` in its WORKDIR (`/var/lib/ika`,
   bind-mounted to `./ika-state` on the host).
5. Launches all validator processes in-memory (see `ika-swarm::Swarm::launch`).

The CLI flags `--sui-fullnode-rpc-url` and `--sui-faucet-url` are accepted but unused by `start` —
set the Sui endpoints via `SUI_RPC_URL` / `SUI_FAUCET_URL` env vars instead (the docker-compose
already does this).

## Full source → destination e2e

`sui-source.localnet.test.ts` runs the entire pipeline against the real Ika MPC swarm in docker:

1. Generates a fresh Sui keypair, faucets it.
2. `ika.sui.createDWallet({ kind: 'shared', curve: SECP256K1 })` runs a real shared-DKG through the
   swarm (~30s).
3. `dWallet.ethereum.sign({ kind: 'transaction', tx })` requests a presign and a sign — both go
   through the four-validator MPC.
4. `ika.publish(signed)` broadcasts the resulting transaction to anvil and waits for a receipt.
5. Asserts the receipt's `from` matches the dWallet's derived address.

End-to-end run time: ~2.5–4 min on the M-series host setup described above. Pricing is zero on this
localnet, so `suiSource({ ikaFeePerOp: 0n })` lets `coinWithBalance` lower to `coin::zero<IKA>` and
no IKA token bridging is required. The signer still needs SUI gas — the test faucets it on every
run.
