# Local Sui + ika localnet

For SDK integration tests, reproduction rigs, and manual poking.

## Start

```bash
# 1. Sui localnet — the binary version MUST match the workspace pin
#    (see ../conventions/sui-version-bump.md). A mismatched sui completes
#    the network DKG but silently stalls reconfiguration — the failure
#    appears one epoch later and nothing points back at the version.
sui --version   # must match the mainnet-vX.Y.Z tag in root Cargo.toml
#    The data-ingestion dir doubles as a checkpoint archive for the ika
#    validators (next step): the localnet fullnode prunes aggressively,
#    and a checkpoint pruned before the validators' pusher fetches it is
#    otherwise lost permanently — one lost session-request event can
#    wedge an epoch close (issue #2018).
sui start --with-faucet --force-regenesis \
  --data-ingestion-dir /tmp/sui-ingestion > /tmp/sui.log 2>&1 &

# 2. ika localnet on top (it expects the Sui RPC at 127.0.0.1:9000).
#    5-minute epochs are the validated sweet spot: too long stalls the
#    network-key DKG; too short fails dWallet DKG with
#    InvalidMPCPartyType (3/4 convergence).
RUST_LOG="warn,ika=info,ika_node=info,ika_core=info" \
  ./target/release/ika start --force-reinitiation --epoch-duration-ms 300000 \
  --sui-checkpoint-archive-url file:///tmp/sui-ingestion \
  > /tmp/ika.log 2>&1 &
```

For MPC debugging add
`,ika_core::dwallet_mpc=debug,ika_core::sui_connector::sui_executor=debug,ika_core::sui_connector::sui_syncer=debug`
to `RUST_LOG` — the post-mortem playbook assumes those.

## Readiness

Don't start traffic at "process is up" — requests fail with
`validate_network_encryption_key_supports_curve` MoveAborts until
per-curve key support registers (it lands around the FIRST epoch close).
The robust gate is the second epoch:

```bash
until grep -q "run_epoch epoch=2" /tmp/ika.log; do sleep 10; done
```

## Traps

- **`ika start --force-reinitiation` republishes contracts with FRESH
  object ids** every run. Never read coordinator/package ids from a
  previous run's `~/.ika/ika_config/network.yaml` — parse the current
  run's publish output in the ika log (`Package \`ika_dwallet_2pc_mpc\`
  published: ...`).
- **Cumulative load degrades a single localnet session**: many heavy test
  files against ONE localnet slow signs progressively without any code bug.
  Measured across one session: 43 s, then 374 s, then timeout — while
  `sign_failures` stayed 0 throughout. That last detail is the tell. A
  failing sign increments the counter; a sign that is merely starved does
  not, so a timeout with a flat `sign_failures` is a host resource limit,
  not a correctness regression.
  **Validate each heavy file on a FRESH localnet before believing a
  timeout.** A timeout at the end of a long multi-file session is evidence
  about accumulated load, not about the change under test — and reading it
  the other way costs a debugging session aimed at innocent code.
- **Test suites**: run via
  `sdk/typescript/scripts/run-integration-tests-sequential.sh
  [--timeout <s>] [--filter <stem>]`. Per-case default is 20 min; the
  SDK/`retryUntil` poll budget is 15 min per call — a session astride an
  epoch boundary legitimately waits out the boundary, so don't "fix"
  slow polls by shrinking budgets.
- All validators run in ONE `ika start` process: per-validator log
  attribution is via the `node{name=k#...}` span; CPU is shared (a busy
  validator starves the others on a laptop).
