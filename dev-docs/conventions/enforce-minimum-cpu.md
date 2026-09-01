# enforce-minimum-cpu — who enforces the 16-core minimum, and when

Decision rule — ALL three must hold, otherwise nothing is enforced:

1. the `enforce-minimum-cpu` cargo feature is compiled in (an
   `ika-node` default feature; some test builds drop it with
   `--no-default-features`),
2. the process runs as a **validator** (`NodeMode::Validator` — the
   `ika-validator` binary, or `ika-node` auto-detected as validator).
   Fullnodes and notifiers never enforce,
3. the **IKA network** is testnet or mainnet:
   `ChainIdentifier::from(sui_connector_config.ika_system_object_id).chain()`
   compared against the compiled-in ika chain identifiers
   (`ika-types/src/digests.rs`). This is ika's own identity, NOT the Sui
   settlement chain — an ika devnet/staging network deployed on Sui
   testnet must not enforce. Anything unrecognized (every localnet) maps
   to `Chain::Unknown` → no enforcement.

The gate is `should_enforce_minimum_cpu` in `ika-core/src/runtime.rs`,
decided once in `IkaRuntimes::new` and stored in a `OnceLock`. Two
consumers read that one decision and therefore always agree:

- the global rayon pool built at startup (`total cores -
  TOKIO_ALLOCATED_CORES` when enforcing; all cores otherwise), and
- the MPC orchestrator's computation-core budget
  (`calculate_num_of_computations_cores`), queried after startup.

When enforcing, startup asserts ≥ 16 cores and panics below that.

## Consequences

- Production **notifier/fullnode** images (docker builds use default
  features) run on any host size — before the runtime gate they hit the
  same 16-core assert as validators.
- CI and localnet builds of the CURRENT checkout need no feature
  juggling: default features are inert there (localnet ika system
  objects map to `Chain::Unknown`).
- The upgrade-test harness's own builder still builds OLD refs
  `--no-default-features` (`ika-upgrade-test/src/binary.rs`): at historical
  tags enforcement was compile-time-only and panics on cgroup-throttled /
  <16-core pods. Do not "clean" that flag — it is there for refs older than
  the runtime gate, not for the ref the suite happens to target today.
  `.github/workflows/upgrade-test.yaml` is the opposite case and is also
  deliberate: its OLD build step passes NO feature flags, because the ref it
  builds (v1.4.0) already carries the runtime gate and the CI localnet's ika
  system object maps to `Chain::Unknown`.
- `IKA_PROTOCOL_CONFIG_CHAIN_OVERRIDE` (honored only when the real
  chain is `Unknown` — `ika-types/src/digests.rs`) makes a localnet
  claim testnet/mainnet for protocol-config selection, and that ALSO
  activates the CPU gate on a validator built with default features. No
  CI path sets it.
