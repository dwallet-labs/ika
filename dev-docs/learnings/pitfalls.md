# Pitfalls — failure classes that cost real debugging time

Each entry: the instance we hit, then the GENERAL rule it taught. The
next occurrence of a class rarely wears the same costume; match on the
rule, not the instance.

## Consensus & determinism

- **A consensus-visible decision must be a pure function of the
  consensus sequence.** Three separate determinism bugs shared this one
  shape: a wall-clock-driven freeze trigger, a locally-installed
  attestation gating a vote, and an instantiation-round baked into
  session ids. If any input to a decision other validators must agree
  with comes from local timing (watch channels, wall clock, "whatever
  has arrived so far"), it WILL diverge under load.
  → Rule: wall-clock-fed inputs run once per service ITERATION, never
  inside the per-consensus-round drain; identifiers and votes derive
  only from consensus-ordered data.
- **Checkpoint contents cannot be gated on locally-synced chain state**
  (it forks checkpoints across validators). Gate what each validator
  *submits to consensus* instead — per-validator divergence there is
  tolerated, and quorum supplies the safety argument. See
  `../specs/epoch-close-session-lock.md`.
- **Strict-equality close predicates make overshoot unhealable.** When a
  protocol predicate is `count == target` and the counter never
  decreases, ONE unauthorized increment wedges forever. Every completion
  path needs the gate; auditing found two that lacked it.
- **Byte-equality output voting convicts honest divergence as malice.**
  A validator with a divergent-but-honest input (e.g. a stale parameter
  set) gets convicted, its messages silently ignored, and the committee
  runs with fault tolerance already spent — the eventual stall surfaces
  far from the cause. In any MPC-silence post-mortem, grep
  `recognized itself as malicious` FIRST.
- **…but that same tally does NOT convict a divergent network KEY — and
  the silence is the danger.** Fault injection established the boundary:
  the output-quorum tally only convicts a validator that computes
  correctly and broadcasts byte-divergent OUTPUT bytes. Corrupt the key
  material instead and nothing is flagged. A divergent *DKG output* is
  inert for signing (all protocol params and shares derive from the
  reconfiguration output; the DKG output is an unused argument on that
  path) and merely makes that validator's own handoff attestation
  mismatch — self-limiting, since peers reject its signature and the cert
  still forms from the honest quorum. A divergent *decryption-key share*
  is worse: threshold signing aborts with
  `FailedToAdvanceMPC(InvalidParameters)` inside
  `interpolate_decryption_shares` / `combine_decryption_shares_semi_honest`
  (those two live in the external `inkrypto` dependency, NOT in this repo —
  `git grep` here finds nothing; `DwalletMPCError::FailedToAdvanceMPC` wraps
  their `mpc::Error`), which is a semi-honest, NON-IDENTIFIABLE abort — the faulty validator
  emits no output (nothing to tally), every peer that includes its share
  fails the same session, and no malicious set is populated. → Rule:
  absence of a malicious flag is NOT evidence of healthy key material. A
  persistently bad share on a live curve fails every session that draws it
  in, forever, with no conviction and no exclusion — a liveness wedge that
  looks like nothing at all. When signing fails repeatedly with
  `InvalidParameters` and all malicious sets are empty, suspect key/share
  divergence, not a byzantine peer.

## Batch processing & error handling

- **`return` inside a batch loop abandons sibling items.** A guard that
  bailed on one stale computation result silently dropped every other
  session's round messages in the same batch — starving sessions
  network-wide. → Rule: per-item guards `continue`; audit any
  batch-processing loop for in-loop `return`s when "some messages never
  arrived" appears.
- **`.ok()?` on a fallible call inside a hot loop is a black hole.** A
  session whose data generation failed was skipped every 20ms tick with
  no log at any level; two post-mortems were blinded by it. → Rule: a
  skip may be correct, but a *silent* skip never is — log once per
  entity (deduped), then skip.
- **Completion updates sent through a captured runtime handle leak
  bookkeeping when the runtime dies.** Started-never-completed counters
  (orchestrator slots) are the visible symptom. → Rule: any
  spawn-and-report-back pattern needs an answer for "what if the
  receiver/runtime is gone when the work finishes?"

## Performance

- **Eager `std::backtrace::Backtrace::capture()` on success paths +
  `RUST_BACKTRACE=1` = catastrophic, invisible slowdown.** Library code
  constructing backtrace-carrying errors via `ok_or(Error::from(..))`
  (eager) instead of `ok_or_else` ran millions of globally-locked DWARF
  unwinds: ~5x CPU, 23x sys-time, NEGATIVE multi-thread scaling. Looked
  exactly like "this hardware is slow". → Rule: error CONSTRUCTION must
  be lazy on hot paths; when one environment is mysteriously slower than
  another, diff the env (especially `RUST_BACKTRACE`) before blaming
  platforms. Sys-time explosion + worse-with-more-threads = global lock,
  not compute.
- **A Dockerfile `ENV`/`export` inside a `RUN` layer doesn't persist.**
  Production "ran with jemalloc" for months via an `LD_PRELOAD` that
  died with its RUN layer. → Rule: runtime env goes in `ENV` directives
  (or better, compile the dependency in); verify what a container
  actually runs, not what the Dockerfile appears to say.

## Testing & infrastructure

- **Probe-then-bind port allocation races across processes.** Two test
  processes probing for free ports then binding later collide
  ("Address already in use"). A cross-process *boot lock* is NOT enough:
  it serializes boots, but other tests' swarm nodes stay alive (holding
  their ports) while their bodies run unlocked, and the probe — `TcpListener`
  on a port that a live node holds for *UDP* (anemo/QUIC binds UDP; TCP
  free-ness says nothing about UDP, which has no TIME_WAIT) — hands out a
  doomed port. This flaked the cluster suite in BOTH swarm layers:
  `ika_node::IkaNode::create_p2p_network` and (via the injected base chain)
  `sui_node::SuiNode::create_p2p_network`. → Rule: don't probe — PRE-ALLOCATE
  a disjoint, deterministic port block per test PROCESS, keyed on
  `NEXTEST_TEST_GLOBAL_SLOT` (unique among concurrently-running tests), so no
  two tests ever share a port for the lifetime of their nodes. See
  `crates/ika-config/src/local_ip_utils.rs::deterministic_port_base` and its
  use in `ika-test-cluster` (ika validators/joiners via
  `with_deterministic_ports`; the upstream Sui validators via a
  `ConfigBuilder` `NetworkConfig` injected with `set_network_config`, since
  Sui's swarm otherwise probes its own ports). Fullnodes ride along — they
  reuse a validator's deterministic p2p port and only probe TCP admin/RPC
  (reliable). Keep the deterministic block below the OS ephemeral range
  (32768+) so it's never handed to an unrelated socket.
- **`tokio::sync::watch` keeps only the last value.** Two sends in a row
  lose the first — test helpers sending event batches must send ONE
  batch. Symptom: the first event simply never happened.
- **`tracing_subscriber::fmt().init()`-style setup in tests caps at INFO
  and ignores RUST_LOG; `init()`/`init_for_testing()` panic if another
  in-process test installed a subscriber first.** → Rule:
  `fmt().with_test_writer().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))).try_init()`
  and ignore the result.
- **Poll budgets calibrated standalone fail under CI contention.**
  A 60s budget that always passed alone timed out at 4-way parallelism;
  a session that (correctly) waits out an epoch boundary needs minutes.
  → Rule: budgets guard against "never", not "slow" — set them
  generously and keep the budget hierarchy ordered (per-call < per-case
  < per-job) so the failure surfaces with the most specific error.
- **Time-compressed epoch tests: a protocol WINDOW that is a fraction of
  the epoch races a crypto cost that does NOT compress.** Cluster tests
  shrink the epoch (e.g. 120s) to run fast, but the mid-epoch-joiner
  freeze window is `epoch/4`, while the per-peer class-groups
  decode-validate the joiner must clear inside it is a fixed multi-second
  cost. Under 4-way suite parallelism the 30s window fell below the
  contended propagation floor, the `3·epoch/4` deadline froze the input
  set without the joiner, and `test_joiner_lands_in_next_committee_class_groups`
  flaked (joiner missing from `class_groups_public_keys_and_proofs`). The
  production behavior is correct — at hour-long epochs the window is
  minutes; a joiner that truly can't propagate is excluded by design.
  → Rule: when a test compresses the epoch, size it so every
  epoch-FRACTION window still exceeds the ABSOLUTE (non-compressing) work
  inside it WITH margin for CI contention; don't tune to "passes alone".
  (`epoch_scaled_poll_interval` compresses poll cadences but cannot
  compress the crypto.)
  Follow-up (issue #1772): window-sizing alone is NOT sufficient — the
  same test later flaked at 240s epochs (a 60s window) when the localnet
  fullnode went transiently unreachable. No window width is sound
  against environmental stalls; assert eventual consistency with a
  bounded grace (present at the boundary, or present one epoch later)
  instead of lucky-timing first-window capture. AND: before reasoning
  about an assertion's timing semantics, verify WHICH object it reads —
  fault-injecting the fix (joiner P2P fan-out disabled entirely)
  revealed this test's `epoch_store.committee()` map is built from
  CHAIN state (`EpochStartSystem::get_ika_committee`), not from the
  off-chain mpc_data freeze everyone (test docs, issue #1772's own
  diagnosis) believed it measured — the off-chain freeze deterministically
  excluded the joiner and the assertion still passed. Two same-shaped
  committee objects with different provenance (chain read vs off-chain
  assembly) is exactly the setup for this trap.
- **Adding a field to a public config struct breaks struct-literal sites
  in crates a targeted `cargo check` never builds.** Literals that
  construct the config with all fields explicit (no `..Default::default()`)
  fail with `E0063 missing field`. A new `SuiConnectorConfig` field
  compiled clean under `-p ika-core -p ika-node -p ika-config` and then
  broke the test-cluster build ~6 min into CI, because the offending
  literals live in `ika-swarm-config`'s `node_config_builder.rs`.
  → Rule: gate any public struct-field addition on
  `cargo check --workspace --all-targets` — `--all-targets` matters
  because TEST targets construct configs too. `git grep "<StructName> {"`
  finds the sites to update.
- **Test-harness state that production syncs from chain must be set
  explicitly.** The in-process harness never syncs the epoch-close lock
  target, so it stays 0 and (correctly) gates everything; tests set it
  past their sequence numbers. When adding a gate on synced state, grep
  the harness for tests that now need it.
- **An `IkaNodeHandle` held across its node's in-process restart wedges
  the respawn on the RocksDB lock.** The handle holds a STRONG
  `Arc<IkaNode>`; `Node::stop()` joins the node thread, but the stores
  live until the last `Arc` drops — a test-held handle keeps them open,
  and `start()` dies with "Cannot open DB … lock hold by current
  process". Real validator restarts never see this (process death
  releases the lock); it's purely an in-process-swarm hazard. → Rule:
  acquire handles on demand (inside each poll tick / scoped to one
  statement); never bind one across a `stop()`/`start()` of its node.

## Sui types & encoding

- **An "empty" Move struct is one BCS byte, not zero — verify wrapper layouts
  against on-chain bytes.** A marker struct like
  `ika_common::extended_field::Key` reads as empty (`Key()` / no fields), but the
  Move compiler still gives it a `bool` dummy field, so it serializes to a single
  `0x00` byte. Reading the value of an `ExtendedField<V>` means decoding its backing
  `Field<Key, V>` dynamic-field object — `id: UID`(32) ++ `name: Key` ++ `value` — so
  the value sits behind a **33-byte** header (`Field<u8, V>`), NOT 32
  (`Field<(), V>`). The unit-name decode short-reads by exactly one byte and fails
  with bcs "unexpected end of input"; because the value-decode runs out before
  completing, it *looks* like a value/layout mismatch and sends you hunting in the
  wrong struct. The actual cause was found only by dumping the raw on-chain bytes and
  finding a clean parse at offset 33. (Cost: three CI cycles of framing guesses on
  the `pending_active_set` read; `ika-sui-client` `decode_pending_active_set`.)
  → Rule: never trust an assumed BCS wrapper layout — round-trip-decode it against
  real on-chain bytes in a unit test before relying on it, and when a strict decoder
  reports "unexpected end of input", suspect a too-short *header* (off-by-a-name)
  before re-checking the value struct.

## Sui reads & submission

- **Re-reading mutable state from a lagging fullnode between serial
  submissions stalls the pipeline.** The notifier fetched its gas coin via
  `get_gas_objects(address)` before building EVERY tx. That reads the
  notifier's own fullnode, which under checkpoint-heavy load (a presign
  flood) trails the validators by hundreds of object versions — so each tx
  carried a stale gas-coin version and was rejected non-retriably
  ("Transaction needs to be rebuilt because object … version …",
  `-32002`). The retry wrapper re-read the same lagging view, so epoch
  advance stalled outright. Symptom profile that distinguishes it from a
  handoff wedge: `current_epoch` and `last_session` pinned, `sui_tx_err`
  climbing into the hundreds, `mismatch=0`. → Rule: for serially-submitted
  transactions, carry mutable object refs forward from the previous tx's
  EFFECTS (authoritative post-tx version), not from a fresh read; fall back
  to a read only for the first submission.
- **An intermediate on-chain state variant can still carry the last
  completed value — don't infer "no data" from the state name.** The v4
  off-chain fast path treated a network key in state
  `AwaitingNetworkReconfiguration` as having nothing to import, and
  synthesized an empty reconfiguration output. But that variant still
  carries the *last completed* reconfiguration's
  `current_reconfiguration_public_output` — the bytes every validator
  decrypts its current share from. At the v3→v4 boundary those bytes exist
  only on chain (produced pre-migration, never in the off-chain cache), so
  the whole committee fell back to the genesis DKG output and decryption
  failed forever with `WaitingForNetworkKey`. → Rule: when gating a
  chain-read away as "already cached", gate on the presence of the STABLE,
  durably-mirrored artifact (here the DKG output), never on the
  epoch-transient one that is legitimately absent at every epoch start;
  and add a don't-downgrade guard so a later empty synthesis cannot
  overwrite good data already held for the epoch. The decisive diagnostic
  was logging the adopted output's digest AND LENGTH per epoch per
  validator — the boundary epoch showed 0 bytes where the prior epoch had
  17824.
- **`ika_types::digests` and `sui_types::digests` export SAME-NAMED chain
  constants with different meanings.** ika's `{MAINNET,TESTNET}_CHAIN_IDENTIFIER_BASE58`
  decode to the ika **system object IDs** (load-bearing: metric labels,
  short-id matching); Sui's are the genuine **genesis checkpoint digests**.
  Genesis-blob verification recomputes the real Sui digest, so importing
  the constant from the ika crate made the check unsatisfiable — no
  legitimate blob could ever pass, on either network, and the failure
  surfaced only as an operator's boot error with two digests that looked
  equally plausible. → Rule: when two crates in a fork expose identically
  named constants, name the crate explicitly at the import and assert the
  semantic in a test (pin the expected value AND pin inequality with the
  look-alike), because the compiler cannot tell you which meaning you
  wanted.

- **serde `rename_all` does NOT cascade to struct-variant fields.** A
  container-level `rename_all` renames the variants, but fields *inside* an
  enum's struct variants keep their original names unless the variant also
  carries `rename_all_fields` (or each field is renamed). Operator-facing
  config is the blast radius: the documented key silently isn't the key the
  deserializer accepts. → Rule: test the serde round-trip for any
  config/wire enum rather than reasoning about attribute inheritance.
- **An inclusion or authenticity proof is NOT a currency proof.** A validly
  signed, correctly-proven old checkpoint proves an *old* version — forever.
  Verification that answers "did the chain ever say this?" cannot answer "is
  this still true?", and a relay free to choose which proven state to serve
  can pin a reader in the past without ever forging anything. → Rule: when a
  read must be current, say what makes it current (a monotone frontier, a
  freshness bound, a fold over a contiguous stream) — signature validity is
  not it.

## Verifying other people's claims

- **Commit messages and PR titles overstate fixes.** An OCS audit found
  "fixed-by" citations that were false (the credited commit didn't fix it),
  incomplete (fixed one of two paths), or orthogonal. The same review cycle
  found review documents whose own status lines contradicted their summary
  tables. → Rule: reconcile every claimed fix against the code before
  treating a finding as closed — the commit is a hypothesis, the code is the
  evidence. This applies to docs in this folder too: a status line is a
  claim, not proof.

## Dead code & dependencies

- **In a library workspace the `dead_code` lint is nearly blind.** rustc
  treats every `pub` item reachable from a crate's API root as used, so
  unused `pub` fns/structs/enums/variants/fields/consts in a lib crate
  never warn — a clean `cargo check`/`clippy` is NOT evidence of no dead
  code. → Rule: find dead code by workspace-wide reference analysis (grep
  each symbol across `crates/` AND `sdk/`), not the compiler; and in a Sui
  fork, classify (safe to remove vs public API vs upstream-parity vs
  has-a-side-effect) before deleting. Full procedure:
  `../conventions/dead-code-cleanup.md`.
- **A grep-only "unused dependency" verdict produces false positives.** An
  audit declared `eyre` unused in `ika-core`; it was used as `eyre::Result`
  / `eyre::eyre!` in five files, caught only by the build. → Rule: never
  remove a Cargo dep on grep evidence alone — remove it, then
  `cargo check --workspace --all-targets`. Know that command's blind spots:
  it does not build `cfg(msim)` code, the excluded `sdk/*-wasm` crates, or
  non-default features, so a dep used only there compiles clean after a
  wrong removal. Verify those paths (`cargo simtest`, the wasm build,
  `--features <f>`) or leave the dep.

## Repo guard hooks

- **A PreToolUse guard checks repo state BEFORE the command runs — any
  check keyed on mutable repo state can be sidestepped by a compound
  command that mutates that state first.** `.claude/hooks/git-guard.sh`
  gates commits containing `.rs` files on `cargo fmt --all --check`, but
  it detects them via `git diff --cached` *at hook time*: staging and
  committing in one command (`git add … && git commit …`, or
  `git commit -a`) presents an empty index and the gate never fires. The
  commit-on-protected-branch check shares the class (it reads the
  current branch, which the same compound command could switch first).
  The command-string checks (`--no-verify`, push targets) don't — the
  string is immutable. → Rule: treat state-keyed guard checks as a
  backstop, not the contract — run `cargo fmt --all` before committing
  regardless (CLAUDE.md: Git Workflow), and never cite a green guard as
  evidence the gated property held.
- **git-guard reports ANY `cargo fmt` failure as "rustfmt is dirty",
  including cargo failing to launch.** The fmt gate runs
  `cargo fmt --all --check >/dev/null 2>&1`, discarding output and exit
  detail, so a cargo that is absent from the hook's PATH (the hook
  inherits the agent process environment, not a login shell —
  `~/.cargo/bin` may be missing from it) blocks every Rust commit with a
  formatting message even though `cargo fmt --all --check` is clean in
  your terminal. Cost a fresh-workstation session real diagnosis time;
  resolved by putting cargo/rustfmt on a directory the hook's PATH does
  include (e.g. symlinks in `~/.local/bin`). → Rule: when a gate blocks
  with a tool's verdict, first prove the tool actually RAN in the gate's
  environment (re-run the gate's exact command with output visible)
  before debugging the verdict itself.

## Process & forensics

- **Verify the chain/config you're querying is the one the system
  used.** Stale object ids from a previous run's config produced
  "object not found" against a perfectly healthy network. Get ids from
  the run's own publish output.
- **When a fix lands, re-run the ORIGINAL failure's reproduction, not
  just the new tests** — two of three "the wedge" investigations found a
  second, co-resident bug only because the rig kept running after the
  first fix.
- **Distinguish exonerating evidence from absence of evidence.** "The
  pattern predates the change" (found in healthy epochs/old logs) is
  exoneration; "we didn't see it again" is not.
