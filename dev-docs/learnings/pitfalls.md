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
- **A per-round drain decision kept only in memory can flip on the
  restart replay — even when every INPUT is consensus-derived.** A restart
  re-runs every round of the epoch against durable per-epoch state (presign
  pools, marker tables) that is NOT rewound to the round being replayed.
  (Historical detail: at the time the rounds came from persisted per-round
  tables; they now reach the drain from the fold over a channel. The hazard
  is unchanged — it is about the DURABLE state the replay runs against, not
  about how the rounds arrive.) Instance: the NOA presign-demand
  park bound dropped a demand from the in-memory queue at round R_e; the
  demand's key pool then filled at a later round; on restart the replayed
  drain re-read the demand at its delivery round against the
  now-non-empty durable pool and ASSIGNED a presign every peer (and the
  validator's own pre-crash self) had abandoned — silently diverging the
  demand→presign pairing for the rest of that pool. The pre-existing
  drain was replay-safe only through an implicit invariant (a demand
  still unassigned in the queue implies its pool is empty), which the new
  eviction path broke. → Rule: for every decision a consensus drain makes,
  ask "if this were forgotten and re-derived during replay against
  POST-CRASH durable state, would it come out the same?" If not, the
  decision itself must be durable — record the terminal outcome in the
  same per-demand marker table that records the positive case (one
  resolution per demand: `Assigned | Evicted`), so replay short-circuits
  on the recorded answer instead of re-deciding. This is the
  time-of-replay sibling of the wall-clock rule above: inputs can all be
  consensus-ordered and the decision still diverges, because durable
  state advanced between the original visit and the replayed one.
  → **Retired for one class, still live for the other.** State the commits
  determine is held in memory and rebuilt by replaying the epoch's commits,
  so replay against non-rewound durable state no longer happens for any of
  it. It is unchanged for what remains on disk — the
  presign pools and their markers, which is where the instance above lived
  and where the rule still bites. What stays, and why:
  `../preserved-epoch-state-audit.md`.
- **One logical fact in two databases is a brick waiting for a storage
  incident.** "How much of this epoch has been consumed" lived both in
  Mysticeti's commit store and in ika's per-epoch watermark, with no shared
  fsync discipline. A CSI failure cost the consensus store its unsynced tail
  while the watermark survived, the two disagreed by one commit, and
  `CommitObserver::recover_and_send_commits` asserts the ordering — so the
  validator aborted on every boot until the epoch rolled over, up to 24h
  (ika #2057). Note the shape: neither store was corrupt, and each was
  individually consistent.
  → Rule: when a fact is recoverable from another component's durable state,
  DERIVE it there rather than keeping a copy. Reconciling copies shrinks the
  disagreement window; deleting the copy removes it. Where the copy is a
  cache of expensive work, the question to ask is whether the work is
  cheaper than the failure mode — here a full-epoch replay costs minutes and
  the copy cost a day of downtime.
- **A test that asserts a declaration against itself catches nothing.** The
  per-epoch derived/preserved classification was first enforced by a wipe
  test and a double-fold test; injecting the exact mistake they existed to
  catch (a fold-written table declared preserved) left both GREEN. The wipe
  test checked each table against its declared class, so a wrong declaration
  agreed with itself; the double-fold passed because the per-round tables
  were keyed by round and a second fold simply overwrote them. (Those tables
  no longer exist — the drain is fed by a channel — but the lesson outlived
  them, and recurred twice more in the same change: a watchdog-hold test that
  drove the state machine directly never noticed the wiring being deleted,
  and a drain-departure test asserted a property tokio provides rather than
  the one the code adds.)
  → Rule: an enforcement test needs a source of truth INDEPENDENT of the
  declaration — here, folding real commits and requiring every table that
  actually got written to be declared derived. And this is only visible if
  you inject the mistake: both tests read as thorough.
  → **Better still, delete the declaration.** The classification is gone: a
  `DBMap` field survives a restart by definition and an in-memory field is
  rebuilt by definition, so there is no second list to agree with itself and
  nothing left to enforce. A rule you can make structural beats a rule you
  have to test, and the enforcement test is worth writing only for the part
  that stays declarative.
- **A test harness that stubs out the component under change tests
  nothing, and stays green while doing it.** The MPC integration harness
  built its services with no round receiver, so when the per-round tables
  became a channel the drain became a no-op in all ~100 tests — which kept
  passing for everything that did not need round content, and started
  failing for everything that did. The failures were then misread as a
  known local-run artifact (a concurrent build replacing the test binary),
  because that artifact had genuinely happened twice before.
  → Rule: when a change replaces a data path, the harness's substitute for
  that path is part of the change — migrate it in the same PR, and treat a
  new failure pattern as evidence about the code until the code is
  eliminated, not the other way round. A plausible known-artifact
  explanation is the easiest way to discard a real regression.
- **Migrating a fan-out from rows to messages changes arity, silently.**
  The same harness distributed each round by appending every submitter's
  messages into one per-round ROW; rewritten naively over a channel it sent
  one MESSAGE per submitter, i.e. four copies of round N to each validator.
  Rows are addressed and idempotent; messages are sequenced and are not.
  → Rule: when a keyed store becomes a stream, re-check every writer's
  arity — "extend the entry for key K" becomes "send exactly one K",
  and the loop that was harmless to repeat is not.

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

- **A metric-label fixture invented by the test author validates the
  test against itself.** A cluster assertion matched validators by their
  full `AuthorityName` (`k#` + 64 hex), but
  `ika_dwallet_mpc_user_session_output_received_from` labels by
  `authority_name.concise()` (`k#` + 8 hex + `..`). The matcher could
  never match anything. Its unit tests passed because the fixtures used
  the same invented string — `"k#subject"` — on BOTH sides of the
  comparison, so the format was consistent with itself and wrong about
  reality. The cost: a scenario that polled for 30 minutes and then
  reported that a perfectly healthy validator "is following consensus
  without contributing MPC" — a false accusation aimed at the feature
  under test rather than at the instrument.
  → Rule: a fixture for a metric, log line, or any other emitted format
  must reproduce the REAL emission, copied from the SET SITE (grep the
  `with_label_values` call, not the registration) — never a placeholder
  that only has to satisfy the code being tested. Where a series can be
  labelled by more than one rendering of the same identity, accept every
  rendering and keep a test that pins what happens when one is missing.
- **An assertion that cannot see a healthy subject is indistinguishable
  from a broken subject.** The same bug would have been caught in
  minutes by pointing the instrument at the subject while it was known
  healthy, before the phase under test. → Rule: a long scenario whose
  verdict depends on a per-node observation should CALIBRATE in-run —
  run the identical instrument against a healthy subject first and fail
  there, naming the instrument, if it sees nothing. It also measures the
  observation latency the later phase has to budget for.
- **Per-session metric series are ephemeral; the poll that misses them
  is not evidence of absence.** `user_session_*` gauges are zeroed when
  a session leaves the manager's active map, so a 5-second poll simply
  misses short sessions. → Rule: for "did X ever happen", ACCUMULATE
  observations across a fast poll instead of sampling; a single read
  answers only "is X happening right now".
- **In a 4-validator committee one honest output is always
  superfluous.** Any 3 of 4 form a quorum, so a session can complete
  before the fourth finishes computing, and that validator's output is
  never observed by anyone — measured at 147 of 306 quorums on a healthy
  cluster. An assertion of the form "a peer must witness THIS
  validator's output" is therefore a coin flip per session, and it
  worsens for a node that just restarted, which is the slow one.
  → Rule: pair a quorum-observable assertion with one that a race cannot
  answer falsely (a local completion counter), and read the pair.
- **A poll that outlives the window it is about produces a confident
  wrong diagnosis.** An assertion bounded only by a generous timeout ran
  30 minutes past an epoch boundary and blamed the subject for a
  question that had stopped being asked once the boundary handed it a
  fresh epoch store. → Rule: bound such a poll on the CONDITION that
  ends its validity (here the epoch ceiling), not only on elapsed time,
  and say in the failure which one fired.
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
- **Settle flake provenance by measurement, not inference: same module,
  same parallelism, base commit.** A branch that adds heavy tests to a
  module and then sees OTHER tests in it fail looks like a regression and
  usually is not — but "my diff can't affect that path" is inference, and
  it has been wrong in this repo before. Instance: after adding four
  drain tests to `network_owned_address_sign`, two E2E sign tests failed
  at `--test-threads=4`; moving the work aside with a temporary WIP
  commit (never a bare stash — the stash stack is shared across
  worktrees) and re-running the SAME module at the SAME parallelism on
  the base commit showed FIVE failures with the identical assertion —
  pre-existing, and the branch was strictly less affected. The
  comparison also caught a refactor (#2042, identity-keyed idempotent
  assignment) FIXING the underlying flake, which a fresh green run alone
  could never have attributed. → Rule: adding tests to a parallel module
  raises its contention and makes every latent race in it more likely to
  fire; before triaging a module failure as yours, reproduce the module
  run on the base commit at the same parallelism and compare failure
  sets. Known latent race still open in that module:
  `test_presign_assignment_is_consensus_ordered_not_local` asserts a
  pool of ≥ 2 presigns in its SETUP ("test needs at least two presigns …
  (pool size 1)") while the wait helper
  `advance_rounds_while_presign_pool_empty` returns as soon as the pool
  is non-empty; it passes alone. The fix belongs in the helper (take a
  minimum pool size), not in the tests that trip it.

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
- **A benchmark can pass vacuously, exactly like a test.** A v2-vs-v3
  epoch-state benchmark ran to completion and produced a clean-looking
  comparison table while measuring almost nothing: its fixture keyed commits
  by `[round as u8; 32]`, so the key space wrapped at 256 distinct values and
  the dedup set under measurement plateaued there — 769 entries for 4,000
  folded transactions. What caught it was not review of the harness but an
  INSTRUMENTATION cross-check: the design's own processed-set gauge, read
  alongside the timing numbers, contradicted the transaction count. → Rule:
  every benchmark needs at least one internal consistency check tying what it
  measured to what it claims to have driven (entries == transactions folded,
  bytes == rows × size), asserted or eyeballed BEFORE the table is trusted —
  a wall-clock number with no witness that the work happened is a claim, not
  a measurement.

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
- **"Unread but written per-version" config is not automatically dead.** A
  `backward_compatible` flag and its `is_*_version_v3` predicates looked like
  leftover scaffolding and were reported as removable; they were
  load-bearing — they select the deployed network's `-10` relaxed
  discrete-log bound, and dropping them switched the reconfiguration proof
  to the strict bound, changing the Fiat–Shamir transcript and forking
  consensus with live v5 validators. → Rule: before deleting or relabeling
  code as dead, trace every reader to a concrete live effect. A
  protocol-config flag that is set per-version with no obvious reader may
  still feed a crypto/consensus parameter downstream; relabeling live
  consensus code as "vestigial" is a correctness risk, not a cleanup.

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

## Library bumps & compatibility claims

- **A wire/consensus/crypto compatibility claim is unproven until the test
  that exercises THAT property is green.** "This bump is wire-compatible"
  was asserted from a determinism unit test that only pinned the network-key
  anchor *reconstruction*, never the live reshare's equality-of-coefficients
  proof; the cross-binary upgrade test later flagged the upgraded node
  malicious. → Rule: don't say "compatible / safe / a no-op" from a test
  that doesn't exercise the exact property. Run the cross-binary / upgrade
  test EARLY; report what's verified vs not, and give a
  recommendation-with-uncertainty, not a verdict.
- **Bumping a crypto/consensus library: read the WHOLE upstream diff, not
  just the change you wanted.** An inkrypto rev intended only to remove
  pre-aggregation types ALSO deleted the relaxed discrete-log-bound
  machinery, silently switching the reconfiguration wire format. → Rule: for
  any crypto/consensus dependency bump, audit the full upstream diff for
  consensus-affecting changes — bounds, limb widths, serialization, anything
  transcribed into a Fiat–Shamir challenge — before implementing. A
  "remove X" changelog can carry a second, unadvertised format change.
- **A PR that must not merge until a prerequisite lands must be a DRAFT.** A
  chained step-2 PR (wire-safe only after step-1's protocol upgrade deploys)
  was opened as a normal PR; a teammate merged it into the step-1 branch and
  it rode into main prematurely, forcing a revert. → Rule: only the base of
  a chain is a normal PR. Every deploy-after-X / protocol-gated follow-up is
  `gh pr create --draft`, with the gating condition ("merge once v6 is
  live") stated in the body.

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
