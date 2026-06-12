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
  ("Address already in use") — and the window can be SECONDS when setup
  work sits between probe and bind (the joiner spawn did several
  on-chain txs in between). → Rule: hold a cross-process lock from probe
  to bind, and audit every node-spawn path, not just the boot path.
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
- **Test-harness state that production syncs from chain must be set
  explicitly.** The in-process harness never syncs the epoch-close lock
  target, so it stays 0 and (correctly) gates everything; tests set it
  past their sequence numbers. When adding a gate on synced state, grep
  the harness for tests that now need it.

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
