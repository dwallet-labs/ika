# Test-testing — prove an expensive test actually catches its failure

A passing test only means something if it would behave *differently* when
the property under test is broken. "Test-testing" (fault injection /
mutation testing) proves that: inject a deliberate, minimal fault that
*should* trip the property, confirm the system reacts the way you predicted
**in the logs**, then revert. Most valuable for the slow, opaque
integration tests where a green run is otherwise an act of faith —
upgrade-suite scenarios and cluster/simtest suites asserting things like
serialized-MPC-data continuity, cross-binary wire compat, or malicious-party
detection.

The `/test-testing` skill is the invocable entry point; this playbook is the
methodology it runs.

## The one thing to internalize: the exit code is NOT the assertion

Injected faults produce one of two outcome shapes, and they invert how you
read a green run:

- **Hard-fail** — the fault wedges or aborts the system; the property's
  guard fires and nothing recovers (e.g. strict `bcs` rejects a corrupted
  output → epoch can't advance). The test *fails*. But it may only fail at
  a slow epoch/timeout (~20 min), while the **precise error appears in the
  node logs within minutes**. So: grep for the predicted error, confirm,
  and **stop the run early** — don't wait for the timeout. Here a *green*
  run is a RED flag: the test didn't catch the fault.

- **Recoverable** — the system is *designed* to detect the fault and keep
  going (e.g. honest validators identify a malicious party, exclude it, and
  reshare without it). The test **PASSES** — that's correct behaviour. The
  exit code tells you nothing about whether the fault was caught; the
  **detection log event is the only proof**. A pass *without* that log line
  is the RED flag: the fault may never have triggered (wrong injection
  site, dead code path, fault built into the wrong binary).

Either way, **the log is the assertion.** Predict the exact log message and
where it appears *before* running, then gate on grepping for it. Never
conclude from pass/fail alone.

## The loop

1. **State the property, the fault, the outcome shape, and the expected log.**
   Write down: (a) the invariant, (b) the minimal fault that trips it,
   (c) hard-fail or recoverable, (d) the *exact* log string and which node's
   log it lands in. If you can't predict the log line, you don't understand
   the test yet — read it first.

2. **Pick the injection SIDE deliberately — this is where it's easy to go
   wrong.** Decide what you're testing:
   - "Can consumer X read producer Y's output?" → corrupt **Y's output**
     (producer), observe **X** reject it.
   - "Do honest peers reject a bad actor?" → corrupt **one party's outgoing
     round message** (the broadcast contribution peers verify — *not* the
     final stored output), observe peers mark it malicious.
   Mark the edit unmistakably: `// TEST-TESTING FAULT (temporary — DO NOT MERGE): …`.
   Keep it one byte / one flag / one skipped check.

3. **Make a recoverable test actually survivable.** If the expected outcome
   is recovery, the system must have room to exclude the fault and still
   reach quorum: e.g. fault only a *minority* (one validator of four), allow
   the committee to shrink (`with_min_validator_count(3)`), drop buffer
   stake to a bare quorum (`set_buffer_stake(0)`), and assert the network
   **advances** (reaches the next epoch). The test passing *is* part of the
   expectation; the log line is the rest.

4. **Build only the binary that carries the fault, and name it.** A
   reference binary you can't edit (a fixed release like the literal
   v1.3.1 build) cannot carry a producer fault — put the fault in the
   **local** build and run it as the minority in an otherwise-honest
   committee. Build to a clearly-named artifact (`…-FAULTED` / `…-FAULTY-*`)
   so it's never mistaken for a real binary.

5. **Run, then grep the node logs for the predicted evidence** at
   `$UPGRADE_TEST_DIR/validator-*/node.log`. For hard-fail, confirm-then-kill.
   For recoverable, confirm the test passed AND the detection log is present
   AND it's **specific** (see below).

6. **Check specificity — the built-in control.** A real catch is *targeted*:
   only the faulty output/party is rejected and the rest of the system stays
   healthy. If *everything* fails (or every cross-binary message is
   rejected, or a clean swapped validator is also flagged), you're measuring
   collateral breakage (wire-incompat, setup panic), not the property. When
   in doubt, run a clean control (same setup, no fault) and confirm it does
   *not* produce the evidence.

7. **Revert every fault artifact.** `git checkout` the source, `rm` the
   `…-FAULTED` binary, confirm `git status` is clean and `grep -r
   "TEST-TESTING FAULT"` is empty. The fault is scaffolding; it must never
   land. The test harness *may* stay (it references an externally-built
   faulted binary), but the source mutation does not.

## Prefer the compiled-in fault to a source edit

The reconfiguration-message fault this repo uses most is no longer a source
mutation you add and revert. It lives permanently in the tree behind the
`test-testing` cargo feature, in the main reconfiguration advance path
(`crytographic_computation/mpc_computations.rs`, the
`GuaranteedOutputDeliveryRoundResult::Advance` arm), and appends one trailing
byte to this validator's outgoing round message. It is compiled out of every
normal build, so the only way to produce a faulty binary is an explicit
`--features test-testing`:

```bash
cargo build --release -p ika-node --bin ika-validator --features test-testing
cp target/release/ika-validator /tmp/ika-validator-FAULTY-RECONFIG
```

That is strictly better than editing source: it cannot be forgotten in a
working tree, it cannot merge by accident, and the faulty binary is a named
artifact rather than a build you have to remember is dirty. **When a fault
you need already exists as a feature gate, use it.** Reach for a source
mutation only for a one-off boundary no gate covers, and then follow the
revert discipline in step 7.

## Worked example — recoverable: cross-binary malicious-party detection

Property: in a mixed-binary committee, honest validators identify a
validator that broadcasts a malformed contribution and reconfigure without
it.

Harness: `crates/ika-upgrade-test/tests/malicious_v131.rs`. It boots a
4-validator committee on the HONEST literal v1.3.1 release, lets the genesis
network DKG finish, then swaps ONE validator to the `--features test-testing`
build so it corrupts its outgoing reconfiguration message at the next epoch
boundary.

```bash
gh workflow run upgrade-test.yaml --ref <branch> -f test=malicious_v131
```

Outcome shape: **recoverable** — the honest validators exclude the faulty
one, reshare without it (committee dips to 3), and the network still reaches
epoch 3, so **the test PASSES**. The exit code therefore proves nothing on
its own, which is exactly the trap this playbook exists for. Here the
assertion is programmatic rather than a log grep: the scenario scrapes
`ika_dwallet_mpc_malicious_actors_count` via
`expect_malicious_actors_at_least(&[3], 1)`. The network could reach epoch 3
without flagging anyone, and that is the vacuous pass the gauge assertion
catches.

Specificity check (step 6): only the faulty validator is flagged, while the
committee still reaches quorum. That specificity is the control — it proves
the fault was caught, not that the two binaries are blanket-incompatible. A
wire incompatibility would have failed every cross-binary message and never
reached quorum; had a *clean* swapped validator also been flagged, you would
be measuring incompatibility, not detection.

What a green `malicious_v131` buys you is the right to trust a different
run: it shows `v131_rollout`'s zero-malicious gate would actually fire on a
real divergence, rather than reading zero because nothing ever checks.

## Worked example — hard-fail: running the fault through the gate itself

The same fault, pointed at the compatibility gate rather than at the
detection test, inverts the outcome shape:

```bash
gh workflow run upgrade-test.yaml --ref <branch> \
  -f test=v131_rollout -f test_testing_fault=true
```

`v131_rollout` requires mixed reshares to converge byte-identically with
ZERO malicious reports, so a faulty validator must break it. **This run is
expected to FAIL**, and its logs must show the specific zero-malicious or
output-convergence assertion firing. A green run here is the red flag: it
would mean the gate's own assertions are vacuous.

This is the general shape worth internalizing — one fault, two harnesses,
opposite expected exit codes. Neither exit code is the assertion by itself;
what you check is that the predicted evidence appeared in the predicted
place.

## Artifacts and logs

Node logs land at `$UPGRADE_TEST_DIR/validator-*/node.log` locally. From a
CI dispatch, pull `upgrade-test-node-logs-<test>-<attempt>` (see
[`ci-suites.md`](ci-suites.md)) — and note that a runner-pod death drops
every artifact, so a run with no logs is a run with no evidence, not a run
with no findings.

## Pitfalls (learned the hard way)

- **Wrong injection side.** "Local can't read 1.1.8's output" needs a
  *producer* corruption on the release's side (impossible — it's a fixed
  binary) or a *consumer* corruption that simulates it; "the release
  rejects a bad local validator" needs the *local broadcast message*
  corrupted. Decide which direction you're testing before editing (see
  step 2). These are not interchangeable.
- **Immutable reference binaries.** You cannot add a byte to a released
  binary's output. Put producer faults in the build you control and run it
  as a minority among honest reference nodes.
- **cargo ignores edits to git-dependency checkouts.** A `[dependency]` from
  git is fingerprinted by its **rev**, not file contents — editing
  `~/.cargo/git/checkouts/<dep>/…` is silently ignored on rebuild (the build
  is suspiciously fast and `strings <binary> | grep <marker>` is empty). To
  fault a crypto/git dependency, add a `[patch."<git-url>"]` mapping each
  crate to a local **path** checkout (path deps *are* content-fingerprinted).
  ika-side faults rebuild normally.
- **Final output vs round message.** Malicious-party detection fires on the
  per-round broadcast contribution peers verify, not the final stored
  output. Corrupting only the `Finalize` output gives a wrong stored result,
  not a "malicious" flag.

## Notes

- Run the cross-binary / cluster mechanics per
  [`ci-suites.md`](ci-suites.md) and the test docs in
  `crates/ika-upgrade-test/tests/`; this playbook is about *what* to inject,
  *which outcome shape to expect*, and *what log to grep*, not how to launch
  the suite.
- A trailing-byte fault is universal (strict `bcs` rejects it everywhere),
  so it's a good fast hard-fail probe. For a *specific* boundary, choose a
  fault only the intended side rejects.
