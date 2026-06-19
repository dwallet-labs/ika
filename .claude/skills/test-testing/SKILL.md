---
name: test-testing
description: Validate that an expensive integration/upgrade test actually catches the failure it claims to — by injecting a minimal, targeted fault and confirming the EXPECTED evidence appears in the logs, then reverting. Guards against tests that pass vacuously. Key idea most people miss: the injected failure is often RECOVERABLE (the system detects and excludes it and the test still PASSES), so the log evidence — not the exit code — is the real assertion. Use before trusting a green cross_binary / v118 / cluster run as proof of wire/state compatibility or malicious-party detection.
user-invocable: true
---

A passing test only means something if it would behave differently when the
property under test is broken. "Test testing" (fault injection / mutation
testing) proves that: inject a deliberate, minimal fault that *should*
trip the property, confirm the system reacts the way you predicted **in the
logs**, then revert. Most valuable for the slow, opaque integration tests
where a green run is otherwise an act of faith — `cross_binary`,
`v118_upgrade`, cluster/simtest suites asserting things like
serialized-MPC-data continuity, cross-binary wire compat, or
malicious-party detection.

Target: $ARGUMENTS (the property/test to validate, e.g. "cross_binary state
continuity" or "honest validators reject a faulty one"). If empty, ask
which test and which property.

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
   reference binary you can't edit (a fixed release like literal
   `mainnet-v1.1.8`) cannot carry a producer fault — put the fault in the
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
   land. The test harness/skill *may* stay (they reference an
   externally-built faulted binary), but the source mutation does not.

## Worked example — hard-fail: cross_binary state continuity (ika)

Property: the NEW (v4) binary must decode the network-key DKG output bytes
the OLD (v3) binary produced. Fault (producer side): append one trailing
`0u8` to the backward-compat (V2) network DKG output in `network_dkg.rs`
where `VersionedNetworkDkgOutput::V2(public_output_value)` is built.

```rust
let mut public_output_value = public_output_value;
public_output_value.push(0u8); // TEST-TESTING FAULT (temporary — DO NOT MERGE)
let public_output_value = bcs::to_bytes(&VersionedNetworkDkgOutput::V2(public_output_value))?;
```

Build the OLD binary only (`MAX_PROTOCOL_VERSION=3` patch + this fault) to
`ika-validator-max3-FAULTED`. Outcome shape: **hard-fail** — strict
`bcs::from_bytes` rejects the trailing byte; the key can't be instantiated;
the epoch wedges. Confirm in logs within minutes, then kill:

```bash
grep -rh "RemainingInput\|could not instantiate network key" \
  $UPGRADE_TEST_DIR/validator-*/node.log
# observed: mpc_manager: could not instantiate network key ... error=BcsError(RemainingInput)
```

A *green* cross_binary here would mean the harness doesn't actually exercise
state continuity — investigate before trusting it.

## Worked example — recoverable: cross-binary malicious-party detection (ika)

Property: in a mixed-binary committee, honest validators identify and
exclude a validator that broadcasts a malformed contribution. Fault (one
party's outgoing message): corrupt the `Advance { message }` arm (NOT the
`Finalize` output) of the backward-compat reconfiguration in
`reconfiguration.rs`:

```rust
GuaranteedOutputDeliveryRoundResult::Advance { message } => {
    let mut message = message;
    message.push(0u8); // TEST-TESTING FAULT (temporary — DO NOT MERGE)
    Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
}
```

Harness: `crates/ika-upgrade-test/tests/malicious_cross_binary.rs` — boot a
4-validator committee on the HONEST binary (literal `mainnet-v1.1.8`), let
genesis DKG finish, then `stop_and_swap(&[3], faulty_local)` ONE validator
to the fault-built local binary (a mixed committee, staying at v3). Outcome
shape: **recoverable** — the honest validators reject validator 3, reshare
without it, and the network reaches epoch 3, so **the test PASSES**. The
proof is the log:

```bash
grep -rh "malicious actors identified & recorded\|malicious parties detected" \
  $UPGRADE_TEST_DIR/validator-*/node.log
# observed: dwallet_mpc_service: malicious parties detected ... malicious_parties=[1]
#           mpc_manager: malicious actors identified & recorded ... {k#…}
```

Specificity check (step 6): only `malicious_parties=[1]` (the one faulty
validator) is flagged while the committee still reaches quorum. That
*specificity* is the control — it proves the fault was caught, not that the
binaries are blanket-incompatible (a wire-incompat would have failed every
cross-binary message and never reached quorum). Had a *clean* swapped
validator also been flagged, you'd be measuring incompat, not detection.

## Pitfalls (learned the hard way)

- **Wrong injection side.** "Local can't read 1.1.8's output" needs a
  *producer* corruption on 1.1.8's side (impossible — it's a fixed binary)
  or a *consumer* corruption that simulates it; "1.1.8 rejects a bad local
  validator" needs the *local broadcast message* corrupted. Decide which
  direction you're testing before editing (see step 2). These are not
  interchangeable.
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
  `dev-docs/playbooks/ci-suites.md` and the test docs in
  `crates/ika-upgrade-test/tests/`; this skill is about *what* to inject,
  *which outcome shape to expect*, and *what log to grep*, not how to launch
  the suite.
- A trailing-byte fault is universal (strict `bcs` rejects it everywhere),
  so it's a good fast hard-fail probe. For a *specific* boundary, choose a
  fault only the intended side rejects.
