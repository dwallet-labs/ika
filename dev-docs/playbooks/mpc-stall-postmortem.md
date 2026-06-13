# MPC stall post-mortem

Use this when the network stops making MPC progress: epochs stop
advancing, user sessions time out ("Object ... does not exist" from the
SDK), or quorum events go silent. The checks are ORDERED — each one
either identifies the stall class or eliminates it; the order reflects
how often each class was the answer in real investigations and how cheap
the check is. Run them against the localnet/validator log (debug-level
`ika_core::dwallet_mpc=debug` gives the full picture; info-level still
answers most of them).

## 0. Get the timeline anchors first

```bash
L=<log file>
grep -o "run_epoch epoch=[0-9]*" $L | sort -u | tail -3          # highest epoch entered
grep -E "Successfully locked last session|EndOfPublishV2 active" $L | awk '{print $1, $NF}' | tail -6
grep "MPC output reached quorum" $L | tail -1 | awk '{print $1}' # last quorum = stall onset
```

The minute quorums stopped is the anchor for every later check.

## 1. Malicious conviction (check FIRST — it masquerades as everything else)

```bash
grep -c "recognized itself as malicious" $L
grep "malicious actors identified" $L | head -3
```

A convicted validator's messages are silently ignored from conviction
onward — the committee runs at reduced redundancy and the EVENTUAL stall
(often much later) looks like an unrelated message-flow bug. If this
fires: the divergence source is almost always a network-key parameter
mismatch on the convicted validator (see the adoption guards in
`../specs/handoff.md`), not actual byzantine behavior.

## 2. Started-vs-completed computation balance (orchestrator health)

```bash
grep -c "Starting cryptographic computation" $L
grep -c "Cryptographic computation completed successfully" $L
```

A persistent delta = computations stranded (leaked orchestrator slots /
results sent into a dead handle). Per-validator attribution: re-run with
`| grep "name=k#<id>"`. Zero CPU (cgroup sampler ~idle) while sessions
sit Active means computations are not SPAWNING — different class than
hanging.

## 3. Epoch-entry key gap (the stale-mpc_data race, issue #1736)

```bash
grep "Adopted network key epoch does not match" $L | sed -E 's/^([^ ]+).*name=(k#[a-f0-9]{8}).*/\1 \2/'
grep "Updating network key" $L | sed -E 's/^([^ ]+).*name=(k#[a-f0-9]{8}).*/\1 \2/' | tail -8
```

Historically: exactly ONE rejection warn per epoch boundary is routine —
that validator's presign sessions may be silently dead all epoch
(invisible at 3-of-4 quorum). TWO at one boundary = quorum death for
internal presigns = pool starvation = the wedge. Check whether sessions
created during a validator's key gap ever compute afterwards.

## 4. Chain counters — the over/undershoot discriminator

Read the coordinator inner object (dynamic field of the coordinator id;
get the REAL id from the run's own publish logs, never from a possibly
stale `~/.ika/ika_config/network.yaml`):

- `locked_...` + `last_user_initiated_session_to_complete_in_current_epoch`
  (the frozen target) vs `user_sessions_keeper.completed_sessions_count`.
- `completed > target` → **overshoot**: permanently unhealable (the close
  predicate is a strict equality); a completion path bypassed the lock
  gate — see `../specs/epoch-close-session-lock.md`.
- `completed < target` → **undershoot**: a locked-set session can't
  complete; find WHY it can't (pool starvation? messages missing? — back
  to checks 1-3).
- System keeper: `started == completed` required for close as well.

## 5. What still flows vs what doesn't

Narrow the dead layer by checking each pipeline stage independently:

```bash
grep -c "Presign request reached majority vote" $L   # consensus + votes alive?
grep -c "Adding a new MPC session" $L                # admission alive?
grep -c "popped presign from internal pool" $L       # serving alive?
grep "retrieved missed events" $L | tail -2          # event sync alive? (count growing = backlog)
```

The combination "votes flow + sessions added + zero quorums + zero
serving" pinpoints computation/messaging; "nothing flows" pinpoints
consensus or the service loop.

## 6. Trace ONE session end-to-end

Pick a stuck session id and pull every line mentioning it, per
validator: who added it, who computed each round ("Advancing session" /
"Starting cryptographic computation"), how many round messages each
validator received, who submitted outputs. The validator whose round-N
message never appears IS the lead. Verify session ids are byte-identical
across validators (internal-presign ids are deterministic by
construction; divergence = determinism bug).

## Hard-won interpretation rules

- **Silence is a finding.** "No errors" + dead pipeline usually means a
  silent skip (`.ok()?`-style swallows) or a result delivered into a
  dropped channel — not the absence of a problem.
- **Distinguish slow from never.** Budgets/timeouts that were calibrated
  standalone WILL fire under 4-way CI contention; the failure mode worth
  hunting is "never", not "slow". Before tightening, check whether the
  thing eventually happened after the budget expired.
- **The log's absence of a line is only meaningful at the right
  RUST_LOG.** Several load-bearing lines are debug-level; at info, do
  not conclude "X never happened" for a debug-level X.
- **Multi-line struct dumps break line-based grep.** Anchor greps on the
  timestamp prefix (`^2026-`) or use single-line fields
  (`session_sequence_number=`), and prefer python for multiset diffs.
- **Verify the chain you query is the chain the network used.** Stale
  config files (object ids from a previous run) and multiple listeners
  on one port have both produced hours of false "the object doesn't
  exist" leads. Get ids from the run's own publish output.
