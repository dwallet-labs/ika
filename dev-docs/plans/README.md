# plans/ — implementation plans worth keeping in the repo

For plans that outlive a single session or span multiple PRs: migration
strategies, multi-phase refactors, protocol-change rollouts. A plan
that fits in one PR description belongs there instead.

## Conventions

- One file per effort, kebab-case topic name (e.g.
  `reconfiguration-unification.md`).
- Start with a STATUS line: `Status: active | deferred | landed | superseded |
  abandoned` (+ date and the PRs that executed it). Update it when the
  state changes — a stale "active" plan misleads both humans and agents.
- A plan records INTENT and sequencing; durable behavior belongs in
  `../specs/` once it lands. When a plan lands, move the behavioral
  contract to a spec and mark the plan `landed` — don't let the plan
  become the de-facto spec.
- Code comments must NEVER reference plan/phase names ("Phase 4f") —
  plan nomenclature rots once the plan is archived (CLAUDE.md rule);
  comments carry the technical content only.
- Agents: when asked to execute part of a plan kept here, read the
  whole plan first, and update its status/progress markers in the same
  PR as the work.

## Archiving a landed plan

Once a plan has shipped AND its durable behavior lives in a spec, `git mv`
it into `archive/` and add a quoted note directly under its title saying
what shipped, where current truth now lives, and — this is the part that
earns the file its keep — what it still carries that no spec does. Leave
the body untouched: an archived plan is a dated record of intent, not a
document to bring up to date.

Delete instead of archiving when the plan carries nothing a spec does not
already say. A plan kept only because it was once written is a file that
will be mistaken for current truth by whoever finds it next.

**A landed plan whose central design was never actually built does not get
archived — it gets deleted.** Its status line is a claim like any other
(see the "verifying other people's claims" entries in
[`../learnings/pitfalls.md`](../learnings/pitfalls.md)), and a plan
asserting it executed a design that exists nowhere manufactures a
precedent someone will later cite.

## Current plans

Only two are live; everything else is under `archive/`.

- [`handoff-barrier-escape-and-pure-close-gate.md`](handoff-barrier-escape-and-pure-close-gate.md)
  — deferred. Three unbuilt items around relaxing the prepare-then-start
  barrier and making the epoch-close gate a pure function of the consensus
  sequence. Carries a dated note that its central safety premise no longer
  holds at HEAD and must be re-derived first. Three specs and several code
  comments point at it.
- [`ocs-subscription-changeset-stream.md`](ocs-subscription-changeset-stream.md)
  — deferred, zero implementation. Its open soundness question about
  `OBJECT_DIGEST_CANCELLED` bucketing has been lifted into the residuals of
  [`../specs/ocs-verified-sui-reads.md`](../specs/ocs-verified-sui-reads.md)
  so it survives whatever happens to this file.
