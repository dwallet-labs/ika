# plans/ — implementation plans worth keeping in the repo

For plans that outlive a single session or span multiple PRs: migration
strategies, multi-phase refactors, protocol-change rollouts. A plan
that fits in one PR description belongs there instead.

## Conventions

- One file per effort, kebab-case topic name (e.g.
  `reconfiguration-unification.md`).
- Start with a STATUS line: `Status: active | landed | superseded |
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
