# Naming things that outlive their context

Two rules, one reason: a name is read by people who were not there when it
was chosen. Both are review-enforced — no lint checks either.

## Full words, never abbreviations that fork

**Always `reconfiguration`. Never `reconfig`.** In identifiers, file names,
branch names, comments, commit messages, and documentation.

The codebase already uses the full word throughout —
`reconfiguration_public_outputs`, `reconfiguration_message_version`,
`all_network_encryption_keys_reconfiguration_completed` — and that
consistency is the point. An abbreviation used by half the codebase is
worse than either convention applied uniformly, because it forks every
search: `grep reconfig` catches both spellings, `grep reconfiguration`
silently misses the abbreviated half, and the person who greps the long
form is the one who most needs the complete answer.

The rule generalizes. Before shortening a domain word in a name, ask
whether someone searching for the full form must find this symbol. If
yes, spell it out.

## No internal labels in anything durable

Never put a label that only resolves inside its originating context into
code, comments, specs, playbooks, PR descriptions, or commit messages:

- plan and phase names (`Phase 4f`, `step 2 of the crypto bump`);
- ticket shorthands and internal work-item IDs;
- test or property IDs invented for one document (`F4-1`, `ocs-binding-1`).

These rot the moment the document that defined them is archived, and they
rot silently — the text still reads as though it means something. Spell out
the mechanism in plain terms instead. "Closed by the shared
`dynamic_field_child_owned_by` check" survives; "closed by `ocs-binding-1`"
does not.

An issue or PR NUMBER is different and is fine: it is a permanent, publicly
resolvable reference. `ika #2057` still retrieves its own context years
later; `Phase 4f` does not. The test is whether a reader outside the moment
can look the label up.

Where a historical document deliberately preserves a record of how work was
organized — an archived plan, an archived review — its internal labels stay
as written. Archives are dated records, not maintained truth. The rule binds
what a reader is expected to act on today.
