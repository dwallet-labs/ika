# reviews/ — written reviews worth keeping in the repo

For substantial review documents: deep PR reviews, design reviews,
audit reports, post-merge retrospectives. Inline PR comments remain the
default; a file lands here when the review is long-form, spans many
findings, or needs to be referenced later (e.g. as the checklist a
follow-up PR works through).

## Conventions

- Naming: `pr-<number>-<slug>.md` for PR reviews (e.g.
  `pr-1721-offchain-metadata.md`); `<topic>-review.md` for design/audit
  reviews.
- Open with: what was reviewed (PR/commit range/design doc), at what
  commit, on what date, and the verdict summary.
- Findings as a numbered list, each with severity, `file:line` anchors,
  and a RESOLUTION field filled in as findings are addressed (link the
  fixing commit/PR) — a review whose findings' fates are unrecorded
  loses most of its value.
- Unlike `../specs/`, these are point-in-time RECORDS: they are not
  maintained after the review cycle closes, and nothing should treat an
  old review as a source of current truth — that's what specs are for.
- Recurring findings that reflect a general failure class should also
  be distilled into `../learnings/pitfalls.md` (the review records the
  instance; the pitfall records the rule).
