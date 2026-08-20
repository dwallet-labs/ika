# reviews/ — written reviews worth keeping in the repo

For substantial review documents: deep PR reviews, design reviews,
audit reports, post-merge retrospectives. Inline PR comments remain the
default; a file lands here when the review is long-form, spans many
findings, or needs to be referenced later (e.g. as the checklist a
follow-up PR works through).

## Conventions

- Naming: name the file after its SUBJECT, kebab-case — the shape this
  directory actually converged on (`ocs-grpc-migration-review.md`,
  `issue1952-root-mechanism-and-fix.md`). Put the PR number, commit and
  date in the opening block rather than in the filename.
- Open with: what was reviewed (PR/commit range/design doc), at what
  commit, on what date, and the verdict summary. All three, every time —
  a review with no date is one nobody can weigh against the code.
- Findings as a numbered list, each with severity, `file:line` anchors,
  and a RESOLUTION field filled in as findings are addressed (link the
  fixing commit/PR) — a review whose findings' fates are unrecorded
  loses most of its value.
- Unlike `../specs/`, these are point-in-time RECORDS: they are not
  maintained after the review cycle closes, and nothing should treat an
  old review as a source of current truth — that's what specs are for.
- Recurring findings that reflect a general failure class should also
  be distilled into `../learnings/pitfalls.md` (the review records the
  instance; the pitfall records the rule). Do this while the review is
  open — every review in `archive/` that skipped it had to be mined years
  later by someone reconstructing the context from scratch.

## Archiving

A review whose cycle has closed moves to `archive/` with a quoted note
under its title: what it reviewed, at what commit and date, whether the
work landed, where current truth lives now, and anything it says that the
code later settled the OTHER way. That last part matters more than it
sounds — an old review reads as authoritative to anyone who opens it
without checking `git log`, and the header is the only thing standing
between a reader and a confidently-wrong conclusion.

Extract anything still live BEFORE archiving: a general failure class goes
to `../learnings/pitfalls.md`, a durable behavioral claim to `../specs/`,
an operational rule to `../playbooks/`.

Delete rather than archive when a file is an unfinished working document
rather than a review — self-labelled non-verdicts, empty finding stubs, no
date, no PR number, reasoning about a protocol version the code no longer
has. Archiving those preserves length, not knowledge, and the archive
header cannot rescue a document whose findings were never adjudicated at
all.
