#!/usr/bin/env bash
# Epoch-table write-discipline ratchet: every field of
# `AuthorityEpochTables` must declare, in its doc comment, how it is
# written — `commit-batched` (only via
# `ConsensusCommitOutput::write_to_batch`) or `direct` with the argument
# that makes its consumers survive an out-of-band write.
#
# Why a check and not just review: #1917 was a direct write whose safety
# argument lived in a comment a screen away from the reader that
# invalidated it. A missing line is the cheapest possible signal that a
# new table (or a new writer) never had the argument made.
#
# Convention: dev-docs/conventions/epoch-table-write-discipline.md
#
# Usage:
#   check-epoch-table-write-discipline.sh          # validate (CI)
#   check-epoch-table-write-discipline.sh --list   # print each field + its declaration
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "$@" <<'EOF'
import pathlib
import re
import sys

SOURCE = pathlib.Path("crates/ika-core/src/authority/authority_per_epoch_store.rs")
STRUCT = "pub struct AuthorityEpochTables {"
# A field declaration at struct indentation: `[pub(crate) ]name: Type` or a
# `name:` whose type wrapped to the next line.
FIELD = re.compile(r"^    (?:pub(?:\((?:crate|super)\))?\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*:")
DECLARATION = re.compile(r"write-discipline:\s*(?P<value>.+?)\s*$")

lines = SOURCE.read_text().splitlines()
try:
    start = next(i for i, line in enumerate(lines) if line.strip() == STRUCT) + 1
except StopIteration:
    sys.exit(f"ERROR: `{STRUCT}` not found in {SOURCE} — update this script alongside the rename.")
end = next(i for i in range(start, len(lines)) if lines[i] == "}")

fields = []
doc = []
for line in lines[start:end]:
    stripped = line.strip()
    if stripped.startswith("///"):
        doc.append(stripped[3:].strip())
        continue
    if stripped.startswith("#[") or stripped.startswith("//") or not stripped:
        # Attributes and blank lines don't interrupt a doc block; a plain `//`
        # comment isn't a declaration site, so it doesn't either.
        continue
    match = FIELD.match(line)
    if match:
        declaration = next(
            (m.group("value") for m in map(DECLARATION.search, doc) if m), None
        )
        fields.append((match.group("name"), declaration))
    doc = []

if "--list" in sys.argv:
    for name, declaration in fields:
        print(f"{name}: {declaration or '<MISSING>'}")
    print(f"# {len(fields)} fields in AuthorityEpochTables", file=sys.stderr)
    sys.exit(0)

missing = [name for name, declaration in fields if declaration is None]
if missing:
    print(
        "ERROR: every AuthorityEpochTables field must declare its write discipline\n"
        "in its doc comment (one `write-discipline:` line). Missing:",
        file=sys.stderr,
    )
    for name in missing:
        print(f"  {name}", file=sys.stderr)
    print(
        "\nUse one of:\n"
        "  /// write-discipline: commit-batched\n"
        "  /// write-discipline: direct - safe because <reason>: <consumer>\n"
        "  /// write-discipline: direct - UNPROVEN (#issue)\n"
        "See dev-docs/conventions/epoch-table-write-discipline.md",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK: all {len(fields)} AuthorityEpochTables fields declare a write discipline")
EOF
