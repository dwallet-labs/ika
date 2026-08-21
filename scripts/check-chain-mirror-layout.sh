#!/usr/bin/env bash
# Chain-mirror layout ratchet: the Move structs that Rust mirrors with untagged
# `#[derive(Deserialize)]` types may not change shape without the Rust mirror,
# the version dispatch, and the docs changing in the same PR.
#
# Why a check and not just review: `DWalletCoordinatorInner`, `SystemInner`, and
# `DWalletNetworkEncryptionKey` are read from chain into Rust structs that carry
# NO version tag. BCS is positional, so their field order is the wire format of
# bytes deployed packages have already written, and nothing in those bytes
# identifies which layout produced them. Every OCS proof gate — committee BLS,
# artifacts digest, Merkle inclusion, id binding, currency — verifies the bytes'
# PROVENANCE and none verifies their SHAPE, so a drifted layout passes all of
# them and surfaces, at best, as a bare bcs error pointing at the wrong field.
#
# The check is build-time on purpose. An in-place field-add cannot reach
# mainnet/testnet anyway (Sui's compatible-policy upgrade checker rejects
# datatype layout changes); drift arrives through a `VERSION` bump plus
# `migrate()`, or a fresh package publish — both of which pass through this repo,
# where a red build is the cheapest possible signal.
#
# The Rust half of the guard is the golden layout tests beside each mirror
# (`cargo test --release -p ika-types layout_is_pinned`); this script is the
# Move half plus the mapping between them.
#
# Convention: dev-docs/conventions/chain-mirror-layout.md
#
# Usage:
#   check-chain-mirror-layout.sh           # validate (CI)
#   check-chain-mirror-layout.sh --list    # print each mirror's extracted layout
#   check-chain-mirror-layout.sh --write   # regenerate the manifest after a
#                                          # DELIBERATE change
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "$@" <<'EOF'
import pathlib
import re
import sys

MANIFEST = pathlib.Path("scripts/chain-mirror-layout.txt")
SPEC = "dev-docs/specs/ocs-verified-sui-reads.md"
CONVENTION = "dev-docs/conventions/chain-mirror-layout.md"

# A Move field line inside a struct body: `name: Type,`. Types can carry nested
# generics and commas, so take everything up to the LAST comma.
MOVE_FIELD = re.compile(r"^\s{4}(?P<name>[a-z_][A-Za-z0-9_]*)\s*:\s*(?P<type>.+?),?\s*$")
# A Rust field line at struct indentation: `pub name: Type,`.
RUST_FIELD = re.compile(r"^    pub\s+(?P<name>[a-z_][A-Za-z0-9_]*)\s*:")
MOVE_VERSION = re.compile(r"^const VERSION:\s*u64\s*=\s*(?P<value>\d+)\s*;")


def fail(message):
    sys.exit(f"ERROR: {message}")


def read_lines(path):
    source = pathlib.Path(path)
    if not source.is_file():
        fail(f"{path} not found — update this script alongside the move/rename.")
    return source.read_text().splitlines()


def strip_comment(line):
    """Drop a trailing `//` comment, which Move field lines carry freely."""
    return line.split("//", 1)[0].rstrip()


def struct_body(lines, header, path):
    """The lines between a `... struct NAME ... {` header and its closing `}`."""
    starts = [i for i, line in enumerate(lines) if line.rstrip().endswith("{") and header in line]
    if not starts:
        fail(f"`{header}` not found in {path} — update this script alongside the rename.")
    if len(starts) > 1:
        fail(f"`{header}` is declared {len(starts)} times in {path}; the extractor needs one.")
    start = starts[0] + 1
    ends = [i for i in range(start, len(lines)) if lines[i].rstrip() == "}"]
    if not ends:
        fail(f"`{header}` in {path} has no closing brace at column 0.")
    return lines[start:ends[0]]


def move_fields(path, struct):
    """Ordered `(name, type)` of a Move struct, comments and blank lines dropped."""
    lines = read_lines(path)
    fields = []
    for raw in struct_body(lines, f"struct {struct} ", path):
        line = strip_comment(raw)
        if not line.strip():
            continue
        match = MOVE_FIELD.match(line)
        if match:
            fields.append((match.group("name"), match.group("type").strip()))
    if not fields:
        fail(f"extracted no fields from Move `{struct}` in {path}.")
    return fields


def rust_fields(path, struct):
    """Ordered field names of an all-`pub` Rust struct."""
    lines = read_lines(path)
    names = []
    for raw in struct_body(lines, f"pub struct {struct} ", path):
        line = strip_comment(raw)
        if not line.strip() or line.strip().startswith("#["):
            continue
        match = RUST_FIELD.match(line)
        if match:
            names.append(match.group("name"))
    if not names:
        fail(f"extracted no fields from Rust `{struct}` in {path}.")
    return names


def move_version(path):
    for line in read_lines(path):
        match = MOVE_VERSION.match(line.strip())
        if match:
            return match.group("value")
    fail(f"`const VERSION: u64` not found in {path}.")


def parse_manifest():
    """Blocks of `key = value`, with `fields` taking indented continuation lines."""
    blocks = []
    block = None
    key = None
    for raw in MANIFEST.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.strip() == "[mirror]":
            block = {"fields": []}
            blocks.append(block)
            key = None
            continue
        if block is None:
            fail(f"{MANIFEST}: content before the first [mirror] block.")
        if raw.startswith((" ", "\t")):
            if key != "fields":
                fail(f"{MANIFEST}: indented line outside `fields =`: {raw!r}")
            move_side, _, rust_name = raw.strip().partition("->")
            move_name, _, move_type = move_side.partition(":")
            block["fields"].append(
                (move_name.strip(), move_type.strip(), rust_name.strip())
            )
            continue
        key, _, value = raw.partition("=")
        key, value = key.strip(), value.strip()
        # `fields =` opens the indented list parsed above; it has no value of
        # its own and must not overwrite the list already sitting there.
        if key != "fields":
            block[key] = value
    return blocks


def render(block, fields):
    lines = ["[mirror]"]
    for key in ("move-source", "move-struct", "rust-source", "rust-struct"):
        lines.append(f"{key} = {block[key]}")
    if "version-source" in block:
        lines.append(f"version-source = {block['version-source']}")
        lines.append(f"version-value = {block['version-value']}")
    lines.append("fields =")
    for move_name, move_type, rust_name in fields:
        lines.append(f"  {move_name}: {move_type} -> {rust_name}")
    return "\n".join(lines)


def extract(block):
    """The live layout, as manifest-shaped `(move_name, move_type, rust_name)`."""
    move = move_fields(block["move-source"], block["move-struct"])
    rust = rust_fields(block["rust-source"], block["rust-struct"])
    if len(move) != len(rust):
        fail(
            f"Move `{block['move-struct']}` has {len(move)} fields but Rust "
            f"`{block['rust-struct']}` has {len(rust)}.\n\n"
            f"  Move: {block['move-source']}\n"
            f"  Rust: {block['rust-source']}\n\n"
            "These must agree field for field: the Rust struct is an UNTAGGED mirror, so its\n"
            "field order is the wire format of bytes already on chain. Fix the mismatch, then\n"
            f"regenerate with `./scripts/check-chain-mirror-layout.sh --write`.\n\n"
            f"See {CONVENTION}."
        )
    return [(name, type_, rust_name) for (name, type_), rust_name in zip(move, rust)]


blocks = parse_manifest()

if "--list" in sys.argv:
    for block in blocks:
        print(render(block, extract(block)))
        print()
    sys.exit(0)

if "--write" in sys.argv:
    header = []
    for line in MANIFEST.read_text().splitlines():
        if line.strip() == "[mirror]":
            break
        header.append(line)
    body = "\n\n".join(render(block, extract(block)) for block in blocks)
    MANIFEST.write_text("\n".join(header) + body + "\n")
    print(f"wrote {MANIFEST}")
    sys.exit(0)

problems = []
for block in blocks:
    live = extract(block)
    pinned = block["fields"]
    if live != pinned:
        detail = [f"Move `{block['move-struct']}` <-> Rust `{block['rust-struct']}`:"]
        for index in range(max(len(live), len(pinned))):
            got = live[index] if index < len(live) else None
            want = pinned[index] if index < len(pinned) else None
            if got != want:
                detail.append(f"    field {index}: pinned {want} but source has {got}")
        problems.append("\n".join(detail))
    if "version-source" in block:
        version = move_version(block["version-source"])
        if version != block["version-value"]:
            problems.append(
                f"Move `{block['move-struct']}`: {block['version-source']} declares "
                f"VERSION = {version}, manifest pins {block['version-value']}."
            )

if problems:
    sys.exit(
        "ERROR: a chain-mirror layout drifted from its pin.\n\n"
        + "\n\n".join(problems)
        + "\n\n"
        "These Rust structs are UNTAGGED mirrors of deployed Move structs. BCS is\n"
        "positional, so their field order is the wire format of bytes already written on\n"
        "chain, and nothing in those bytes says which layout produced them: every OCS proof\n"
        "gate verifies the bytes' provenance, none verifies their shape. A drift here does\n"
        "not fail closed at runtime — it re-interprets live chain state.\n\n"
        "If this change is deliberate, ALL of the following move together:\n"
        "  1. the Move struct and the Rust mirror,\n"
        "  2. the version dispatch — `match wrapper.version { 1 | 2 => .. }` in\n"
        "     crates/ika-sui-client/src/lib.rs and\n"
        "     crates/ika-core/src/sui_connector/verified_reader.rs — which today asserts,\n"
        "     untested, that versions 1 and 2 share one layout. A layout change means they\n"
        "     no longer do, and the arm must stop claiming it,\n"
        "  3. the `const VERSION` bump plus `migrate()` that carries old state across (an\n"
        "     in-place field-add is rejected by Sui's compatible-policy upgrade checker, so\n"
        "     there is no same-version path to chain),\n"
        "  4. the golden layout tests: cargo test --release -p ika-types layout_is_pinned,\n"
        f"  5. the Residuals section of {SPEC},\n"
        "  6. this manifest: ./scripts/check-chain-mirror-layout.sh --write\n\n"
        f"See {CONVENTION}."
    )
EOF
