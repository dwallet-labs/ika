#!/usr/bin/env python3
"""Verify every `path:line` / `path:A-B` citation in markdown files exists.

usage: ROOT=/path/to/checkout check_cites.py <doc.md> [more.md ...]
       CHECK_FLAGS=--print prints the cited lines.
Exit 1 if any citation names a missing file or a line past the file's end.
"""
import os, re, sys
ROOT = os.environ.get("ROOT", os.getcwd())
pat = re.compile(r"`([A-Za-z0-9_./-]+\.(?:rs|move|sol|md|ts|py|go|js|toml|yaml|yml)):(\d+)(?:-(\d+))?`")
bad = total = 0
for part in sys.argv[1:]:
    for m in pat.finditer(open(part).read()):
        total += 1
        path, a, b = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            print(f"MISSING FILE {path}:{a}"); bad += 1; continue
        lines = open(full, errors="replace").read().splitlines()
        if b > len(lines) or a < 1 or b < a:
            print(f"OUT OF RANGE {path}:{a}-{b} (file has {len(lines)} lines)"); bad += 1; continue
        if "--print" in os.environ.get("CHECK_FLAGS", ""):
            print(f"--- {path}:{a}-{b}")
            for i in range(a, min(b, a + 12) + 1):
                print(f"{i}\t{lines[i-1]}")
print(f"{total} citations, {bad} bad")
sys.exit(1 if bad else 0)
