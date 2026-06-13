#!/usr/bin/env bash
# PreToolUse[Bash] guard: deterministic enforcement of CLAUDE.md's git
# rules (advisory rules degrade under context pressure; hooks don't).
# Blocks (exit 2; stderr explains to the agent):
#   - any git command carrying --no-verify
#   - git push targeting dev / main / master
#   - git commit while ON dev / main / master
#   - git commit including .rs files while `cargo fmt --all --check` is dirty
set -uo pipefail

input=$(cat)
cmd=$(echo "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -n "$cmd" ] || exit 0

# Flags and push targets live in the command itself — never inside a
# heredoc body or a quoted string (e.g. a commit MESSAGE that mentions
# "--no-verify" must not trip the guard). Scan a reduced view: cut at
# the first heredoc marker, then strip quoted spans per line.
flag_scan=${cmd%%<<*}
flag_scan=$(printf '%s' "$flag_scan" | sed -e "s/'[^']*'//g" -e 's/"[^"]*"//g')

# Only inspect commands that invoke git.
echo "$flag_scan" | grep -qE '(^|[;&|[:space:]])git([[:space:]]|$)' || exit 0

if echo "$flag_scan" | grep -qE -- '--no-verify'; then
    echo "BLOCKED (git-guard): --no-verify skips git hooks — fix the hook failure instead (CLAUDE.md: Git Workflow)." >&2
    exit 2
fi

if echo "$flag_scan" | grep -qE 'git([[:space:]]+-[^[:space:]]+)*[[:space:]]+push'; then
    # Match dev/main/master as a push target: bare word, refspec dst
    # (after a colon), or at the end of refs/heads/. Branch names that
    # merely CONTAIN these words (e.g. chore/dev-docs) don't match.
    if echo "$flag_scan" | grep -qE '([[:space:]:]|refs/heads/)(dev|main|master)([[:space:]]*$|[[:space:]])'; then
        echo "BLOCKED (git-guard): pushing to a protected branch (dev/main/master). Push a feature branch and open a PR (CLAUDE.md: Git Workflow)." >&2
        exit 2
    fi
fi

if echo "$flag_scan" | grep -qE 'git([[:space:]]+-[^[:space:]]+)*[[:space:]]+commit'; then
    branch=$(git symbolic-ref --short -q HEAD || true)
    case "$branch" in
        dev|main|master)
            echo "BLOCKED (git-guard): committing directly on '$branch'. Create a feature branch first (CLAUDE.md: Git Workflow)." >&2
            exit 2
            ;;
    esac
    # fmt gate: only when Rust files are part of what's being committed.
    if git diff --cached --name-only 2>/dev/null | grep -q '\.rs$'; then
        if ! cargo fmt --all --check >/dev/null 2>&1; then
            echo "BLOCKED (git-guard): rustfmt is dirty. Run 'cargo fmt --all' and include the formatted files in the commit (CLAUDE.md: Git Workflow)." >&2
            exit 2
        fi
    fi
fi

exit 0
