#!/bin/bash

# Run all integration tests sequentially, one at a time, with per-test reports and configurable timeout.
#
# Usage:
#   ./scripts/run-integration-tests-sequential.sh [--timeout <seconds>] [--filter <pattern>]
#
# Options:
#   --timeout <seconds>   Per individual test case timeout in seconds (default: 120 = 2 minutes)
#   --filter <pattern>    Only run test files matching this glob pattern (e.g. "dwallet*")
#
# Examples:
#   ./scripts/run-integration-tests-sequential.sh
#   ./scripts/run-integration-tests-sequential.sh --timeout 300
#   ./scripts/run-integration-tests-sequential.sh --timeout 900 --filter "imported*"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
TEST_DIR="$PROJECT_DIR/test/integration"

# Defaults
TIMEOUT_SECONDS=120
FILTER=""

# Tests ordered by feature dependency: foundational tests first, comprehensive combos last.
# If a basic feature breaks, you see it early without waiting for complex combo tests.
ORDERED_TESTS=(
    "dwallet-creation"
    "global-presign"
    "transfer-dwallet"
    "imported-key"
    "make-public-share-and-sign"
    "imported-key-make-public-share-and-sign"
    "dwallet-sign-during-dkg"
    "all-combinations"
    "all-combinations-future-sign"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --filter)
            FILTER="$2"
            shift 2
            ;;
        --help|-h)
            head -16 "$0" | tail -14
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# Build ordered test file list
TEST_FILES=()
if [[ -n "$FILTER" ]]; then
    # With filter: discover matching files (sorted alphabetically)
    while IFS= read -r f; do
        TEST_FILES+=("$f")
    done < <(find "$TEST_DIR" -name "${FILTER}.test.ts" -type f | sort)
else
    # Without filter: use the dependency-ordered list
    for name in "${ORDERED_TESTS[@]}"; do
        FILE="$TEST_DIR/${name}.test.ts"
        if [[ -f "$FILE" ]]; then
            TEST_FILES+=("$FILE")
        else
            echo "Warning: expected test file not found: ${name}.test.ts"
        fi
    done
    # Also pick up any new test files not yet in the ordered list
    while IFS= read -r f; do
        BASENAME=$(basename "$f" .test.ts)
        ALREADY_LISTED=false
        for name in "${ORDERED_TESTS[@]}"; do
            if [[ "$name" == "$BASENAME" ]]; then
                ALREADY_LISTED=true
                break
            fi
        done
        if [[ "$ALREADY_LISTED" == "false" ]]; then
            TEST_FILES+=("$f")
        fi
    done < <(find "$TEST_DIR" -name "*.test.ts" -type f | sort)
fi

if [[ ${#TEST_FILES[@]} -eq 0 ]]; then
    echo "No test files found."
    exit 1
fi

TOTAL=${#TEST_FILES[@]}
PASSED=0
FAILED=0

# Collect results for final summary
declare -a RESULT_NAMES=()
declare -a RESULT_STATUSES=()
declare -a RESULT_DURATIONS=()

# Colors (only when stdout is a terminal)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    CYAN=''
    BOLD=''
    RESET=''
fi

echo ""
echo -e "${BOLD}Integration Test Runner${RESET}"
echo "========================================"
echo -e "  Tests found:   ${CYAN}${TOTAL}${RESET}"
echo -e "  Timeout:       ${CYAN}${TIMEOUT_SECONDS}s${RESET} per test"
if [[ -n "$FILTER" ]]; then
    echo -e "  Filter:        ${CYAN}${FILTER}${RESET}"
fi
echo "========================================"
echo ""

INDEX=0

for TEST_FILE in "${TEST_FILES[@]}"; do
    INDEX=$((INDEX + 1))
    TEST_NAME=$(basename "$TEST_FILE" .test.ts)

    TIMEOUT_MS=$((TIMEOUT_SECONDS * 1000))

    echo -e "${BOLD}[${INDEX}/${TOTAL}] Running: ${CYAN}${TEST_NAME}${RESET}"
    echo -e "  File: ${TEST_FILE#"$PROJECT_DIR"/}"
    echo -e "  Timeout: ${TIMEOUT_SECONDS}s per test case"
    echo ""

    START_TIME=$(date +%s)

    # Run vitest with per-test-case timeout.
    # --testTimeout: vitest kills individual test cases that exceed this (in ms).
    # --reporter=verbose: prints each test case result as it completes/fails/times out.
    # --sequence.concurrent=false: run test cases sequentially within each file.
    # --pool=forks --poolOptions.forks.singleFork: single process, no parallelism.
    set +e
    (
        cd "$PROJECT_DIR" && \
        NODE_OPTIONS="--max-old-space-size=8192" \
        npx vitest run "$TEST_FILE" \
            --reporter=verbose \
            --testTimeout="$TIMEOUT_MS" \
            --hookTimeout="$TIMEOUT_MS" \
            --sequence.concurrent=false \
            --pool=forks \
            --poolOptions.forks.singleFork \
            2>&1
    )
    EXIT_CODE=$?
    set -e

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    # Format duration as mm:ss
    DURATION_MIN=$((DURATION / 60))
    DURATION_SEC=$((DURATION % 60))
    DURATION_FMT=$(printf "%dm %02ds" "$DURATION_MIN" "$DURATION_SEC")

    RESULT_NAMES+=("$TEST_NAME")
    RESULT_DURATIONS+=("$DURATION_FMT")

    echo ""
    echo "  ----------------------------------------"

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo -e "  Result:   ${GREEN}PASSED${RESET}"
        PASSED=$((PASSED + 1))
        RESULT_STATUSES+=("PASSED")
    else
        echo -e "  Result:   ${RED}FAILED${RESET} (exit code ${EXIT_CODE})"
        FAILED=$((FAILED + 1))
        RESULT_STATUSES+=("FAILED")
    fi

    echo -e "  Duration: ${DURATION_FMT}"
    echo "  ----------------------------------------"
    echo ""
done

# Final summary
echo ""
echo "========================================"
echo -e "${BOLD}Final Summary${RESET}"
echo "========================================"
echo ""

for i in "${!RESULT_NAMES[@]}"; do
    STATUS="${RESULT_STATUSES[$i]}"
    case "$STATUS" in
        PASSED)   STATUS_FMT="${GREEN}PASSED${RESET}"  ;;
        FAILED)   STATUS_FMT="${RED}FAILED${RESET}"    ;;
        *)        STATUS_FMT="$STATUS"                  ;;
    esac
    printf "  %-50s %b  %s\n" "${RESULT_NAMES[$i]}" "$STATUS_FMT" "${RESULT_DURATIONS[$i]}"
done

echo ""
echo "========================================"
echo -e "  Total:      ${BOLD}${TOTAL}${RESET}"
echo -e "  Passed:     ${GREEN}${PASSED}${RESET}"
echo -e "  Failed:     ${RED}${FAILED}${RESET}"
echo "========================================"
echo ""

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi

exit 0
