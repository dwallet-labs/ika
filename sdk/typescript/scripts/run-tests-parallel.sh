#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/../test/dkg-v2"

# Find all test files recursively
TEST_FILES=$(find "$TEST_DIR" -name "*.test.ts" -type f)

# Array to store background process PIDs
PIDS=()

echo "Running tests in parallel..."
echo "======================================"

# Run each test file in parallel
for test_file in $TEST_FILES; do
    echo "Starting: $test_file"
    bun test "$test_file" --timeout 10000000 &
    PIDS+=($!)
done

# Wait for all background processes to complete
echo "======================================"
echo "Waiting for all tests to complete..."
echo "======================================"

FAILED=0
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        FAILED=1
    fi
done

# Exit with error if any test failed
if [ $FAILED -eq 1 ]; then
    echo "======================================"
    echo "Some tests failed!"
    exit 1
else
    echo "======================================"
    echo "All tests passed!"
    exit 0
fi