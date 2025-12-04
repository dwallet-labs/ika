#!/bin/bash

# First, reset addresses to 0x0 for publishing
MOVE_TOML="../contract/Move.toml"

echo "Resetting addresses to 0x0 for publishing..."
sed -i.bak "s|^published-at = \"0x[a-f0-9]*\"|published-at = \"0x0\"|" "$MOVE_TOML"
sed -i.bak "s|^ika_btc_multisig = \"0x[a-f0-9]*\"|ika_btc_multisig = \"0x0\"|" "$MOVE_TOML"
rm -f "$MOVE_TOML.bak"

echo "Publishing contract..."
cd ../contract

# Run sui client publish and capture JSON output
PUBLISH_OUTPUT=$(sui client publish --json 2>&1)

# Check if publish was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to publish contract"
    echo "$PUBLISH_OUTPUT"
    exit 1
fi

# Extract the packageId from the JSON output
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | grep -o '"packageId": "0x[a-f0-9]*"' | head -1 | cut -d'"' -f4)

if [ -z "$PACKAGE_ID" ]; then
    echo "Error: Could not extract package ID from publish output"
    echo "$PUBLISH_OUTPUT"
    exit 1
fi

echo ""
echo "✓ Contract published successfully!"
echo "  Package ID: $PACKAGE_ID"
echo ""

# Return to frontend directory and run update script
cd ../frontend
bash scripts/update_published_address.bash "$PACKAGE_ID"

echo ""
echo "✓ All done! Contract published and Move.toml updated."

