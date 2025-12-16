#!/bin/bash

# Path to Move.toml
MOVE_TOML="../contract/Move.toml"

# Check if Move.toml exists
if [ ! -f "$MOVE_TOML" ]; then
    echo "Error: Move.toml not found at $MOVE_TOML"
    exit 1
fi

# Check if package address is provided as argument
if [ -z "$1" ]; then
    echo "Error: No package address provided"
    echo "Usage: $0 <package-address>"
    exit 1
fi

PACKAGE_ADDRESS="$1"

echo "Updating Move.toml with published package address..."
echo "  Package address: $PACKAGE_ADDRESS"

# Update published-at field (replace any existing address)
sed -i.bak "s|^published-at = \"0x[a-f0-9]*\"|published-at = \"$PACKAGE_ADDRESS\"|" "$MOVE_TOML"

# Update ika_btc_multisig address (replace any existing address)
sed -i.bak "s|^ika_btc_multisig = \"0x[a-f0-9]*\"|ika_btc_multisig = \"$PACKAGE_ADDRESS\"|" "$MOVE_TOML"

# Remove backup file
rm -f "$MOVE_TOML.bak"

echo "✓ Move.toml updated successfully!"
echo ""
echo "Updated fields:"
grep "published-at" "$MOVE_TOML"
grep "ika_btc_multisig" "$MOVE_TOML"

