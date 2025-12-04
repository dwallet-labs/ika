#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script directory to ensure relative paths work
cd "$SCRIPT_DIR"

# Path to the files (relative to frontend/scripts/)
ADDRESS_MAPPING="../../contract/package_summaries/address_mapping.json"
TESTNET_ADDRESSES="../../../../deployed_contracts/testnet/address.yaml"
MOVE_TOML="../../contract/Move.toml"
LAYOUT_TSX="../src/app/layout.tsx"
USE_OBJECTS_TS="../src/hooks/useObjects.ts"

# Check if files exist
if [ ! -f "$ADDRESS_MAPPING" ]; then
    echo "Error: address_mapping.json not found at $ADDRESS_MAPPING"
    exit 1
fi

if [ ! -f "$TESTNET_ADDRESSES" ]; then
    echo "Error: address.yaml not found at $TESTNET_ADDRESSES"
    exit 1
fi

if [ ! -f "$MOVE_TOML" ]; then
    echo "Error: Move.toml not found at $MOVE_TOML"
    exit 1
fi

if [ ! -f "$LAYOUT_TSX" ]; then
    echo "Error: layout.tsx not found at $LAYOUT_TSX"
    exit 1
fi

if [ ! -f "$USE_OBJECTS_TS" ]; then
    echo "Error: useObjects.ts not found at $USE_OBJECTS_TS"
    exit 1
fi

# Extract addresses from YAML file
IKA_PACKAGE_ID=$(grep "^ika_package_id:" "$TESTNET_ADDRESSES" | awk '{print $2}')
IKA_COMMON_PACKAGE_ID=$(grep "^ika_common_package_id:" "$TESTNET_ADDRESSES" | awk '{print $2}')
IKA_DWALLET_2PC_MPC_PACKAGE_ID=$(grep "^ika_dwallet_2pc_mpc_package_id:" "$TESTNET_ADDRESSES" | awk '{print $2}')
IKA_COORDINATOR_OBJECT_ID=$(grep "^ika_coordinator_object_id:" "$TESTNET_ADDRESSES" | awk '{print $2}')

# Extract published-at address from Move.toml
PUBLISHED_AT=$(grep "^published-at" "$MOVE_TOML" | sed -E 's/published-at = "(.*)"/\1/')

echo "Updating address_mapping.json with testnet addresses..."
echo "  ika: $IKA_PACKAGE_ID"
echo "  ika_common: $IKA_COMMON_PACKAGE_ID"
echo "  ika_dwallet_2pc_mpc: $IKA_DWALLET_2PC_MPC_PACKAGE_ID"
echo "  coordinator: $IKA_COORDINATOR_OBJECT_ID"
echo ""
echo "Updating layout.tsx with published contract address..."
echo "  published-at: $PUBLISHED_AT"

# Use jq if available, otherwise use sed
if command -v jq &> /dev/null; then
    # Use jq for JSON manipulation
    jq --arg ika "$IKA_PACKAGE_ID" \
       --arg ika_common "$IKA_COMMON_PACKAGE_ID" \
       --arg ika_dwallet_2pc_mpc "$IKA_DWALLET_2PC_MPC_PACKAGE_ID" \
       '.ika = $ika | .ika_common = $ika_common | .ika_dwallet_2pc_mpc = $ika_dwallet_2pc_mpc' \
       "$ADDRESS_MAPPING" > "$ADDRESS_MAPPING.tmp" && mv "$ADDRESS_MAPPING.tmp" "$ADDRESS_MAPPING"
else
    # Fallback to sed (less reliable but works without jq)
    sed -i.bak \
        -e "s|\"ika\": \"0x0*\"|\"ika\": \"$IKA_PACKAGE_ID\"|" \
        -e "s|\"ika_common\": \"0x0*\"|\"ika_common\": \"$IKA_COMMON_PACKAGE_ID\"|" \
        -e "s|\"ika_dwallet_2pc_mpc\": \"0x0*\"|\"ika_dwallet_2pc_mpc\": \"$IKA_DWALLET_2PC_MPC_PACKAGE_ID\"|" \
        "$ADDRESS_MAPPING"
    rm -f "$ADDRESS_MAPPING.bak"
fi

echo "✓ Address mapping updated successfully!"

# Update layout.tsx with the published-at address
sed -i.bak \
    -e "s|'@local-pkg/multisig-contract': '0x[^']*'|'@local-pkg/multisig-contract': '$PUBLISHED_AT'|" \
    "$LAYOUT_TSX"
rm -f "$LAYOUT_TSX.bak"

echo "✓ Layout.tsx updated successfully!"

# Update useObjects.ts with the coordinator, multisigPackageId, and ikaPackageId
sed -i.bak \
    -e "s|coordinator: '0x[^']*'|coordinator: '$IKA_COORDINATOR_OBJECT_ID'|" \
    -e "s|multisigPackageId: '0x[^']*'|multisigPackageId: '$PUBLISHED_AT'|" \
    -e "s|ikaPackageId: '0x[^']*'|ikaPackageId: '$IKA_PACKAGE_ID'|" \
    "$USE_OBJECTS_TS"
rm -f "$USE_OBJECTS_TS.bak"

echo "✓ useObjects.ts updated successfully!"

