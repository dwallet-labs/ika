#!/bin/bash

# Check if directory path is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <validator_directory_path>"
    echo "Example: $0 beta.devnet2.ika-network.net"
    exit 1
fi

VALIDATOR_DIR_PATH="$1"

# Check if the directory exists
if [ ! -d "$VALIDATOR_DIR_PATH" ]; then
    echo "Error: Directory '$VALIDATOR_DIR_PATH' does not exist."
    exit 1
fi

echo "Generating seed_peers.yaml from directory: $VALIDATOR_DIR_PATH"

# Change to the validator directory
cd "$VALIDATOR_DIR_PATH" || exit 1

SEED_PEERS_FILE="seed_peers.yaml"
: > "$SEED_PEERS_FILE"  # Empty or create file

# Find all validator directories (those starting with 'val' and ending with the domain)
# Sort them alphanumerically to ensure consistent ordering
for VALIDATOR_DIR in $(ls -1d val* 2>/dev/null | sort -V); do
    # Check if it's a directory and matches the pattern
    if [ -d "$VALIDATOR_DIR" ]; then
        echo "Processing validator directory: $VALIDATOR_DIR"

        INFO_FILE="$VALIDATOR_DIR/validator.info"
        NETWORK_KEY_FILE="$VALIDATOR_DIR/key-pairs/network.key"

        if [[ -f "$INFO_FILE" && -f "$NETWORK_KEY_FILE" ]]; then
            # Extract p2p_address from validator.info
            P2P_ADDR=$(yq e '.p2p_address' "$INFO_FILE")

            # Extract peer_id from network.key using sui keytool
            PEER_ID=$(sui keytool show "$NETWORK_KEY_FILE" --json | jq -r '.peerId')

            if [ "$P2P_ADDR" != "null" ] && [ "$PEER_ID" != "null" ] && [ -n "$P2P_ADDR" ] && [ -n "$PEER_ID" ]; then
                echo "- address: $P2P_ADDR" >> "$SEED_PEERS_FILE"
                echo "  peer-id: $PEER_ID" >> "$SEED_PEERS_FILE"
                echo "  ✅ Added $VALIDATOR_DIR"
            else
                echo "  ❌ Failed to extract p2p_address or peer_id for $VALIDATOR_DIR"
                echo "     P2P_ADDR: $P2P_ADDR"
                echo "     PEER_ID: $PEER_ID"
            fi
        else
            echo "  ❌ Missing required files for $VALIDATOR_DIR"
            echo "     INFO_FILE exists: $([ -f "$INFO_FILE" ] && echo "yes" || echo "no")"
            echo "     NETWORK_KEY_FILE exists: $([ -f "$NETWORK_KEY_FILE" ] && echo "yes" || echo "no")"
        fi
    fi
done

echo ""
echo "✅ $SEED_PEERS_FILE generated in $VALIDATOR_DIR_PATH/"
echo "📊 Total entries: $(grep -c "address:" "$SEED_PEERS_FILE")"
