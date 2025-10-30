#!/bin/bash

set -e

# Load environment variables from .env if not already set
if [ -f .env ]; then
  echo "Loading variables from .env"
  while IFS='=' read -r key value; do
    # Skip comments and empty lines
    if [ -z "$key" ] || echo "$key" | grep -q '^#'; then
      continue
    fi

    # Only export if not already set in environment
    if [ -z "${!key}" ]; then
      export "$key=$value"
    fi
  done < .env
else
  echo ".env file not found!"
  exit 1
fi

cp ../../../../target/debug/ika .
BINARY_NAME="$(pwd)/ika"

pushd "$SUBDOMAIN"
SUI_CONFIG_PATH=~/.sui/sui_config
export PUBLISHER_DIR=publisher
# Copy publisher sui_config to SUI_CONFIG_PATH
rm -rf "$SUI_CONFIG_PATH"
mkdir -p "$SUI_CONFIG_PATH"
cp -r "$PUBLISHER_DIR/sui_config/"* "$SUI_CONFIG_PATH"
pushd ../upgrade-network-key
# set a var named protocol_cap_id to the value of the first param passed to the script
protocol_cap_id=$1

$BINARY_NAME protocol set-supported-and-pricing \
  --protocol-cap-id "$protocol_cap_id" \
  --default-pricing "$(pwd)/new_pricing.yaml" \
  --supported-curves-to-signature-algorithms-to-hash-schemes "$(pwd)/supported_curves_config.yaml"