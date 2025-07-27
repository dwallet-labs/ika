#!/bin/bash

set -euo pipefail
#set -x

# Default values
VALIDATOR_NUM=55
TERRAFORM_WORKSPACES_FILE="../../../infra/tf-gcp/workspaces.tf"
SUBDOMAIN=beta.devnet.ika-network.net
GCP_PROJECT=mainnet-449616
ENV_PREFIX=ika-devnet
TF_NETWORK_NAME=devnet

# Validate required parameters
if [ -z "$SUBDOMAIN" ]; then
    echo "Error: No subdomain provided." >&2
    exit 1
fi

if [ -z "$GCP_PROJECT" ]; then
    echo "Error: GCP_PROJECT not provided." >&2
    exit 1
fi

if [ -z "$ENV_PREFIX" ]; then
    echo "Error: ENV_PREFIX not provided." >&2
    exit 1
fi

if [ -z "$TF_NETWORK_NAME" ]; then
    echo "Error: TF_NETWORK_NAME not provided." >&2
    exit 1
fi

# Validate that subdomain directory exists
if [ ! -d "$SUBDOMAIN" ]; then
    echo "Error: Subdomain directory '$SUBDOMAIN' not found." >&2
    exit 1
fi

# Validate that locals.tf exists in the subdomain directory
if [ ! -f "$SUBDOMAIN/locals.tf" ]; then
    echo "Error: locals.tf not found in '$SUBDOMAIN' directory." >&2
    exit 1
fi

echo "🚀 Starting deployment and Terraform update process..."
echo "📁 Subdomain: $SUBDOMAIN"
echo "☁️  GCP Project: $GCP_PROJECT"
echo "🏷️  Environment Prefix: $ENV_PREFIX"
echo "🔧 Terraform Network Name: $TF_NETWORK_NAME"
echo "👥 Validator Count: $VALIDATOR_NUM"
echo "📄 Terraform File: $TERRAFORM_WORKSPACES_FILE"
echo ""

###############################################################################
# PART 1: Deploy Validator Keys (Same as gcp-upsert-validator-keys.sh)
###############################################################################

echo "🔐 Deploying validator keys to GCP secrets..."

pushd "$SUBDOMAIN"

# List of key files.
KEY_FILES=("consensus.key" "network.key" "protocol.key" "root-seed.key")
VALIDATOR_NAME_PREFIX="val"

# Maximum parallel jobs
MAX_PARALLEL=10
job_count=0

for i in $(seq 1 ${VALIDATOR_NUM}); do
    # example: val3.beta.devnet.ika-network.net
    VALIDATOR_FULL_DIR_NAME="${VALIDATOR_NAME_PREFIX}${i}.${SUBDOMAIN}"
    # example: ika-new-devnet-ika-val-3-keys
    VALIDATOR_SECRET_NAME="${ENV_PREFIX}-ika-${VALIDATOR_NAME_PREFIX}-${i}-keys"

    if [ ! -d "$VALIDATOR_FULL_DIR_NAME/key-pairs" ]; then
        echo "⚠️  Warning: Directory $VALIDATOR_FULL_DIR_NAME/key-pairs not found, skipping..."
        continue
    fi

    pushd "$VALIDATOR_FULL_DIR_NAME/key-pairs"

    # Initialize an empty JSON object
    SECRETS_JSON="{}"

    # Debug: print current working directory
    echo "📂 Processing validator keys in: $(pwd)"

    # Loop through each key file and add its content to the JSON object
    for FILE in "${KEY_FILES[@]}"; do
        if [ -f "$FILE" ]; then
            CONTENT=$(cat "$FILE")
            SECRETS_JSON=$(echo "$SECRETS_JSON" | jq --arg key "$FILE" --arg value "$CONTENT" '. + {($key): $value}')
        else
            echo "⚠️  Warning: Key file $FILE not found in $(pwd)"
        fi
    done

    # Output the final JSON object to a file.
    echo "$SECRETS_JSON" > secrets.json
    # Add a new version to the existing secret.
    gcloud secrets versions add "$VALIDATOR_SECRET_NAME" --data-file=secrets.json --project "$GCP_PROJECT"
    echo "✅ Added new version to secret: $VALIDATOR_SECRET_NAME"
    popd

    # Control parallel execution
    (( job_count++ ))
    if [[ $job_count -ge $MAX_PARALLEL ]]; then
        wait
        job_count=0
    fi
done

# Wait for any remaining jobs
wait

echo "✅ Validator keys deployment completed!"

###############################################################################
# PART 2: Deploy Fullnode Keys (Same as gcp-upsert-fullnode-notifier-secret.sh)
###############################################################################

echo "🔐 Deploying fullnode keys to GCP secrets..."

# Change to the publisher directory within the subdomain directory
if [ -d "publisher/sui_config" ]; then
    pushd "publisher/sui_config"

    # Ensure publisher.key exists
    if [ -f "publisher.key" ]; then
        # Note: this script currently supports only 1 fullnode.
        # Example: ika-devnet-publisher-key
        SECRET_NAME="${ENV_PREFIX}-ika-fullnode-1-keys"

        # We assume that the secret exists (created by TF), so add a new version.
        gcloud secrets versions add "$SECRET_NAME" --data-file="publisher.key" --project "$GCP_PROJECT"
        echo "✅ Added new version to secret: $SECRET_NAME"
    else
        echo "⚠️  Warning: publisher.key file not found in $(pwd)"
    fi

    popd
else
    echo "⚠️  Warning: publisher/sui_config directory not found, skipping fullnode key deployment"
fi

popd

echo "✅ Fullnode keys deployment completed!"

###############################################################################
# PART 3: Update Terraform Configuration
###############################################################################

echo "🔧 Updating Terraform configuration..."

# Validate that the Terraform file exists
if [ ! -f "$TERRAFORM_WORKSPACES_FILE" ]; then
    echo "Error: Terraform workspaces file '$TERRAFORM_WORKSPACES_FILE' not found." >&2
    exit 1
fi

# Extract the ika_chain_config block content more reliably
IKA_CHAIN_CONFIG=$(awk '/ika_chain_config = {/,/}/' "$SUBDOMAIN/locals.tf" | sed 's/^[[:space:]]*/          /')

if [ -z "$IKA_CHAIN_CONFIG" ]; then
    echo "Error: Could not extract ika_chain_config from locals.tf" >&2
    exit 1
fi

echo "📋 Extracted ika_chain_config:"
echo "$IKA_CHAIN_CONFIG"

# Create a backup of the original file
cp "$TERRAFORM_WORKSPACES_FILE" "${TERRAFORM_WORKSPACES_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo "📋 Created backup: ${TERRAFORM_WORKSPACES_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Use a more robust approach to replace the ika_chain_config block
# We'll use a file-based approach to avoid string interpolation issues
temp_file=$(mktemp)
config_file=$(mktemp)

# Write the new config to a temporary file
echo "$IKA_CHAIN_CONFIG" > "$config_file"

awk -v network_name="$TF_NETWORK_NAME" -v config_file="$config_file" '
BEGIN {
    in_network = 0
    in_ika_config = 0
    network_brace_count = 0
}

# Look for the network block
$0 ~ network_name " = {" {
    in_network = 1
    network_brace_count = 1
    print
    next
}

# If we are in the target network block
in_network == 1 {
    # Count braces to track the network block level
    for (i = 1; i <= length($0); i++) {
        char = substr($0, i, 1)
        if (char == "{") network_brace_count++
        if (char == "}") network_brace_count--
    }

    # Check if we are entering ika_chain_config
    if (/ika_chain_config = {/ && in_ika_config == 0) {
        in_ika_config = 1
        # Print the new config from file instead
        while ((getline line < config_file) > 0) {
            print line
        }
        close(config_file)
        next
    }

    # Skip lines while in ika_chain_config
    if (in_ika_config == 1) {
        # Look for the closing brace of ika_chain_config
        if (/^[[:space:]]*}[[:space:]]*$/) {
            in_ika_config = 0
        }
        next
    }

    # Print the line if not in ika_chain_config
    print

    # Check if we are exiting the network block
    if (network_brace_count == 0) {
        in_network = 0
    }
    next
}

# Print all other lines
{
    print
}
' "$TERRAFORM_WORKSPACES_FILE" > "$temp_file"

# Clean up the temporary config file
rm -f "$config_file"

# Replace the original file with the updated content
mv "$temp_file" "$TERRAFORM_WORKSPACES_FILE"

echo "✅ Updated ika_chain_config for network '$TF_NETWORK_NAME' in $TERRAFORM_WORKSPACES_FILE"

# Verify the update was successful
if grep -A 10 "$TF_NETWORK_NAME = {" "$TERRAFORM_WORKSPACES_FILE" | grep -q "ika_chain_config = {"; then
    echo "✅ Terraform configuration update verified successfully!"
else
    echo "⚠️  Warning: Could not verify Terraform configuration update. Please check manually."
fi

###############################################################################
# PART 4: Copy Files to Terraform Modules Directory
###############################################################################

echo "📁 Copying files to Terraform modules directory..."

# Extract the subdomain prefix (part before "ika-network")
SUBDOMAIN_PREFIX=$(echo "$SUBDOMAIN" | sed 's/\.ika-network.*//')
echo "🔍 Extracted subdomain prefix: $SUBDOMAIN_PREFIX"

# Get the directory where the Terraform workspaces file is located
TERRAFORM_DIR=$(dirname "$TERRAFORM_WORKSPACES_FILE")
echo "📂 Terraform directory: $TERRAFORM_DIR"

# Construct the destination directory path
DEST_DIR="$TERRAFORM_DIR/modules/ika-chains/files/$SUBDOMAIN_PREFIX/ika"
echo "🎯 Destination directory: $DEST_DIR"

# Create the destination directory if it doesn't exist
mkdir -p "$DEST_DIR"
echo "📁 Created destination directory: $DEST_DIR"

# Files to copy
FILES_TO_COPY=("seed_peers.yaml")

# Copy each file
for FILE in "${FILES_TO_COPY[@]}"; do
    SOURCE_FILE="$SUBDOMAIN/$FILE"
    DEST_FILE="$DEST_DIR/$FILE"

    if [ -f "$SOURCE_FILE" ]; then
        cp "$SOURCE_FILE" "$DEST_FILE"
        echo "✅ Copied $FILE to $DEST_FILE"
    else
        echo "⚠️  Warning: Source file $SOURCE_FILE not found, skipping..."
    fi
done

echo "✅ File copying completed!"

###############################################################################
# COMPLETION
###############################################################################

echo ""
echo "🎉 All tasks completed successfully!"
echo "📋 Summary:"
echo "   - Deployed $VALIDATOR_NUM validator keys to GCP secrets"
echo "   - Deployed fullnode keys to GCP secrets"
echo "   - Updated Terraform configuration for network '$TF_NETWORK_NAME'"
echo "   - Copied configuration files to Terraform modules directory"
echo "   - Backup created: ${TERRAFORM_WORKSPACES_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo ""
echo "🔍 Next steps:"
echo "   1. Review the updated Terraform configuration"
echo "   2. Run 'terraform plan' to validate the changes"
echo "   3. Apply the changes with 'terraform apply'"
