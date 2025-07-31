#!/bin/bash

# This script allows to add N validators to the next committee.
# The script accepts the <VALIDATOR_NUM> <FIRST_VALIDATOR_IN_SET> arguments.
# The <VALIDATOR_NUM> is the number of validators to add to the committee.
# The <FIRST_VALIDATOR_IN_SET> is the current committee size + 1, i.e. if the current committee size is 4,
# you should pass 5 as the <FIRST_VALIDATOR_IN_SET> argument.

# This script will only work if you run ./create-ika-genesis.sh beforehand.

set -e

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

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

# Check if jq is installed
if ! command_exists jq; then
    echo "jq is not installed, installing..."
    brew install jq
else
    echo "jq is already installed."
fi

# Check if yq is installed
if ! command_exists yq; then
    echo "yq is not installed, installing..."
    brew install yq
else
    echo "yq is already installed."
fi

. ./shared.sh

# Default values.
# The prefix for the validator names (e.g. val1.devnet.ika.cloud, val2.devnet.ika.cloud, etc...).
export VALIDATOR_PREFIX="val"
# The number of validators to join committee.

if [ $# -ne 2 ]; then
  echo "Usage: $0 <VALIDATOR_NUM> <FIRST_VALIDATOR_IN_SET>" >&2
  exit 1
fi
VALIDATOR_NUM="$1"
FIRST_VALIDATOR_IN_SET="$2"
# The number of staked tokens for each validator.
export VALIDATOR_STAKED_TOKENS_NUM=40000000000000000
# The subdomain for Ika the network.
# The binary name to use.
export BINARY_NAME="ika"
# The directory to store the key pairs.
export KEY_PAIRS_DIR="key-pairs"
export SUI_CHAIN_IDENTIFIER="custom"
SUI_CONFIG_PATH=~/.sui/sui_config

RUST_MIN_STACK=16777216

RUST_MIN_STACK=$RUST_MIN_STACK cargo build --release --bin "$BINARY_NAME"
cp ../../../../target/release/"$BINARY_NAME" .
BINARY_NAME="$(pwd)/$BINARY_NAME"

pushd $SUBDOMAIN

############################
## Create Validators
############################
SUI_BACKUP_DIR="sui_backup"
ROOT_SEED_CREATED=0  # Track if the root-seed.key has been created

for ((i=1; i<=VALIDATOR_NUM; i++)); do
    VALIDATOR_NAME="${VALIDATOR_PREFIX}${i}"
    VALIDATOR_HOSTNAME="${VALIDATOR_NAME}.${SUBDOMAIN}"

    # Use the VALIDATOR_HOSTNAME as the directory name.
    VALIDATOR_DIR="${VALIDATOR_HOSTNAME}"
    echo "Creating directory structure for validator '$VALIDATOR_NAME' with hostname '$VALIDATOR_HOSTNAME'"

    # Create validator directory and backup directory.
    mkdir -p "$VALIDATOR_DIR/$SUI_BACKUP_DIR"
    SUI_CONFIG_PATH=~/.sui/sui_config

    # Recreate the sui config for each validator.
    rm -rf $SUI_CONFIG_PATH
    mkdir -p $SUI_CONFIG_PATH

    VALIDATOR_ACCOUNT_KEY_FILE=${VALIDATOR_HOSTNAME}.account.json
    SUI_TEMPLATE_DIR=../sui-template
    SUI_CLIENT_YAML_FILE=client.yaml
    SUI_KEYSTORE_FILE=sui.keystore
    SUI_ALIASES_FILE=sui.aliases
    cp $SUI_TEMPLATE_DIR/sui.keystore.template "$SUI_CONFIG_PATH/$SUI_KEYSTORE_FILE"
    cp $SUI_TEMPLATE_DIR/client.template.yaml "$SUI_CONFIG_PATH/$SUI_CLIENT_YAML_FILE"
    cp $SUI_TEMPLATE_DIR/sui.aliases.template.json "$SUI_CONFIG_PATH/$SUI_ALIASES_FILE"

    pushd $SUI_CONFIG_PATH > /dev/null

    sui keytool generate ed25519 "m/44'/784'/0'/0'/0'" word24 --json > "$VALIDATOR_ACCOUNT_KEY_FILE"
    SUI_ADDR=$(jq -r '.suiAddress' "$VALIDATOR_ACCOUNT_KEY_FILE")
    MNEMONIC=$(jq -r '.mnemonic' "$VALIDATOR_ACCOUNT_KEY_FILE")
    sui keytool import "$MNEMONIC" ed25519 "m/44'/784'/0'/0'/0'"

    # Fetch the alias and change it (the --alias option is not working currently)
    SUI_CURRENT_ALIAS=$(jq -r '.[].alias' sui.aliases)
    sui keytool update-alias "$SUI_CURRENT_ALIAS" "$VALIDATOR_NAME"
    yq e -i ".envs[].alias = \"$SUBDOMAIN\"" "$SUI_CLIENT_YAML_FILE"
    yq e -i ".envs[].rpc = \"$SUI_FULLNODE_RPC_URL\"" "$SUI_CLIENT_YAML_FILE"
    yq e -i ".active_address = \"$SUI_ADDR\"" "$SUI_CLIENT_YAML_FILE"
    yq e -i ".active_env = \"$SUBDOMAIN\"" "$SUI_CLIENT_YAML_FILE"
    yq e -i ".keystore.File = \"$SUI_CONFIG_PATH/$SUI_KEYSTORE_FILE\"" "$SUI_CLIENT_YAML_FILE"

    popd > /dev/null
    cp -r $SUI_CONFIG_PATH "$VALIDATOR_DIR/$SUI_BACKUP_DIR"
    SENDER_SUI_ADDR=$SUI_ADDR

    # Create Validator info.
    pushd "$VALIDATOR_DIR" > /dev/null

    # If we already have a root-seed.key, copy it into current dir before make-validator-info
    if [ "$ROOT_SEED_CREATED" -eq 1 ]; then
        echo "Copying existing root-seed.key for validator '$VALIDATOR_NAME'"
        cp ../root-seed.key .
    fi

    # Now run make-validator-info
    RUST_MIN_STACK=$RUST_MIN_STACK $BINARY_NAME validator make-validator-info "$VALIDATOR_NAME" "$VALIDATOR_NAME" "" "" "$VALIDATOR_HOSTNAME" 0 "$SENDER_SUI_ADDR"

    # After the first validator generates root-seed.key, save it globally
    if [ "$ROOT_SEED_CREATED" -eq 0 ]; then
        echo "Saving initial root-seed.key after first validator"
        cp root-seed.key ../root-seed.key
        ROOT_SEED_CREATED=1
    fi

    mkdir -p "$KEY_PAIRS_DIR"
    mv ./*.key "$KEY_PAIRS_DIR"/

    popd > /dev/null

    sui keytool list
done


SUI_BACKUP_DIR="sui_backup"

export PUBLISHER_DIR=publisher

PUBLISHER_CONFIG_FILE="$PUBLISHER_DIR/ika_publish_config.json"

IKA_PACKAGE_ID=$(jq -r '.ika_package_id' "$PUBLISHER_CONFIG_FILE")
IKA_SYSTEM_PACKAGE_ID=$(jq -r '.ika_system_package_id' "$PUBLISHER_CONFIG_FILE")
IKA_SYSTEM_OBJECT_ID=$(jq -r '.ika_system_object_id' "$PUBLISHER_CONFIG_FILE")
IKA_COMMON_PACKAGE_ID=$(jq -r '.ika_common_package_id' "$PUBLISHER_CONFIG_FILE")
IKA_DWALLET_2PC_MPC_PACKAGE_ID=$(jq -r '.ika_dwallet_2pc_mpc_package_id' "$PUBLISHER_CONFIG_FILE")

# Print the values for verification.
echo "IKA Package ID: $IKA_PACKAGE_ID"
echo "IKA System Package ID: $IKA_SYSTEM_PACKAGE_ID"
echo "System ID: $IKA_SYSTEM_OBJECT_ID"
echo "IKA Common Package ID: $IKA_COMMON_PACKAGE_ID"
echo "IKA DWallet 2PC MPC Package ID: $IKA_DWALLET_2PC_MPC_PACKAGE_ID"

############################
# Request Tokens and Create Validator.yaml (Max 5 Parallel + Retry)
############################

# Concurrency control (compatible with bash < 4.3)
MAX_JOBS=10
JOB_COUNT=0

for ((i=1; i<=VALIDATOR_NUM; i++)); do
  request_and_generate_yaml "$i" &

  (( JOB_COUNT++ ))

  if [[ $JOB_COUNT -ge $MAX_JOBS ]]; then
    wait  # wait for all background jobs
    JOB_COUNT=0
  fi
done

# Wait for any remaining background jobs
wait

# Array to store validator tuples
VALIDATOR_TUPLES=()
TMP_OUTPUT_DIR="/tmp/become_candidate_outputs"
TUPLES_FILE="$TMP_OUTPUT_DIR/tuples.txt"
rm -f "$TUPLES_FILE"

# Launch jobs with a max concurrency of 5 using a simple counter
MAX_JOBS=10
JOB_COUNT=0

for ((i=1; i<=VALIDATOR_NUM; i++)); do
    process_validator "$i" &

    (( JOB_COUNT++ ))

    if [[ $JOB_COUNT -ge $MAX_JOBS ]]; then
        wait
        JOB_COUNT=0
    fi
done

# Final wait for any remaining jobs
wait

# Read tuples file after all jobs complete
if [[ -f "$TUPLES_FILE" ]]; then
    while IFS= read -r tuple; do
        VALIDATOR_TUPLES+=("$tuple")
    done < "$TUPLES_FILE"
else
    echo "[ERROR] Tuples file not found: $TUPLES_FILE"
    exit 1
fi

# Summary
echo
echo "✅ All validator tuples:"
for tup in "${VALIDATOR_TUPLES[@]}"; do
    echo "  $tup"
done

############################
# Stake Validators
############################

# Copy publisher sui_config to SUI_CONFIG_PATH
rm -rf "$SUI_CONFIG_PATH"
mkdir -p "$SUI_CONFIG_PATH"
cp -r "$PUBLISHER_DIR/sui_config/"* "$SUI_CONFIG_PATH"

# Extract IKA_SUPPLY_ID (ika_coin_id) from publisher config
IKA_SUPPLY_ID=$(jq -r '.ika_supply_id' "$PUBLISHER_CONFIG_FILE")

# Stake Validators
for entry in "${VALIDATOR_TUPLES[@]}"; do
    # New format: validator_name:validator_id:validator_cap_id
    IFS=":" read -r VALIDATOR_NAME VALIDATOR_ID VALIDATOR_CAP_ID <<< "$entry"

    echo "Staking for Validator '$VALIDATOR_NAME' (ID: $VALIDATOR_ID) with IKA Coin ID: $IKA_SUPPLY_ID"

    # Execute the stake-validator command
    $BINARY_NAME validator stake-validator \
        --validator-id "$VALIDATOR_ID" \
        --ika-supply-id "$IKA_SUPPLY_ID" \
        --stake-amount "$VALIDATOR_STAKED_TOKENS_NUM"
done

echo "✅ All validators have been staked successfully."
############################
# Join Committee
############################

for tuple in "${VALIDATOR_TUPLES[@]}"; do
    IFS=":" read -r VALIDATOR_NAME VALIDATOR_ID VALIDATOR_CAP_ID <<< "$tuple"

    # Find the validator's hostname based on its name
    for ((i=1; i<=VALIDATOR_NUM; i++)); do
        NAME="${VALIDATOR_PREFIX}${i}"
        HOSTNAME="${VALIDATOR_NAME}.${SUBDOMAIN}"
        if [[ "$NAME" == "$VALIDATOR_NAME" ]]; then
            echo "Debug: Processing validator: $VALIDATOR_NAME with ID: $VALIDATOR_ID and Cap ID: $VALIDATOR_CAP_ID"

            VALIDATOR_HOSTNAME="$HOSTNAME"
            echo "Debug: Found hostname: $VALIDATOR_HOSTNAME"

            # Copy sui_config and run join-committee
            VALIDATOR_DIR="$VALIDATOR_HOSTNAME"
            rm -rf "$SUI_CONFIG_PATH"
            echo "Debug: Removing $SUI_CONFIG_PATH"
            mkdir -p "$SUI_CONFIG_PATH"
            echo "Debug: Creating $SUI_CONFIG_PATH"
            echo "Debug: Copying sui_config from $VALIDATOR_DIR/$SUI_BACKUP_DIR/sui_config/ to $SUI_CONFIG_PATH"
            cp -r "$VALIDATOR_DIR/$SUI_BACKUP_DIR/sui_config/"* "$SUI_CONFIG_PATH"

            echo "Joining committee for Validator '$VALIDATOR_NAME' (Cap ID: $VALIDATOR_CAP_ID)"

            VAL_IKA_CONFIG_DIR="/tmp/ika_config_${VALIDATOR_NAME}"
            IKA_SUI_CONFIG_FILE="$VAL_IKA_CONFIG_DIR/ika_sui_config.yaml"
            $BINARY_NAME validator join-committee \
                --validator-cap-id "$VALIDATOR_CAP_ID" --ika-sui-config "$IKA_SUI_CONFIG_FILE"
            break
        fi
    done
done

IKA_DWALLET_COORDINATOR_OBJECT_ID=$(jq -r '.ika_dwallet_coordinator_object_id' "$PUBLISHER_DIR/ika_publish_config.json")
for ((i=1; i<=VALIDATOR_NUM; i++)); do
    VALIDATOR_NAME="${VALIDATOR_PREFIX}${i}"
    VALIDATOR_HOSTNAME="${VALIDATOR_NAME}.${SUBDOMAIN}"
    VALIDATOR_DIR="${VALIDATOR_HOSTNAME}"
    yq e ".\"sui-connector-config\".\"ika-common-package-id\" = \"$IKA_COMMON_PACKAGE_ID\"" -i "$VALIDATOR_DIR/validator.yaml"
    yq e ".\"sui-connector-config\".\"ika-dwallet-2pc-mpc-package-id\" = \"$IKA_DWALLET_2PC_MPC_PACKAGE_ID\"" -i "$VALIDATOR_DIR/validator.yaml"
    yq e ".\"sui-connector-config\".\"ika-dwallet-coordinator-object-id\" = \"$IKA_DWALLET_COORDINATOR_OBJECT_ID\"" -i "$VALIDATOR_DIR/validator.yaml"
done

echo "✅ All validators have joined the committee successfully."