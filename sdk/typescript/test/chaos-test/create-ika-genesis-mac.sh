#!/bin/bash

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

# Default values.
# The prefix for the validator names (e.g. val1.devnet.ika.cloud, val2.devnet.ika.cloud, etc...).
export VALIDATOR_PREFIX="val"
# The number of staked tokens for each validator.
export VALIDATOR_STAKED_TOKENS_NUM=40000000000000000
# The subdomain for Ika the network.
# For local minikube cluster, use the .svc.cluster.local suffix
export SUBDOMAIN="ika-dns-service.ika.svc.cluster.local"
#export SUBDOMAIN="beta50.devnet.ika-network.net"
# The binary name to use.
export BINARY_NAME="ika"
# The directory to store the key pairs.
export KEY_PAIRS_DIR="key-pairs"
# The root address for the genesis account (to hold all the tokens).
# In a testnet use the faucet public key.
ROOT_ADDR=""
# The file containing the validators (separator: newline).
export VALIDATORS_FILE=""
#export EPOCH_DURATION_TIME_MS=2400000
# Sui chain identifier.
export SUI_CHAIN_IDENTIFIER="custom"

# Function to display help message
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "This script sets up a genesis and config with given options."
    echo ""
    echo "Options:"
    echo "  --validator-prefix <prefix>         Set the prefix for validators. Default: $VALIDATOR_PREFIX"
    echo "  --validator-num <number>            Set the number of validators. Default: $VALIDATOR_NUM"
    echo "  --validator-staked-tokens-num <num>   Set the number of staked tokens. Default: $VALIDATOR_STAKED_TOKENS_NUM"
    echo "  --subdomain <subdomain>             Set the subdomain for validators. Default: $SUBDOMAIN"
    echo "  --binary-name <path>                Set the binary name path. Default: $PWD/ika"
    echo "  --key-pairs-dir <directory>         Set the directory for key pairs. Default: key-pairs"
    echo "  --root-addr <address>               Set the root address. Default: 0x3e..."
    echo "  --validators-file <file>            Specify a file with validators."
    echo "  --sui-faucet-url <url>              Set the SUI faucet URL. Default: $SUI_FAUCET_URL"
    echo "  --epoch-duration-time <time>        Set the epoch duration time. Default: $EPOCH_DURATION_TIME_MS"
    echo "  -h, --help                        Display this help message and exit."
    echo ""
    echo "Note: --validators-file overrides --validator-prefix and --validator-num."
}

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --validator-prefix) VALIDATOR_PREFIX="$2"; shift ;;
        --validator-num) VALIDATOR_NUM="$2"; shift ;;
        --validator-staked-tokens-num) VALIDATOR_STAKED_TOKENS_NUM="$2"; shift ;;
        --subdomain) SUBDOMAIN="$2"; shift ;;
        --binary-name) BINARY_NAME="$2"; shift ;;
        --key-pairs-dir) KEY_PAIRS_DIR="$2"; shift ;;
        --root-addr) ROOT_ADDR="$2"; shift ;;
        --validators-file) VALIDATORS_FILE="$2"; shift ;;
        --sui-faucet-url) SUI_FAUCET_URL="$2"; shift ;;
        --epoch-duration-time) EPOCH_DURATION_TIME_MS="$2"; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done


RUST_MIN_STACK=16777216

RUST_MIN_STACK=$RUST_MIN_STACK cargo build --release --bin "$BINARY_NAME"
cp ../../../../target/release/"$BINARY_NAME" .
BINARY_NAME="$(pwd)/$BINARY_NAME"

VALIDATORS_ARRAY=()

# Check if --validators-file is provided and process it.
if [[ -n "$VALIDATORS_FILE" ]]; then
    echo "Creating validators from file: $VALIDATORS_FILE"

    if [[ ! -f "$VALIDATORS_FILE" ]]; then
        echo "Error: File '$VALIDATORS_FILE' not found." >&2
        exit 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines.
        [[ -z "$line" ]] && continue

        # Split the line into two parts: validator name and hostname.
        read -r name hostname <<< "$line"

        # Trim any extra whitespace.
        name=$(echo "$name" | xargs)
        hostname=$(echo "$hostname" | xargs)

        # Append the tuple as "name:hostname" to the array.
        VALIDATORS_ARRAY+=("$name:$hostname")
    done < "$VALIDATORS_FILE"

    for entry in "${VALIDATORS_ARRAY[@]}"; do
        IFS=":" read -r v_name v_hostname <<< "$entry"
        echo "Processed validator: Name = $v_name, Hostname = $v_hostname"
    done

    VALIDATOR_NUM=${#VALIDATORS_ARRAY[@]}
else
    echo "Creating validators from prefix '$VALIDATOR_PREFIX' and number '$VALIDATOR_NUM'"

    for ((i=1; i<=VALIDATOR_NUM; i++)); do
        VALIDATOR_NAME="${VALIDATOR_PREFIX}${i}"
        # For enumerated list, compute the hostname as: name.SUBDOMAIN
        VALIDATOR_HOSTNAME="${VALIDATOR_NAME}.${SUBDOMAIN}"
        echo "Generated validator: Name = $VALIDATOR_NAME, Hostname = $VALIDATOR_HOSTNAME"
        VALIDATORS_ARRAY+=("$VALIDATOR_NAME:$VALIDATOR_HOSTNAME")
    done
fi

#############################
## Create a dir for this deployment.
#############################
rm -rf "$SUBDOMAIN"
mkdir -p "$SUBDOMAIN"
pushd "$SUBDOMAIN"

############################
## Create Validators
############################
SUI_BACKUP_DIR="sui_backup"
CLASS_GROUPS_KEY_CREATED=0  # Track if the class-groups.key has been created

for entry in "${VALIDATORS_ARRAY[@]}"; do
    # Split the tuple "name:hostname" into VALIDATOR_NAME and VALIDATOR_HOSTNAME.
    IFS=":" read -r VALIDATOR_NAME VALIDATOR_HOSTNAME <<< "$entry"

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

    # If we already have a class-groups.key, copy it into current dir before make-validator-info
    if [ "$CLASS_GROUPS_KEY_CREATED" -eq 1 ]; then
        echo "Copying existing class-groups.key for validator '$VALIDATOR_NAME'"
        cp ../class-groups.key .
    fi

    # Now run make-validator-info
    RUST_MIN_STACK=$RUST_MIN_STACK $BINARY_NAME validator make-validator-info "$VALIDATOR_NAME" "$VALIDATOR_NAME" "" "" "$VALIDATOR_HOSTNAME" 0 "$SENDER_SUI_ADDR"

    # After the first validator generates class-groups.key, save it globally
    if [ "$CLASS_GROUPS_KEY_CREATED" -eq 0 ]; then
        echo "Saving initial class-groups.key after first validator"
        cp class-groups.key ../class-groups.key
        CLASS_GROUPS_KEY_CREATED=1
    fi

    mkdir -p "$KEY_PAIRS_DIR"
    mv ./*.key "$KEY_PAIRS_DIR"/

    popd > /dev/null

    sui keytool list
done


###############################
# Create the Ika system on Sui.
###############################
rm -rf "$SUI_CONFIG_PATH"

cargo build --bin ika-swarm-config
cp ../../../../../target/debug/ika-swarm-config .

# Publish IKA Modules (Creates the publisher config).
./ika-swarm-config publish-ika-modules --sui-rpc-addr "$SUI_FULLNODE_RPC_URL" --sui-faucet-addr "$SUI_FAUCET_URL"

# Mint IKA Tokens
./ika-swarm-config mint-ika-tokens --sui-rpc-addr "$SUI_FULLNODE_RPC_URL" --sui-faucet-addr "$SUI_FAUCET_URL" --ika-config-path ./ika_publish_config.json

# Init IKA
./ika-swarm-config init-env --sui-rpc-addr "$SUI_FULLNODE_RPC_URL" --ika-config-path ./ika_publish_config.json --epoch-duration-ms "$EPOCH_DURATION_TIME_MS"

export PUBLISHER_DIR=publisher

mkdir -p $PUBLISHER_DIR
mv ika_publish_config.json $PUBLISHER_DIR/
cp -r "$SUI_CONFIG_PATH" $PUBLISHER_DIR/
PUBLISHER_CONFIG_FILE="$PUBLISHER_DIR/ika_publish_config.json"

IKA_PACKAGE_ID=$(jq -r '.ika_package_id' "$PUBLISHER_CONFIG_FILE")
IKA_SYSTEM_PACKAGE_ID=$(jq -r '.ika_system_package_id' "$PUBLISHER_CONFIG_FILE")
IKA_SYSTEM_OBJECT_ID=$(jq -r '.ika_system_object_id' "$PUBLISHER_CONFIG_FILE")

# Print the values for verification.
echo "IKA Package ID: $IKA_PACKAGE_ID"
echo "IKA System Package ID: $IKA_SYSTEM_PACKAGE_ID"
echo "System ID: $IKA_SYSTEM_OBJECT_ID"

cat > locals.tf <<EOF
locals {
  ika_chain_config = {
    sui_chain_identifier  = "${SUI_CHAIN_IDENTIFIER}"
    ika_package_id        = "${IKA_PACKAGE_ID}"
    ika_system_package_id = "${IKA_SYSTEM_PACKAGE_ID}"
    ika_system_object_id  = "${IKA_SYSTEM_OBJECT_ID}"
  }
}
EOF

############################
# Request Tokens and Create Validator.yaml (Max 5 Parallel + Retry)
############################

request_and_generate_yaml() {
  local entry="$1"
  IFS=":" read -r VALIDATOR_NAME VALIDATOR_HOSTNAME <<< "$entry"
  local VALIDATOR_DIR="${VALIDATOR_HOSTNAME}"

  # Extract values from the validator.info file
  local ACCOUNT_ADDRESS
  ACCOUNT_ADDRESS=$(yq e '.account_address' "${VALIDATOR_DIR}/validator.info")
  local P2P_ADDR
  P2P_ADDR=$(yq e '.p2p_address' "${VALIDATOR_DIR}/validator.info")

  # Copy the validator template
  cp ../validator.template.yaml "$VALIDATOR_DIR/validator.yaml"

  # Replace placeholders using yq
  yq e ".\"sui-connector-config\".\"sui-rpc-url\" = \"$SUI_DOCKER_URL\"" -i "$VALIDATOR_DIR/validator.yaml"
  yq e ".\"sui-connector-config\".\"sui-chain-identifier\" = \"$SUI_CHAIN_IDENTIFIER\"" -i "$VALIDATOR_DIR/validator.yaml"
  yq e ".\"sui-connector-config\".\"ika-package-id\" = \"$IKA_PACKAGE_ID\"" -i "$VALIDATOR_DIR/validator.yaml"
  yq e ".\"sui-connector-config\".\"ika-system-package-id\" = \"$IKA_SYSTEM_PACKAGE_ID\"" -i "$VALIDATOR_DIR/validator.yaml"
  yq e ".\"sui-connector-config\".\"ika-system-object-id\" = \"$IKA_SYSTEM_OBJECT_ID\"" -i "$VALIDATOR_DIR/validator.yaml"

  yq e ".p2p-config.external-address = \"$P2P_ADDR\"" -i "$VALIDATOR_DIR/validator.yaml"

  # Request tokens from the faucet with retry
  local attempt=1
  local max_attempts=10
  local sleep_time=2

  echo "[Faucet] Requesting tokens for '$VALIDATOR_NAME' ($ACCOUNT_ADDRESS)..."

  while (( attempt <= max_attempts )); do
    response=$(curl -s -w "%{http_code}" -o "$VALIDATOR_DIR/faucet_response.json" -X POST --location "${SUI_FAUCET_URL}" \
      -H "Content-Type: application/json" \
      -d '{
            "FixedAmountRequest": {
              "recipient": "'"${ACCOUNT_ADDRESS}"'"
            }
          }')

    if [[ "$response" == "201" || "$response" == "200" ]]; then
        echo "[Faucet] ✅ Success for '$VALIDATOR_NAME'"
        jq . "$VALIDATOR_DIR/faucet_response.json"
        break
      else
        echo "[Faucet] ❌ Attempt $attempt failed with HTTP $response for '$VALIDATOR_NAME'"
        (( attempt++ ))
        sleep $(( sleep_time ** attempt ))
      fi
    done



  if (( attempt > max_attempts )); then
    echo "[Faucet] ❗ Failed to get tokens for '$VALIDATOR_NAME' after $max_attempts attempts."
  fi
}

# Concurrency control (compatible with bash < 4.3)
MAX_JOBS=10
JOB_COUNT=0

for entry in "${VALIDATORS_ARRAY[@]}"; do
  request_and_generate_yaml "$entry" &

  (( JOB_COUNT++ ))

  if [[ $JOB_COUNT -ge $MAX_JOBS ]]; then
    wait  # wait for all background jobs
    JOB_COUNT=0
  fi
done

# Wait for any remaining background jobs
wait

# This is needed later for the publisher, in oder to update the ika_sui_config.yaml.
$BINARY_NAME validator config-env \
    --ika-package-id "$IKA_PACKAGE_ID" \
    --ika-system-package-id "$IKA_SYSTEM_PACKAGE_ID" \
    --ika-system-object-id "$IKA_SYSTEM_OBJECT_ID"

############################
# Become Validator Candidate (Max 5 Parallel Jobs)
############################

# Array to store validator tuples
VALIDATOR_TUPLES=()
TMP_OUTPUT_DIR="/tmp/become_candidate_outputs"
TUPLES_FILE="$TMP_OUTPUT_DIR/tuples.txt"
mkdir -p "$TMP_OUTPUT_DIR"
rm -f "$TUPLES_FILE"

# Function to process a validator
process_validator() {
    local entry="$1"
    IFS=":" read -r VALIDATOR_NAME VALIDATOR_HOSTNAME <<< "$entry"
    local VALIDATOR_DIR="${VALIDATOR_HOSTNAME}"
    local OUTPUT_FILE="$TMP_OUTPUT_DIR/${VALIDATOR_NAME}_output.json"
    local LOCAL_SUI_CONFIG_DIR="/tmp/sui_config_${VALIDATOR_NAME}"
    local LOCAL_IKA_CONFIG_DIR="/tmp/ika_config_${VALIDATOR_NAME}"

    echo "[Become Validator Candidate] Processing validator '$VALIDATOR_NAME' in directory '$VALIDATOR_DIR'"

    rm -rf "$LOCAL_IKA_CONFIG_DIR"
    mkdir -p "$LOCAL_IKA_CONFIG_DIR"

    # Set up clean local SUI config dir
    rm -rf "$LOCAL_SUI_CONFIG_DIR"
    mkdir -p "$LOCAL_SUI_CONFIG_DIR"
    cp -r "$VALIDATOR_DIR/$SUI_BACKUP_DIR/sui_config/"* "$LOCAL_SUI_CONFIG_DIR"
    # Update keystore path in client.yaml to the current validator's sui.keystore
    yq e ".keystore.File = \"$LOCAL_SUI_CONFIG_DIR/sui.keystore\"" -i "$LOCAL_SUI_CONFIG_DIR/client.yaml"

    # Run validator config-env and become-candidate with isolated config dirs
    SUI_CONFIG_DIR="$LOCAL_SUI_CONFIG_DIR" \
    IKA_CONFIG_DIR="$LOCAL_IKA_CONFIG_DIR" \
    $BINARY_NAME validator config-env \
        --ika-package-id "$IKA_PACKAGE_ID" \
        --ika-system-package-id "$IKA_SYSTEM_PACKAGE_ID" \
        --ika-system-object-id "$IKA_SYSTEM_OBJECT_ID"

    SUI_CONFIG_DIR="$LOCAL_SUI_CONFIG_DIR" \
    IKA_CONFIG_DIR="$LOCAL_IKA_CONFIG_DIR" \
    $BINARY_NAME validator become-candidate "$VALIDATOR_DIR/validator.info" --json > "$OUTPUT_FILE"

    # Validate and extract IDs
    if jq empty "$OUTPUT_FILE" 2>/dev/null; then
        VALIDATOR_ID=$(jq -r '.[1].validator_id' "$OUTPUT_FILE")
        VALIDATOR_CAP_ID=$(jq -r '.[1].validator_cap_id' "$OUTPUT_FILE")
        echo "[✓] Parsed validator_id=$VALIDATOR_ID, validator_cap_id=$VALIDATOR_CAP_ID for $VALIDATOR_NAME"
        echo "$VALIDATOR_NAME:$VALIDATOR_ID:$VALIDATOR_CAP_ID" >> "$TUPLES_FILE"
    else
        echo "[ERROR] Invalid JSON from become-candidate for $VALIDATOR_NAME"
        cat "$OUTPUT_FILE"
    fi
}

# Launch jobs with a max concurrency of 5 using a simple counter
MAX_JOBS=10
JOB_COUNT=0

for entry in "${VALIDATORS_ARRAY[@]}"; do
    process_validator "$entry" &

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

############################
# Join Committee
############################

for tuple in "${VALIDATOR_TUPLES[@]}"; do
    IFS=":" read -r VALIDATOR_NAME VALIDATOR_ID VALIDATOR_CAP_ID <<< "$tuple"

    # Find the validator's hostname based on its name
    for entry in "${VALIDATORS_ARRAY[@]}"; do
        IFS=":" read -r NAME HOSTNAME <<< "$entry"
        if [[ "$NAME" == "$VALIDATOR_NAME" ]]; then
            VALIDATOR_HOSTNAME="$HOSTNAME"
            break
        fi
    done

    # Copy sui_config and run join-committee
    VALIDATOR_DIR="$VALIDATOR_HOSTNAME"
    rm -rf "$SUI_CONFIG_PATH"
    mkdir -p "$SUI_CONFIG_PATH"
    cp -r "$VALIDATOR_DIR/$SUI_BACKUP_DIR/sui_config/"* "$SUI_CONFIG_PATH"

    echo "Joining committee for Validator '$VALIDATOR_NAME' (Cap ID: $VALIDATOR_CAP_ID)"

    $BINARY_NAME validator join-committee \
        --validator-cap-id "$VALIDATOR_CAP_ID"
done

#############################
# IKA System Initialization
#############################

# Copy publisher sui_config to SUI_CONFIG_PATH
rm -rf "$SUI_CONFIG_PATH"
mkdir -p "$SUI_CONFIG_PATH"
cp -r $PUBLISHER_DIR/sui_config/* "$SUI_CONFIG_PATH"

./ika-swarm-config ika-system-initialize --sui-rpc-addr "$SUI_FULLNODE_RPC_URL" --ika-config-path $PUBLISHER_DIR/ika_publish_config.json

# This if the file name that the SDK is looking for.
mv $PUBLISHER_DIR/ika_publish_config.json $PUBLISHER_DIR/ika_config.json

############################
# Generate Seed Peers
############################
echo "Generating seed_peers.yaml..."

SEED_PEERS_FILE="seed_peers.yaml"
: > "$SEED_PEERS_FILE"  # Empty or create file

for entry in "${VALIDATORS_ARRAY[@]}"; do
  IFS=":" read -r VALIDATOR_NAME VALIDATOR_HOSTNAME <<< "$entry"
  VALIDATOR_DIR="${VALIDATOR_HOSTNAME}"

  INFO_FILE="$VALIDATOR_DIR/validator.info"
  ACCOUNT_FILE="$VALIDATOR_DIR/sui_backup/sui_config/${VALIDATOR_DIR}.account.json"

  if [[ -f "$INFO_FILE" && -f "$ACCOUNT_FILE" ]]; then
    P2P_ADDR=$(yq e '.p2p_address' "$INFO_FILE")
    PEER_ID=$(jq -r '.peerId' "$ACCOUNT_FILE")

    echo "- address: $P2P_ADDR" >> "$SEED_PEERS_FILE"
    echo "  peer-id: $PEER_ID" >> "$SEED_PEERS_FILE"
  else
    echo "Missing $INFO_FILE or $ACCOUNT_FILE"
    exit 1
  fi
done

echo "$SEED_PEERS_FILE generated in $SUBDOMAIN/"


################################
# Create the fullnode.yaml file.
################################
echo "Creating fullnode.yaml..."
export FULLNODE_YAML_PATH="$PUBLISHER_DIR/fullnode.yaml"

# Copy the template
cp ../fullnode.template.yaml "$FULLNODE_YAML_PATH"

# Replace upper-case variables with real values using yq
yq e ".\"sui-connector-config\".\"sui-rpc-url\" = \"$SUI_DOCKER_URL\"" -i "$FULLNODE_YAML_PATH"
yq e ".\"sui-connector-config\".\"sui-chain-identifier\" = \"$SUI_CHAIN_IDENTIFIER\"" -i "$FULLNODE_YAML_PATH"
yq e ".\"sui-connector-config\".\"ika-package-id\" = \"$IKA_PACKAGE_ID\"" -i "$FULLNODE_YAML_PATH"
yq e ".\"sui-connector-config\".\"ika-system-package-id\" = \"$IKA_SYSTEM_PACKAGE_ID\"" -i "$FULLNODE_YAML_PATH"
yq e ".\"sui-connector-config\".\"ika-system-object-id\" = \"$IKA_SYSTEM_OBJECT_ID\"" -i "$FULLNODE_YAML_PATH"

# Replace HOSTNAME in external-address
yq e ".\"p2p-config\".\"external-address\" = \"/dns/fullnode.$SUBDOMAIN/udp/8084\"" -i "$FULLNODE_YAML_PATH"

# Replace SEED_PEERS with actual array from seed_peers.yaml
yq e '."p2p-config"."seed-peers" = load("seed_peers.yaml")' -i "$FULLNODE_YAML_PATH"

