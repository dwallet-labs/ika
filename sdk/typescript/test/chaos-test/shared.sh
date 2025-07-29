#!/bin/bash

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
        --ika-system-object-id "$IKA_SYSTEM_OBJECT_ID" \
        --ika-common-package-id "$IKA_COMMON_PACKAGE_ID" \
        --ika-dwallet-2pc-mpc-package-id "$IKA_DWALLET_2PC_MPC_PACKAGE_ID" \

    SUI_CONFIG_DIR="$LOCAL_SUI_CONFIG_DIR" \
    IKA_CONFIG_DIR="$LOCAL_IKA_CONFIG_DIR" \
    $BINARY_NAME validator become-candidate "$VALIDATOR_DIR/validator.info" --json > "$OUTPUT_FILE"
#    $BINARY_NAME validator become-candidate "$VALIDATOR_DIR/validator.info" --json 2>&1 | tee "$OUTPUT_FILE"

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
