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
