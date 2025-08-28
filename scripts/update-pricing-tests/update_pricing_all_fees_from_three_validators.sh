#!/bin/bash

# This script allows running a pricing update experiment for Ika using Swarm.
# You set the new Ika fee per validator in the NEW_IKA_FEE_PER_VALIDATOR variable.

# Then, run the "should fetch all the validator operator cap ids from Sui" TS test, and update the OPERATORS_CAP_IDS
# with it.

# Then, when running this script, it will send a pricing vote from each operator to its ika fee,
# i.e. using the below value, from validator 1 it will send a vote to set the ika fee to 100,
# from validator 2 it will send a vote to set the ika fee to 200, etc.

# After sending the vote, wait for an epoch switch for the votes to take effect.

# Then query the new current price with `./target/debug/ika validator get-current-pricing-info` & verify the
# new ika fee has been updated correctly.

NEW_IKA_FEE_PER_VALIDATOR="100 100 100"

OPERATORS_CAP_IDS="0x5be562316735e388da26a102f73cbceb45dfb8d6099e28ef930d896729575f49 \
0x4eb389561653b11265c504eec739b66732c0189595d685393db542b60753f1a3 \
0x5f05ea3505d8ee724c41c90afabb030031219634d5d30a1f56cdd3afbb92e6bd"

yq -P -o yaml ./ika_config.json > /Users/itaylevy/.ika/ika_config/ika_sui_config.yaml
./target/debug/ika validator get-current-pricing-info
grep "account_key_pair: A" ~/.ika/ika_config/network.yaml | awk '{print $2}' | while read key; do
  parsed_secret=$(sui keytool convert "$key" --json | jq -r '.bech32WithFlag')
  sui keytool import "$parsed_secret" ed25519
done

paste <(echo "$OPERATORS_CAP_IDS" | tr ' ' '\n') <(echo "$NEW_IKA_FEE_PER_VALIDATOR" | tr ' ' '\n') | while read object_id fee; do
  echo "fee: $fee"
  yq -i "(.[] | select(.value.fee_ika) | .value.fee_ika) = $fee" current_pricing.yaml
  yq -i "(.[] | select(.value.gas_fee_reimbursement_sui_for_system_calls) | .value.gas_fee_reimbursement_sui_for_system_calls) = $fee" current_pricing.yaml
  yq -i "(.[] | select(.value.gas_fee_reimbursement_sui) | .value.gas_fee_reimbursement_sui) = $fee" current_pricing.yaml
  owner_address=$(sui client object "$object_id" | grep 'AddressOwner' | sed -n 's/.*│ *\(0x[a-f0-9]\{64\}\) *│.*/\1/p')
  sui client switch --address "$owner_address"
  ./target/debug/ika validator set-pricing-vote --validator-operation-cap-id "$object_id"  --new-pricing-file-path ./current_pricing.yaml
done
