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

NEW_IKA_FEE_PER_VALIDATOR="0 0 0 0"

OPERATORS_CAP_IDS="0x39d8a4171b40b8c8531bd2cbb89ee52069e01ee2cccffebfd0775dc35eddc509 0xaa526c5272b6eb77c6f30f1c7485a93b6681818029bfc94dbd35c4cea93a9e1f 0xfa41ce6654a553ee672960edcddbc32de7ccd2b66d5658f9f6bbb360eac7319e 0x3b4cebb120d725a57ac63ed102983f4be77dd8631ce962c0fe014c7df35077c6"

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
