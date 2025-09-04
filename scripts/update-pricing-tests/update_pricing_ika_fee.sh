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

NEW_IKA_FEE_PER_VALIDATOR="100 200 300 400"

OPERATORS_CAP_IDS="0xc7c57a13f0be2c06cbf27079013e60ce53f6d3175e571bb145e3894481ac8ccb 0x29dac18df402828cee3a57286ca312987c6f38bedff9ef58c190c4fd733e7ad7 0x7ced8211f735854a484fd62c4d2a19238ee9f697dd7f80c3d0d6ce6b3b6580ef 0x3774dfc4a84a89b53bd8acfad08cfd3b4b46eaca728d47c2488d9a24973f85a8"

yq -P -o yaml ./ika_config.json > /Users/itaylevy/.ika/ika_config/ika_sui_config.yaml
./target/debug/ika validator get-current-pricing-info
grep "account_key_pair: A" ~/.ika/ika_config/network.yaml | awk '{print $2}' | while read key; do
  parsed_secret=$(sui keytool convert "$key" --json | jq -r '.bech32WithFlag')
  sui keytool import "$parsed_secret" ed25519
done

paste <(echo "$OPERATORS_CAP_IDS" | tr ' ' '\n') <(echo "$NEW_IKA_FEE_PER_VALIDATOR" | tr ' ' '\n') | while read object_id fee; do
  echo "fee: $fee"
  yq -i "(.[] | select(.value.fee_ika) | .value.fee_ika) = $fee" current_pricing.yaml
  owner_address=$(sui client object "$object_id" | grep 'AddressOwner' | sed -n 's/.*│ *\(0x[a-f0-9]\{64\}\) *│.*/\1/p')
  sui client switch --address "$owner_address"
  ./target/debug/ika validator set-pricing-vote --validator-operation-cap-id "$object_id"  --new-pricing-file-path ./current_pricing.yaml
done
