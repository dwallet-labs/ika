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

OPERATORS_CAP_IDS="0x2aa779a22b358946e6d39cedcd91c12f6d5875ac2b3b6e9e72f34b1ccfb73bcc \
0xc07237cee68ea44a3d415c9643310a4d975157b1ee893aeb02b38149c6d4fd4e \
0x08c3ca6aa5dad3fe3317892c2dbe4cc40d8835ad05d4318f18bc30caeca323b1 \
0x6b82a5a60779a47bb046859540d45ed4eb802d1347be43c5b8795f0c76de66ec"

yq -P -o yaml ./ika_config.json > /Users/itaylevy/.ika/ika_config/ika_sui_config.yaml
./target/debug/ika validator get-current-pricing-info
yq -i '(.[] | select(.value.fee_ika) | .value.fee_ika) = 100' current_pricing.yaml
grep "account_key_pair: A" ~/.ika/ika_config/network.yaml | awk '{print $2}' | while read key; do
  parsed_secret=$(sui keytool convert "$key" --json | jq -r '.bech32WithFlag')
  sui keytool import "$parsed_secret" ed25519
done


paste <(echo "$OPERATORS_CAP_IDS" | tr ' ' '\n') <(echo "$NEW_IKA_FEE_PER_VALIDATOR" | tr ' ' '\n') | while read object_id fee; do
  yq -i "(.[] | select(.value.fee_ika) | .value.fee_ika) = $fee" current_pricing.yaml
  owner_address=$(sui client object "$object_id" | grep 'AddressOwner' | sed -n 's/.*│ *\(0x[a-f0-9]\{64\}\) *│.*/\1/p')
  sui client switch --address "$owner_address"
  ./target/debug/ika validator set-pricing-vote --validator-operation-cap-id "$object_id"  --new-pricing-file-path ./current_pricing.yaml
done
