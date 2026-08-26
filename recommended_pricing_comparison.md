# Recommended protocol pricing comparison

Snapshot date: 2026-08-26

This document compares the pricing deployed on both Ika mainnet and testnet with the proposed values in [`recommended_default_pricing.yaml`](./recommended_default_pricing.yaml). Mainnet and testnet had the same pricing at the time of the snapshot. The proposed transaction has not been executed; “before” is therefore also the live pricing until governance executes an update.

## Summary

| Component | Before | Suggested | Change |
|---|---:|---:|---:|
| IKA protocol fee | 0.01–0.25 IKA | 1–25 IKA | 100× |
| Notifier gas reimbursement | 0 SUI | 0.03 SUI | +0.03 SUI |
| System-call reimbursement | 0 SUI | 0.02 SUI | +0.02 SUI |
| Total SUI reimbursement funded per priced request | 0 SUI | 0.05 SUI | +0.05 SUI |

The two SUI fields cover different costs:

- `gas_fee_reimbursement_sui` reimburses the notifier-paid transaction. It should not duplicate gas paid directly by the user.
- `gas_fee_reimbursement_sui_for_system_calls` funds the shared system-call pool used for network-key reconfiguration.

The USD estimates use a dated market snapshot of **1 IKA = $0.002199** and **1 SUI = $0.7605**, from [CoinGecko’s IKA page](https://www.coingecko.com/en/coins/ika) and [CoinGecko’s SUI page](https://www.coingecko.com/en/coins/sui). At those prices:

- 0.03 SUI notifier reimbursement = $0.022815.
- 0.02 SUI system-call reimbursement = $0.015210.
- Combined SUI reimbursement = $0.038025.
- The suggested configured charge ranges from about $0.040224 to $0.093000 per priced request.

USD totals below include the configured IKA fee and both configured SUI reimbursements. They exclude any SUI gas paid separately by the end user.

## Full comparison

`—` in the signature column means the protocol is priced at curve level and has no signature-algorithm key.

| Curve | Signature | Protocol | Before IKA | Suggested IKA | Before SUI (notifier + system) | Suggested SUI (notifier + system) | Before USD | Suggested USD |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 0 secp256k1 | — | 2 Re-encrypt | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 0 secp256k1 | — | 3 Make share public | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 0 secp256k1 | — | 4 Imported-key verification | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 0 secp256k1 | — | 9 dWallet DKG | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 0 secp256k1 | 0 ECDSA | 5 Presign | 0.25 | 25 | 0 + 0 | 0.03 + 0.02 | $0.000550 | $0.093000 |
| 0 secp256k1 | 0 ECDSA | 6 Sign | 0.1 | 10 | 0 + 0 | 0.03 + 0.02 | $0.000220 | $0.060015 |
| 0 secp256k1 | 0 ECDSA | 7 Future sign | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 0 secp256k1 | 0 ECDSA | 8 Sign with partial user signature | 0.1 | 10 | 0 + 0 | 0.03 + 0.02 | $0.000220 | $0.060015 |
| 0 secp256k1 | 0 ECDSA | 10 dWallet DKG with sign | 0.11 | 11 | 0 + 0 | 0.03 + 0.02 | $0.000242 | $0.062214 |
| 0 secp256k1 | 1 Taproot | 5 Presign | 0.12 | 12 | 0 + 0 | 0.03 + 0.02 | $0.000264 | $0.064413 |
| 0 secp256k1 | 1 Taproot | 6 Sign | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 0 secp256k1 | 1 Taproot | 7 Future sign | 0.01 | 1 | 0 + 0 | 0.03 + 0.02 | $0.000022 | $0.040224 |
| 0 secp256k1 | 1 Taproot | 8 Sign with partial user signature | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 0 secp256k1 | 1 Taproot | 10 dWallet DKG with sign | 0.06 | 6 | 0 + 0 | 0.03 + 0.02 | $0.000132 | $0.051219 |
| 1 secp256r1 | — | 2 Re-encrypt | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 1 secp256r1 | — | 3 Make share public | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 1 secp256r1 | — | 4 Imported-key verification | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 1 secp256r1 | — | 9 dWallet DKG | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 1 secp256r1 | 0 ECDSA | 5 Presign | 0.12 | 12 | 0 + 0 | 0.03 + 0.02 | $0.000264 | $0.064413 |
| 1 secp256r1 | 0 ECDSA | 6 Sign | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 1 secp256r1 | 0 ECDSA | 7 Future sign | 0.01 | 1 | 0 + 0 | 0.03 + 0.02 | $0.000022 | $0.040224 |
| 1 secp256r1 | 0 ECDSA | 8 Sign with partial user signature | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 1 secp256r1 | 0 ECDSA | 10 dWallet DKG with sign | 0.06 | 6 | 0 + 0 | 0.03 + 0.02 | $0.000132 | $0.051219 |
| 2 Curve25519 | — | 2 Re-encrypt | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 2 Curve25519 | — | 3 Make share public | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 2 Curve25519 | — | 4 Imported-key verification | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 2 Curve25519 | — | 9 dWallet DKG | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 2 Curve25519 | 0 EdDSA | 5 Presign | 0.12 | 12 | 0 + 0 | 0.03 + 0.02 | $0.000264 | $0.064413 |
| 2 Curve25519 | 0 EdDSA | 6 Sign | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 2 Curve25519 | 0 EdDSA | 7 Future sign | 0.01 | 1 | 0 + 0 | 0.03 + 0.02 | $0.000022 | $0.040224 |
| 2 Curve25519 | 0 EdDSA | 8 Sign with partial user signature | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 2 Curve25519 | 0 EdDSA | 10 dWallet DKG with sign | 0.06 | 6 | 0 + 0 | 0.03 + 0.02 | $0.000132 | $0.051219 |
| 3 Ristretto | — | 2 Re-encrypt | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 3 Ristretto | — | 3 Make share public | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 3 Ristretto | — | 4 Imported-key verification | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 3 Ristretto | — | 9 dWallet DKG | 0.02 | 2 | 0 + 0 | 0.03 + 0.02 | $0.000044 | $0.042423 |
| 3 Ristretto | 0 Schnorrkel | 5 Presign | 0.12 | 12 | 0 + 0 | 0.03 + 0.02 | $0.000264 | $0.064413 |
| 3 Ristretto | 0 Schnorrkel | 6 Sign | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 3 Ristretto | 0 Schnorrkel | 7 Future sign | 0.01 | 1 | 0 + 0 | 0.03 + 0.02 | $0.000022 | $0.040224 |
| 3 Ristretto | 0 Schnorrkel | 8 Sign with partial user signature | 0.04 | 4 | 0 + 0 | 0.03 + 0.02 | $0.000088 | $0.046821 |
| 3 Ristretto | 0 Schnorrkel | 10 dWallet DKG with sign | 0.06 | 6 | 0 + 0 | 0.03 + 0.02 | $0.000132 | $0.051219 |

## Base-unit values used by the CLI

- `fee_ika` is in INKU: 1 IKA = 1,000,000,000 INKU.
- Both SUI reimbursement fields are in MIST: 1 SUI = 1,000,000,000 MIST.
- Suggested notifier reimbursement: `30_000_000` MIST.
- Suggested system-call reimbursement: `20_000_000` MIST.

The exact CLI-ready values are in [`recommended_default_pricing.yaml`](./recommended_default_pricing.yaml). The supported curve/signature/hash map is unchanged and is kept separately in [`recommended_supported_curves_to_signature_algorithms_to_hash_schemes.yaml`](./recommended_supported_curves_to_signature_algorithms_to_hash_schemes.yaml).
