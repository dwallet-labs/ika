# Recommended protocol pricing comparison

Snapshot date: 2026-08-26

This document compares the pricing deployed on both Ika mainnet and testnet with the proposed values in [`recommended_default_pricing.yaml`](./recommended_default_pricing.yaml). Mainnet and testnet had the same pricing at the time of the snapshot. The proposed transaction has not been executed; “before” is therefore also the live pricing until governance executes an update.

## Summary

| Component | Before | Suggested | Change |
|---|---:|---:|---:|
| IKA protocol fee | 0.01–0.25 IKA | 0.5–12.5 IKA | 50×, except standard DKG at 200× |
| Notifier reimbursement, non-presign | 0 SUI | 0 SUI | Unchanged |
| Notifier reimbursement, ECDSA presign | 0 SUI | 0.015 SUI | +0.015 SUI |
| Notifier reimbursement, Schnorr-style presign | 0 SUI | 0.003 SUI | +0.003 SUI |
| System-call reimbursement contribution | 0 SUI | 0.005 SUI | +0.005 SUI |

The two SUI fields cover different costs:

- `gas_fee_reimbursement_sui` reimburses only the notifier's net transaction cost. It does not duplicate gas paid directly by the user.
- `gas_fee_reimbursement_sui_for_system_calls` funds the shared system-call pool used for network-key reconfiguration. It is not notifier gas.

## Mainnet transaction evidence

Net notifier gas is calculated as `computationCost + storageCost - storageRebate`. A negative result means the notifier received more from released storage than it paid for the transaction.

| Transaction | Result writes | Computation | Storage | Rebate | Net transaction gas | Net per result |
|---|---:|---:|---:|---:|---:|---:|
| [Mixed presign batch](https://suiscan.xyz/mainnet/tx/66j96LtCWom8w6Z4h96TUnGmGoStfmRnXrfxPyWetvPd) | 2 presigns: secp256k1 + Curve25519 | 0.001680000 SUI | 0.180021200 SUI | 0.165768768 SUI | 0.015932432 SUI | 0.007966216 SUI average |
| [Isolated secp256k1 presign](https://suiscan.xyz/mainnet/tx/8pEDXbUCCZEP37zbxwuh2CHi5bM892DfUP8TntDAYUUE) | 1 presign | 0.000779000 SUI | 0.113939200 SUI | 0.100242252 SUI | 0.014475948 SUI | 0.014475948 SUI |
| [Isolated Curve25519 presign](https://suiscan.xyz/mainnet/tx/qmodm2YCXSNPhrWdKFLHzJgWYAyhMcQp4n4pNBz7i8k) | 1 presign | 0.000193000 SUI | 0.102136400 SUI | 0.100242252 SUI | 0.002087148 SUI | 0.002087148 SUI |
| [DKG batch](https://suiscan.xyz/mainnet/tx/Gx28pkreCYXeNcUgYco9aVFbgoX8E9U7oBJQkZUyVUUx) | 2 DKGs: secp256k1 + Curve25519 | 0.000319000 SUI | 0.164524800 SUI | 0.192840120 SUI | **−0.027996320 SUI** | **−0.013998160 SUI average** |
| [Isolated Curve25519 sign](https://suiscan.xyz/mainnet/tx/9EGT6s1fGn8g6TTuVzYEFc6BpMA4KVJTv6svy5Jw6ZGr) | 1 sign | 0.000102000 SUI | 0.093670000 SUI | 0.116057700 SUI | **−0.022285700 SUI** | **−0.022285700 SUI** |

The mixed presign transaction cannot be divided equally by curve: its 0.007966216 SUI figure is only an average. The isolated transactions show that the secp256k1 presign accounts for most of the cost. Charging 0.015 SUI for an ECDSA presign and 0.003 SUI for a smaller Schnorr-style presign covers both isolated transactions. A batch containing one of each would collect 0.018 SUI against the observed 0.015932432 SUI net cost.

Only secp256k1/ECDSA and Curve25519/EdDSA presigns were observed in the queried mainnet and testnet history. The secp256r1 value is inferred from the ECDSA family; Taproot and Ristretto values are inferred from the smaller Schnorr-style family. DKG and sign have direct net-negative evidence. The other non-presign operations are set to zero on the assumption that closing their session releases enough storage to cover the notifier, but they should be checked against production transactions when examples exist.

## USD snapshot

The USD estimates use **1 IKA = $0.002199** and **1 SUI = $0.7605**, from [CoinGecko’s IKA page](https://www.coingecko.com/en/coins/ika) and [CoinGecko’s SUI page](https://www.coingecko.com/en/coins/sui).

- 0.005 SUI system-call contribution = $0.003803.
- 0.003 SUI small-presign notifier reimbursement = $0.002282.
- 0.015 SUI ECDSA-presign notifier reimbursement = $0.011408.
- The suggested configured charge ranges from about $0.004902 to $0.042698 per request at this price snapshot.

USD totals below include the configured IKA fee, the applicable notifier reimbursement, and the system-call contribution. They exclude SUI gas paid separately by the end user.

## Full comparison

`—` in the signature column means the protocol is priced at curve level and has no signature-algorithm key.

| Curve | Signature | Protocol | Before IKA | Suggested IKA | Before SUI (notifier + system) | Suggested SUI (notifier + system) | Before USD | Suggested USD |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 0 secp256k1 | — | 2 Re-encrypt | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 0 secp256k1 | — | 3 Make share public | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 0 secp256k1 | — | 4 Imported-key verification | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 0 secp256k1 | — | 9 dWallet DKG | 0.02 | 4 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.012599 |
| 0 secp256k1 | 0 ECDSA | 5 Presign | 0.25 | 12.5 | 0 + 0 | 0.015 + 0.005 | $0.000550 | $0.042698 |
| 0 secp256k1 | 0 ECDSA | 6 Sign | 0.1 | 5 | 0 + 0 | 0.000 + 0.005 | $0.000220 | $0.014798 |
| 0 secp256k1 | 0 ECDSA | 7 Future sign | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 0 secp256k1 | 0 ECDSA | 8 Sign with partial user signature | 0.1 | 5 | 0 + 0 | 0.000 + 0.005 | $0.000220 | $0.014798 |
| 0 secp256k1 | 0 ECDSA | 10 dWallet DKG with sign | 0.11 | 5.5 | 0 + 0 | 0.000 + 0.005 | $0.000242 | $0.015897 |
| 0 secp256k1 | 1 Taproot | 5 Presign | 0.12 | 6 | 0 + 0 | 0.003 + 0.005 | $0.000264 | $0.019278 |
| 0 secp256k1 | 1 Taproot | 6 Sign | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 0 secp256k1 | 1 Taproot | 7 Future sign | 0.01 | 0.5 | 0 + 0 | 0.000 + 0.005 | $0.000022 | $0.004902 |
| 0 secp256k1 | 1 Taproot | 8 Sign with partial user signature | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 0 secp256k1 | 1 Taproot | 10 dWallet DKG with sign | 0.06 | 3 | 0 + 0 | 0.000 + 0.005 | $0.000132 | $0.010400 |
| 1 secp256r1 | — | 2 Re-encrypt | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 1 secp256r1 | — | 3 Make share public | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 1 secp256r1 | — | 4 Imported-key verification | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 1 secp256r1 | — | 9 dWallet DKG | 0.02 | 4 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.012599 |
| 1 secp256r1 | 0 ECDSA | 5 Presign | 0.12 | 12.5 | 0 + 0 | 0.015 + 0.005 | $0.000264 | $0.042698 |
| 1 secp256r1 | 0 ECDSA | 6 Sign | 0.04 | 5 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.014798 |
| 1 secp256r1 | 0 ECDSA | 7 Future sign | 0.01 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000022 | $0.008201 |
| 1 secp256r1 | 0 ECDSA | 8 Sign with partial user signature | 0.04 | 5 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.014798 |
| 1 secp256r1 | 0 ECDSA | 10 dWallet DKG with sign | 0.06 | 5.5 | 0 + 0 | 0.000 + 0.005 | $0.000132 | $0.015897 |
| 2 Curve25519 | — | 2 Re-encrypt | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 2 Curve25519 | — | 3 Make share public | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 2 Curve25519 | — | 4 Imported-key verification | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 2 Curve25519 | — | 9 dWallet DKG | 0.02 | 4 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.012599 |
| 2 Curve25519 | 0 EdDSA | 5 Presign | 0.12 | 6 | 0 + 0 | 0.003 + 0.005 | $0.000264 | $0.019278 |
| 2 Curve25519 | 0 EdDSA | 6 Sign | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 2 Curve25519 | 0 EdDSA | 7 Future sign | 0.01 | 0.5 | 0 + 0 | 0.000 + 0.005 | $0.000022 | $0.004902 |
| 2 Curve25519 | 0 EdDSA | 8 Sign with partial user signature | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 2 Curve25519 | 0 EdDSA | 10 dWallet DKG with sign | 0.06 | 3 | 0 + 0 | 0.000 + 0.005 | $0.000132 | $0.010400 |
| 3 Ristretto | — | 2 Re-encrypt | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 3 Ristretto | — | 3 Make share public | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 3 Ristretto | — | 4 Imported-key verification | 0.02 | 1 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.006002 |
| 3 Ristretto | — | 9 dWallet DKG | 0.02 | 4 | 0 + 0 | 0.000 + 0.005 | $0.000044 | $0.012599 |
| 3 Ristretto | 0 Schnorrkel | 5 Presign | 0.12 | 6 | 0 + 0 | 0.003 + 0.005 | $0.000264 | $0.019278 |
| 3 Ristretto | 0 Schnorrkel | 6 Sign | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 3 Ristretto | 0 Schnorrkel | 7 Future sign | 0.01 | 0.5 | 0 + 0 | 0.000 + 0.005 | $0.000022 | $0.004902 |
| 3 Ristretto | 0 Schnorrkel | 8 Sign with partial user signature | 0.04 | 2 | 0 + 0 | 0.000 + 0.005 | $0.000088 | $0.008201 |
| 3 Ristretto | 0 Schnorrkel | 10 dWallet DKG with sign | 0.06 | 3 | 0 + 0 | 0.000 + 0.005 | $0.000132 | $0.010400 |

## Base-unit values used by the CLI

- `fee_ika` is in INKU: 1 IKA = 1,000,000,000 INKU.
- Both SUI reimbursement fields are in MIST: 1 SUI = 1,000,000,000 MIST.
- Non-presign notifier reimbursement: `0` MIST.
- ECDSA-presign notifier reimbursement: `15_000_000` MIST.
- Schnorr-style-presign notifier reimbursement: `3_000_000` MIST.
- System-call reimbursement contribution: `5_000_000` MIST.

The exact CLI-ready values are in [`recommended_default_pricing.yaml`](./recommended_default_pricing.yaml). The supported curve/signature/hash map is unchanged and is kept separately in [`recommended_supported_curves_to_signature_algorithms_to_hash_schemes.yaml`](./recommended_supported_curves_to_signature_algorithms_to_hash_schemes.yaml).
