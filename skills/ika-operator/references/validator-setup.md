# Mainnet Validator Setup

Complete step-by-step guide for setting up an Ika mainnet validator with permissionless stake.

## Overview

All validator operations (registration, node management) are coordinated on Sui. You register as a validator candidate via Sui smart contracts, stake IKA, join the committee, then run your node.

## Prerequisites Checklist

- [ ] DNS address configured (recommended: `ika-mainnet-1.<your-domain>`)
- [ ] Own Sui fullnode on Sui mainnet, fully synced (2+ latest epochs)
  - Recommended: Restore from DB snapshot
  - Use separate DNS for Sui node (validator subdomain must point to Ika node, not Sui node)
- [ ] Sui CLI installed, configured for mainnet
- [ ] Active Sui address with at least 10 SUI (for registration transactions)
- [ ] Server meets hardware requirements
- [ ] Ports 8080-8084 and 9184 open
- [ ] Basic git knowledge
- [ ] Download latest binaries from https://github.com/dwallet-labs/ika/releases

## Hardware Requirements

| Resource | Minimum |
|---|---|
| CPU | 16 physical cores / 16 vCPUs (node won't run with fewer) |
| Memory | 128 GB |
| Storage | 4 TB NVMe |
| Network | 1 Gbps |
| OS | Linux Ubuntu/Debian x64, or Docker on x64 Linux |

**Warning**: Hetzner has strict crypto ToS - may close validators without notice.

## Required Ports

| Protocol/Port | Direction | Purpose |
|---|---|---|
| TCP/8080 | Inbound | Protocol / Transaction Interface |
| UDP/8081 | Inbound/Outbound | Consensus Interface |
| UDP/8084 | Inbound/Outbound | Peer-to-Peer State Sync |
| TCP/8443 | Outbound | Metrics Pushing |
| TCP/9184 | Inbound/Outbound | Metrics Scraping |

**All ports 8080-8084 and 9184 must be open with correct protocols (TCP/UDP).**

---

## Step 1: Configure Ika Environment

Generate the Ika Sui config file locally. Get the latest IDs from:
- **Mainnet**: `deployed_contracts/mainnet/address.yaml` ([GitHub](https://github.com/dwallet-labs/ika/blob/main/deployed_contracts/mainnet/address.yaml))
- **Testnet**: `deployed_contracts/testnet/address.yaml` ([GitHub](https://github.com/dwallet-labs/ika/blob/main/deployed_contracts/testnet/address.yaml))

```bash
./ika validator config-env \
  --ika-package-id                    <ika_package_id> \
  --ika-common-package-id             <ika_common_package_id> \
  --ika-dwallet-2pc-mpc-package-id    <ika_dwallet_2pc_mpc_package_id> \
  --ika-system-package-id             <ika_system_package_id> \
  --ika-system-object-id              <ika_system_object_id>
```

**Output**: Creates `~/.ika/ika_config/ika_sui_config.yaml`

**Note**: `ika-dwallet-coordinator-object-id` is not set at this stage (defaults to zero). It must be configured later in the node's `validator.yaml` under `sui-connector-config`.

Verify:

```bash
cat ~/.ika/ika_config/ika_sui_config.yaml
```

---

## Step 2: Generate Validator Info & Keys

```bash
./ika validator make-validator-info \
  "<NAME>" \
  "<DESCRIPTION>" \
  "<IMAGE_URL>" \
  "<PROJECT_URL>" \
  "<HOST_NAME>" \
  <GAS_PRICE> \
  <SENDER_SUI_ADDRESS>
```

**Arguments**:
- `NAME`: Validator display name
- `DESCRIPTION`: Validator description
- `IMAGE_URL`: URL to validator logo/image
- `PROJECT_URL`: Validator project website
- `HOST_NAME`: DNS hostname for the validator node (e.g., `ika-mainnet-1.example.com`)
- `GAS_PRICE`: Gas price in MIST
- `SENDER_SUI_ADDRESS`: Your active Sui mainnet address (from `~/.sui/sui_config/client.yaml`)

**Options**: `--json` for JSON output

**Example**:

```bash
./ika validator make-validator-info \
  "My Validator" "Secure and fast" \
  "https://example.com/image.png" "https://example.com" \
  "ika-mainnet-1.example.com" \
  10000 \
  0x5cf353484d7f512d44feae616910972659c9e10af431323f911e612a5ce6eec7
```

**Output files**:
- `protocol.key` - Protocol signing key
- `network.key` - P2P network key
- `consensus.key` - Consensus key
- `root-seed.key` - MPC root seed key
- `validator.info` - Validator metadata file

**Note**: The error `FailedToReadCGKey` during generation is expected - it indicates the root seed file doesn't exist yet and is being generated.

**Note**: Root seed key creation takes some time. The command is not stuck.

### Key Management Warnings

**CRITICAL - Back up ALL keys immediately**:

- `root-seed.key` is **SECRET** and **IRREPLACEABLE**
  - No way to recover if lost
  - Cannot be updated via contract
  - Validator must run with this exact seed (different seed = won't start)
  - Requires network coordination if lost

- `protocol.key`, `network.key`, `consensus.key`:
  - Can be rotated on-chain if lost
  - Ika contract includes functionality to update these keys
  - CLI commands available for key rotation

**Store keys in secure, offline storage. Treat with same caution as funds.**

---

## Step 3: Become a Validator Candidate

Register as a candidate using the generated `validator.info`:

```bash
./ika validator become-candidate <validator-info-path>
```

**Options**:
- `--gas-budget <gas-budget>` - Override gas budget
- `--ika-sui-config <path>` - Path to ika_sui_config.yaml (default: `~/.ika/ika_config/ika_sui_config.yaml`)
- `--json` - JSON output

**Example**:

```bash
./ika validator become-candidate ./validator.info
```

**Output**:

```
----- Transaction Digest ----
Gu6TeZ9dP72EDTukj1op8qfLFaE2aXyoiLiAexY8S2ke
Validator ID: 0x8704eed3bb82c73b41ee6d63fc0f92db3419d9d0b1f8cb773723311a5a943e37
Validator Cap ID: 0x5d558d7fd928f9bacc7adac83c4c5eabf7947a017ea22797170d9a7378f2e35c
Validator Operation Cap ID: 0x...
Validator Commission Cap ID: 0x...
```

**Save all four IDs** - Validator Cap ID is needed for Step 5. Operation Cap and Commission Cap are used for validator management operations (key rotation, commission changes, etc.).

The cap objects are transferred to the executing account.

---

## Step 4: Stake into Validator

**Minimum stake: 40 million IKA** (below this, cannot join committee).

Staking portal: https://ika-mainnet-validators-staking.pages.dev/

1. Connect your wallet
2. Find your validator
3. **Verify Validator ID matches** the CLI output from Step 3
4. Stake at least 40M IKA

For custody solutions (e.g., Fortuna): they have their own instructions for the staking website.

---

## Step 5: Join Committee

Once staked with sufficient IKA:

```bash
./ika validator join-committee --validator-cap-id <VALIDATOR_CAP_ID>
```

**Options**:
- `--gas-budget <gas-budget>`
- `--ika-sui-config <path>`
- `--json`

**Example**:

```bash
./ika validator join-committee \
  --validator-cap-id 0x5d558d7fd928f9bacc7adac83c4c5eabf7947a017ea22797170d9a7378f2e35c
```

**Result**: You become a **pending validator**. You join the committee starting from the **next epoch**. Meanwhile, start your node to synchronize.

---

## Step 6: Run the Validator Node

### Directory Layout

```
/opt/ika/
├── bin/
│   └── ika-node
├── config/
│   └── validator.yaml
├── key-pairs/
│   ├── protocol.key
│   ├── network.key
│   ├── consensus.key
│   └── root-seed.key
└── db/                     # Created at runtime
    ├── authorities_db/
    └── consensus_db/
```

### Pre-Run Config Edits

Edit `validator.yaml` before starting:

1. **Set all package/object IDs** from `deployed_contracts/mainnet/address.yaml`

2. **Ensure mainnet chain identifier**:
   ```yaml
   sui-chain-identifier: mainnet
   ```

3. **Set metrics push URL**:
   ```yaml
   push-url: "https://mainnet.metrics.ika-network.net:8443/publish/metrics"
   ```

### Start

```bash
ika-node --config-path /opt/ika/config/validator.yaml
```

**Logging**:
- `RUST_LOG` env var controls log levels
- `RUST_LOG_JSON=1` for JSON-formatted logs

---

## Step 7: Verify Operation

Wait a couple of minutes, then check logs for:

```
ika_core::checkpoints: Creating checkpoint(s) for 0 messages next_checkpoint_seq=1
```

Also look for consensus output lines:

```
ika_core::consensus_handler: Received consensus output consensus_commit=CommittedSubDag(...)
```

This confirms your node is running correctly. Additional checkpoints appear only during or after MPC sessions.

---

## Step 8: Ongoing Operations

- **Monitor** `#nodes-updates-mainnet` channel for new releases
- **Update regularly** - download new binaries from GitHub releases
- **Monitor metrics** at `http://localhost:9184/metrics`
- **Admin API** at `http://localhost:1337/` (see SKILL.md for endpoints)

---

## CLI Command Reference

```bash
# Step 1: Configure environment
./ika validator config-env \
  --ika-package-id <ID> \
  --ika-common-package-id <ID> \
  --ika-dwallet-2pc-mpc-package-id <ID> \
  --ika-system-package-id <ID> \
  --ika-system-object-id <ID>

# Step 2: Generate validator info
./ika validator make-validator-info [OPTIONS] <NAME> <DESCRIPTION> <IMAGE_URL> <PROJECT_URL> <HOST_NAME> <GAS_PRICE> <SENDER_SUI_ADDRESS>

# Step 3: Register as candidate
./ika validator become-candidate [OPTIONS] <validator-info-path>

# Step 5: Join committee
./ika validator join-committee [OPTIONS] --validator-cap-id <validator-cap-id>
```

All commands support `--json` for JSON output and `--help` for usage info.

---

## Package & Object IDs

Always get the latest IDs from the canonical source files:

- **Mainnet**: `deployed_contracts/mainnet/address.yaml` ([GitHub](https://github.com/dwallet-labs/ika/blob/main/deployed_contracts/mainnet/address.yaml))
- **Testnet**: `deployed_contracts/testnet/address.yaml` ([GitHub](https://github.com/dwallet-labs/ika/blob/main/deployed_contracts/testnet/address.yaml))
