# IKA Devnet Creation Guide

This guide explains how to create a complete Ika devnet from genesis configuration to running infrastructure.

## Overview

The devnet creation process involves:

1. **Genesis Setup**: Create validator configurations, keys, and blockchain initialization
2. **Infrastructure Configuration**: Set up Terraform configuration for cloud deployment
3. **Secret Deployment**: Deploy keys and configuration to cloud infrastructure

## Prerequisites

- **macOS** with Homebrew (for the genesis script)
- **Rust toolchain** installed
- **Google Cloud CLI** configured with appropriate permissions
- **Terraform** installed and configured
- **jq** and **yq** tools (automatically installed by the script)

---

## Step 1: Configure Genesis Parameters

Edit the configuration variables in `create-ika-genesis-mac.sh`:

### 1.1 Number of Validators

```bash
# The number of validators to create.
export VALIDATOR_NUM=4
```

Set this to your desired number of validators (typically 4 for devnet).

### 1.2 Subdomain Configuration

```bash
# The subdomain for Ika the network.
export SUBDOMAIN="beta.devnet.ika-network.net"
```

Choose your devnet subdomain. This will be used for:

- Validator hostnames: `val1.beta.devnet.ika-network.net`, `val2.beta.devnet.ika-network.net`, etc.
- Network identification and DNS routing

### 1.3 SUI RPC Configuration

Choose between internal SUI network or cloud-based SUI:

**Option A: Internal/Local SUI Network**

```bash
export SUI_FULLNODE_RPC_URL="http://localhost:9000"
export SUI_DOCKER_URL="http://docker.for.mac.localhost:9000"
export SUI_FAUCET_URL="http://localhost:9123/gas"
```

**Option B: Cloud-based SUI Network (Recommended)**

```bash
export SUI_FULLNODE_RPC_URL="https://fullnode.sui.beta.devnet.ika-network.net"
export SUI_DOCKER_URL="https://fullnode.sui.beta.devnet.ika-network.net"
export SUI_FAUCET_URL="https://faucet.sui.beta.devnet.ika-network.net/gas"
```

---

## Step 2: Run Genesis Script

Execute the genesis creation script:

```bash
./create-ika-genesis-mac.sh
```

### What the Script Does

The script performs the following operations:

1. **Builds Ika Binaries**: Compiles `ika` and `ika-swarm-config` binaries
2. **Creates Validator Directories**: Generates folder structure for each validator
3. **Generates Cryptographic Keys**: Creates validator keys (consensus, network, protocol, root-seed)
4. **SUI Integration**:
    - Creates SUI accounts for each validator
    - Publishes Ika smart contracts to SUI
    - Mints Ika tokens
    - Initializes the Ika system
5. **Validator Registration**:
    - Makes each validator a candidate
    - Stakes tokens to validators
    - Joins validators to the committee
6. **Configuration Generation**: Creates all necessary config files

### Generated Structure

After running the script, you'll have a directory structure like `beta.devnet.ika-network.net/`:

```
beta.devnet.ika-network.net/
├── docker-compose.yaml          # Docker orchestration for all services
├── seed_peers.yaml             # P2P network seed peer configuration
├── locals.tf                   # Terraform variables for chain config
├── publisher/                  # Fullnode and system configuration
│   ├── ika_config.json        # Main Ika system configuration
│   ├── fullnode.yaml          # Fullnode configuration
│   └── sui_config/            # SUI blockchain connection config
├── val1.beta.devnet.ika-network.net/   # Validator 1 configuration
│   ├── validator.yaml         # Validator runtime configuration
│   ├── validator.info         # Validator metadata
│   ├── key-pairs/            # Cryptographic keys
│   │   ├── consensus.key     # Consensus protocol key
│   │   ├── network.key       # P2P networking key
│   │   ├── protocol.key      # Protocol signing key
│   │   └── root-seed.key     # Master seed key
│   └── sui_backup/           # SUI account backup
├── val2.beta.devnet.ika-network.net/   # Validator 2 configuration
├── val3.beta.devnet.ika-network.net/   # Validator 3 configuration
└── val4.beta.devnet.ika-network.net/   # Validator 4 configuration
```

---

## Step 3: Configure Terraform Infrastructure

### 3.1 Update Terraform Workspace

Configure your Terraform workspace to match the number of validators:

1. Edit the Terraform workspace file (`infra/tf-gcp/workspace.devnet.tf`)
2. Ensure the validator count matches your `VALIDATOR_NUM` setting
3. Configure the appropriate network name in Terraform

### 3.2 Apply Terraform Configuration

Deploy the infrastructure:

```bash
# Navigate to your Terraform directory
cd ../../../infra/tf-gcp
```

In the file `workspace.devnet.tf`, ensure the validator count matches your setup.
Ensure that `deploy_ika` is `false` (FALSE NOT TRUE).

Example:

```hcl 
chains = {
  new-devnet = {
    # Should I deploy Sui to K8s?
    deploy_sui = true
    # Should I deploy Ika to K8s?
    deploy_ika = false
  }
}
```

```bash
# Select the devnet workspace
terraform workspace select devnet

# Plan the deployment
terraform plan

# Apply the infrastructure changes
terraform apply
```

This parts creates all the necessary GCP resources (VMs, networking, IAM roles, etc.) for your devnet.
But it will not create the Kubernetes resources yet.

---

## Step 4: Deploy Secrets, Update Configuration & Deploy to k8s

Execute the deployment script:

```bash
./deploy-secrets-and-update-terraform.sh
```

Now you can update terraform to deploy Ika to k8s:

set deploy_ika to true in workspace.devnet.tf

```hcl
chains = {
  new-devnet = {
    # Should I deploy Sui to K8s?  
    deploy_sui = true
    # Should I deploy Ika to K8s?
    deploy_ika = true
  }
}
```

```bash
terraform apply
```

### What This Script Does

The script performs three main functions:

#### 4.1 Deploy Validator Keys to GCP Secrets

- **Uploads cryptographic keys** for each validator to Google Cloud Secret Manager
- **Creates versioned secrets** named like `ika-new-devnet-ika-val-1-keys`
- **Bundles all key files** (consensus.key, network.key, protocol.key, root-seed.key) into JSON format
- **Parallel processing** up to 10 validators simultaneously for efficiency

#### 4.2 Deploy Fullnode Keys

- **Uploads fullnode/publisher keys** to GCP Secret Manager
- **Creates secret** named like `ika-new-devnet-ika-fullnode-1-keys`
- **Enables secure key access** for fullnode operations

#### 4.3 Update Terraform Configuration

- **Extracts chain configuration** from `locals.tf`
- **Updates Terraform workspace file** with the new Ika chain parameters
- **Preserves existing configuration** while updating only Ika-specific values
- **Creates automatic backup** of the original Terraform file
- **Copies configuration files** to Terraform modules directory

#### 4.4 File Organization

- **Copies `seed_peers.yaml`** to Terraform modules for network bootstrapping
- **Organizes files** in the correct Terraform directory structure
- **Enables infrastructure** to reference the correct peer information

### Script Parameters

The script uses these default values (can be customized at the top of the file):

```bash
VALIDATOR_NUM=4                                          # Number of validators
TERRAFORM_WORKSPACES_FILE="../../../infra/tf-gcp/workspace.devnet.tf"  # Terraform config file
SUBDOMAIN=beta.devnet.ika-network.net                   # Network subdomain
GCP_PROJECT=devnet-449616                               # GCP project ID
ENV_PREFIX=ika-new-devnet                               # Secret name prefix
TF_NETWORK_NAME=new-devnet                              # Terraform network identifier
```

---

## Final Steps

After completing all steps:

1. **Verify Infrastructure**: Check that all GCP resources are created correctly
2. **Validate Secrets**: Ensure all keys are properly stored in Secret Manager
3. **Test Network**: Verify that validators can communicate and reach consensus
4. **Monitor Logs**: Check validator and fullnode logs for any issues

## Local Testing

You can also run the devnet locally using Docker Compose:

```bash
cd beta.devnet.ika-network.net/
docker-compose up
```

This will start all validators and the fullnode on your local machine for development and testing.

---

## Troubleshooting

- **SUI Connection Issues**: Verify SUI RPC URLs are accessible
- **Key Generation Failures**: Ensure sufficient entropy and disk space
- **Terraform Errors**: Check GCP permissions and quotas
- **Network Issues**: Verify DNS resolution and firewall rules

For additional support, check the validator logs and ensure all prerequisites are properly installed.
