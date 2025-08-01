# Ika for Node Operators

## Overview

This document is focused on running the Ika Node software as a Validator.

## Contents

- [Requirements](#requirements)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Connectivity](#connectivity)
- [Storage](storage.md)
- [Key Management](#key-management)
- [Monitoring](#monitoring)
  - [Logs](#logs)
  - [Metrics](#metrics)
  - [Dashboards](#dashboards)
- [Software Updates](#software-updates)
- [State Sync](#state-sync)
- [Chain Operations](#chain-operations)
- [Private Security Fixes](#private-security-fixes)

## Requirements

To run a Ika Validator a machine with the following is required:
- CPU: 24 physical cores (or 48 virtual cores)
- Memory: 128 GB
- Storage: 4 TB NVME
- Network: 1 Gbps

## Deployment

Ika Node can be deployed in a number of ways.

There are pre-built container images available in [Docker Hub](https://hub.docker.com/r/ika-io/ika-node/tags).

And pre built `linux/amd64` binaries available in S3 that can be fetched using one of the following methods:

```shell
wget https://releases.ika.io/$IKA_SHA/ika-node
```

```shell
curl https://releases.ika.io/$IKA_SHA/ika-node -o ika-node
```

To build directly from source:

```shell
git clone https://github.com/MystenLabs/sui.git && cd ika
git checkout [SHA|BRANCH|TAG]
cargo build --release --bin ika-node
```

Configuration and guides are available for the following deployment options:

- [Systemd](./systemd/README.md)
- [Ansible](./ansible/README.md)
- [Docker Compose](./docker/README.md)

## Configuration

Ika Node runs with a single configuration file provided as an argument, example:

`./ika-node --config-path /opt/ika/config/validator.yaml`.

Configuration templates are available here:

- [Validator](./config/validator.yaml)

## Connectivity

Ika Node uses the following ports by default:

| protocol/port | reachability     | purpose                           |
| ------------- | ---------------- | --------------------------------- |
| TCP/8080      | inbound          | protocol / transaction interface  |
| TCP/8081      | inbound/outbound | consensus interface               |
| UDP/8081      | inbound/outbound | narwhal primary interface         |
| UDP/8082      | inbound/outbound | narwhal worker interface          |
| UDP/8084      | inbound/outbound | peer to peer state sync interface |
| TCP/8443      | outbound         | metrics pushing                   |
| TCP/9184      | localhost        | metrics scraping                  |

To run a validator successfully it is critical that ports 8080-8084 are open as outlined above, including the specific protocol (TCP/UDP).

## Storage

All Ika Node-related data is stored by default under `/opt/ika/db/`. This is controlled in the Ika Node configuration file.

```shell
$ cat /opt/ika/config/validator.yaml | grep db-path
db-path: /opt/ika/db/authorities_db
  db-path: /opt/ika/db/consensus_db
```

Ensure that you have an appropriately sized disk mounted for the database to write to.

- To check the size of the local Ika Node databases:

```shell
du -sh /opt/ika/db/
du -sh /opt/ika/db/authorities_db
du -sh /opt/ika/db/consensus_db
```

- To delete the local Ika Node databases:

```shell
sudo systemctl stop ika-node
sudo rm -rf /opt/ika/db/authorities_db /opt/ika/db/consensus_db
```

## Key Management

The following keys are used by Ika Node:

| key          | scheme   | purpose                         |
| ------------ | -------- | ------------------------------- |
| protocol.key | bls12381 | transactions, narwhal consensus |
| account.key  | ed25519  | controls assets for staking     |
| network.key  | ed25519  | narwhal primary, ika state sync |
| worker.key   | ed25519  | validate narwhal workers        |

These are configured in the [Ika Node configuration file](#configuration).

You can generate each of these via the [ika cli](https://docs.ika.io/guides/developer/getting-started/ika-install).

```
$ ika keytool generate bls12381
$ ika keytool generate ed25519
$ ika keytool generate ed25519
$ ika keytool generate ed25519
```

This will create files like `0x0061b30cdda02b6f55f575f1485a2890ec5c95b753deabbf823b6de7c936eb26.key` & `bls-0x1b7a4038f207d6c65cc106dd5be7270b3031e671fc8f9c1318b19e94a3bf3ed5.key`
which you can copy to your validator and rename to `protocol.key` or `account.key`, etc.

## Monitoring

### Metrics

Ika Node exposes metrics via a local HTTP interface. These can be scraped for use in a central monitoring system as well as viewed directly from the node.

- View all metrics:

```shell
curl -s http://localhost:9184/metrics
```

- Search for a particular metric:

```shell
curl http://localhost:9184/metrics | grep <METRIC>
```

Ika Node also pushes metrics to a central Ika metrics proxy.

### Logs

Logs are controlled using the `RUST_LOG` environment variable.

The `RUST_LOG_JSON=1` environment variable can optionally be set to enable logging in JSON structured format.

Depending on your deployment method, these will be configured in the following places:

- If using Ansible, [here](./ansible/roles/ika-node/files/ika-node.service)
- If using Systemd natively, [here](./systemd/ika-node.service)
- If using Docker Compose, [here](./docker/docker-compose.yaml)

To view and follow the Ika Node logs:

```shell
journalctl -u ika-node -f
```

To search for a particular match

```shell
journalctl -u ika-node -g <SEARCH_TERM>
```

- If using Docker Compose, look at the examples [here](./docker/README.md#logs)

It is possible to change the logging configuration while a node is running using the admin interface.

To view the currently configured logging values:

```shell
curl localhost:1337/logging
```

To change the currently configured logging values:

```shell
curl localhost:1337/logging -d "info"
```

### Dashboards

Public dashboard for network wide visibility:

- [Ika Testnet Validators](https://metrics.ika.io/public-dashboards/9b841d63c9bf43fe8acec4f0fa991f5e)

## Software Updates

When an update is required to the Ika Node software the following process can be used. Follow the relevant Systemd or Docker Compose runbook depending on your deployment type. It is highly unlikely that you will want to restart with a clean database.

- If using Systemd, [here](./systemd/README.md#updates)
- If using Docker Compose, [here](./docker/README.md#updates)

## State Sync

Checkpoints in Ika contain the permanent history of the network. They are comparable to blocks in other blockchains with one big difference being that they are lagging instead of leading. All transactions are final and executed prior to being included in a checkpoint.

These checkpoints are synchronized between validators and fullnodes via a dedicated peer to peer state sync interface.

Inter-validator state sync is always permitted however there are controls available to limit what fullnodes are allowed to sync from a specific validator.

The default and recommended `max-concurrent-connections: 0` configuration does not affect inter-validator state sync, but will restrict all fullnodes from syncing. The Ika Node [configuration](#configuration) can be modified to allow a known fullnode to sync from a validator:

```shell
p2p-config:
  anemo-config:
    max-concurrent-connections: 0
  seed-peers:
    - address: <multiaddr>  # The p2p address of the fullnode
      peer-id: <peer-id>    # hex encoded network public key of the node
    - address: ...          # another permitted peer
      peer-id: ...
```

## Chain Operations

The following chain operations are executed using the `ika` CLI. This binary is built and provided as a release similar to `ika-node`, examples:

```shell
wget https://releases.ika.io/$IKA_SHA/ika
chmod +x ika
```

```shell
curl https://releases.ika.io/$IKA_SHA/ika -o ika
chmod +x ika
```

It is recommended and often required that the `ika` binary release/version matches that of the deployed network.

### Updating On-chain Metadata

You can leverage [Validator Tool](validator_tool.md) to perform majority of the following tasks.

An active/pending validator can update its on-chain metadata by submitting a transaction. Some metadata changes take effect immediately, including:

- name
- description
- image url
- project url

Other metadata (keys, addresses etc) only come into effect at the next epoch.

To update metadata, a validator makes a MoveCall transaction that interacts with the System Object. For example:

1. to update name to `new_validator_name`, use the Ika Client CLI to call `ika_system::update_validator_name`:

```
ika client call --package 0x3 --module ika_system --function update_validator_name --args 0x5 \"new_validator_name\" --gas-budget 10000
```

2. to update p2p address starting from next epoch to `/ip4/192.168.1.1`, use the Ika Client CLI to call `ika_system::update_validator_next_epoch_p2p_address`:

```
ika client call --package 0x3 --module ika_system --function update_validator_next_epoch_p2p_address --args 0x5 "[4, 192, 168, 1, 1]" --gas-budget 10000
```

See the [full list of metadata update functions here](https://github.com/MystenLabs/sui/blob/main/crates/ika-framework/packages/ika-system/sources/ika_system.move#L267-L444).

### Operation Cap

To avoid touching account keys too often and allowing them to be stored off-line, validators can delegate the operation ability to another address. This address can then update the computation price per unit size and tallying rule on behalf of the validator.

Upon creating a `Validator`, an `UnverifiedValidatorOperationCap` is created as well and transferred to the validator address. The holder of this `Cap` object (short for "Capability") therefore could perform operational actions for this validator. To authorize another address to conduct these operations, a validator transfers the object to another address that they control. The transfer can be done by using Ika Client CLI: `ika client transfer`.

To rotate the delegatee address or revoke the authorization, the current holder of `Cap` transfers it to another address. In the event of compromised or lost keys, the validator could create a new `Cap` object to invalidate the incumbent one. This is done by calling `ika_system::rotate_operation_cap`:

```
ika client call --package 0x3 --module ika_system --function rotate_operation_cap --args 0x5 --gas-budget 10000
```

By default the new `Cap` object is transferred to the validator address, which then could be transferred to the new delegatee address. At this point, the old `Cap` becomes invalidated and no longer represents eligibility.

To get the current valid `Cap` object's ID of a validator, use the Ika Client CLI `ika client objects` command after setting the holder as the active address. Or go to the [explorer](https://explorer.ika.io/object/0x0000000000000000000000000000000000000005) and look for `operation_cap_id` of that validator in the `validators` module.

### Updating the Gas Price Survey Quote

To update the Gas Price Survey Quote of a validator, which is used to calculate the Reference Gas Price at the end of the epoch, the sender needs to hold a valid [`UnverifiedValidatorOperationCap`](#operation-cap). The sender could be the validator itself, or a trusted delegatee. To do so, call `ika_system::request_set_computation_price`:

```
ika client call --package 0x3 --module ika_system --function request_set_computation_price --args 0x5 {cap_object_id} {new_computation_price} --gas-budget 10000
```

### Reporting/Un-reporting Validators

To report a validator or undo an existing reporting, the sender needs to hold a valid [`UnverifiedValidatorOperationCap`](#operation-cap). The sender could be the validator itself, or a trusted delegatee. To do so, call `ika_system::report_validator/undo_report_validator`:

```
ika client call --package 0x3 --module ika_system --function report_validator/undo_report_validator --args 0x5 {cap_object_id} {reportee_address} --gas-budget 10000
```

Once a validator is reported by `2f + 1` other validators by voting power, their staking rewards will be slashed.

### Joining the Validator Set

In order for a Ika address to join the validator set, they need to first sign up as a validator candidate by calling `ika_system::request_add_validator_candidate` with their metadata and initial configs:

```
ika client call --package 0x3 --module ika_system --function request_add_validator_candidate --args 0x5 {protocol_pubkey_bytes} {network_pubkey_bytes} {worker_pubkey_bytes} {proof_of_possession} {name} {description} {image_url} {project_url} {net_address}
{p2p_address} {primary_address} {worker_address} {computation_price} {commission_rate} --gas-budget 10000
```

After an address becomes a validator candidate, any address (including the candidate address itself) can start staking with the candidate's staking pool. Refer to our dedicated staking FAQ on how staking works. Once a candidate's staking pool has accumulated at least `ika_system::MIN_VALIDATOR_JOINING_STAKE` amount of stake, the candidate can call `ika_system::request_add_validator` to officially add themselves to the next epoch's active validator set:

```
ika client call --package 0x3 --module ika_system --function request_add_validator --args 0x5 --gas-budget 10000000
```

### Leaving the Validator Set

To leave the validator set starting the next epoch, the sender needs to be an active validator in the current epoch and should call `ika_system::request_remove_validator`:

```
ika client call --package 0x3 --module ika_system --function request_remove_validator --args 0x5 --gas-budget 10000
```

After the validator is removed at the next epoch change, the staking pool will become inactive and stakes can only be withdrawn from an inactive pool.

## Private Security Fixes

There may be instances where urgent security fixes need to be rolled out before publicly announcing it's presence (Issues affecting liveliness, invariants such as IKA supply, governance etc). In order to not be actively exploited MystenLabs will release signed security binaries incorporating such fixes with a delay in publishing the source code until a large % of our validators have patched the vulnerability.

This release process will be different and we expect us to announce the directory for such binaries out of band.
Our public key to verify these binaries would be stored [here](https://ika-private.s3.us-west-2.amazonaws.com/ika_security_release.pem)

You can download all the necessary signed binaries and docker artifacts incorporating the security fixes by using the [download_private.sh](https://github.com/MystenLabs/sui/blob/main/nre/download_private.sh)

Usage
`./download_private.sh <directory-name>`

You can also download and verify specific binaries that may not be included by the above script using the [download_and_verify_private_binary.sh](https://github.com/MystenLabs/sui/blob/main/nre/download_and_verify_private_binary.sh) script.

Usage:
`./download_and_verify_private_binary.sh <directory-name> <binary-name>`
