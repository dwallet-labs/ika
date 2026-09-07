# Epoch startup preparation

An active validator must prepare every MPC input inherited from the preceding
handoff before consensus replay or live rounds can reach the new epoch's MPC
service. Missing local data must not change the validator's inputs, key choice,
or presign assignment order relative to its peers.

Actors: `ika-node::wait_for_handoff_data_ready`,
`DWalletMPCService::prepare_epoch`, `DWalletMPCManager`, the process-level
Sui syncer, and the content-addressed artifact stores. This applies to process
startup/restart, continuing-validator reconfiguration, and fullnode promotion.

## What must be ready

| Input                                                         | Source and preparation                                                              | Before consensus starts                                                                                             |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Current committee, protocol configuration, root-seed decision | Epoch-start state and seed resolution                                               | Constructed and checked already                                                                                     |
| Local VSS HPKE secret key                                     | Root seed in the cryptographic orchestrator constructor                             | Derived already                                                                                                     |
| Prior handoff certificate                                     | Durable store or verified peer fetch                                                | Verified and persisted; persistence failure cannot release the barrier                                              |
| Network key identities                                        | Persisted mappings or identity derivation from chain-published blobs                | Every certified key must translate, including with NOA disabled                                                     |
| Network key creation metadata                                 | Process-level syncer's chain overlay                                                | Every certified key's immutable `dkg_at_epoch` must be present                                                      |
| Inherited DKG and reconfiguration outputs                     | Exact digests in the prior certificate                                              | Matching digest rows and hash-verified durable bytes; repair missing/mismatching data from peers                    |
| Current validator MPC bundles                                 | Prior certificate's `ValidatorMpcData` items intersected with the current committee | All certified members' blobs durable, hash-matching and structurally decodable; then assemble and ingest the bundle |
| Network public parameters and access structure                | Certified output bytes and the entering committee/epoch                             | Instantiation finished, rather than merely queued on rayon                                                          |
| Local AHE decryption shares and VSS caches                    | Instantiated key and root seed                                                      | AHE decryption finished; VSS cache derivation finished with its recorded outcome                                    |
| Fixed NOA signing key                                         | Certified key set and immutable creation metadata                                   | Resolved before construction; absent local data never means a keyless epoch                                         |

The connector constructor first publishes the verified Sui system and
coordinator objects to the syncer's watch channels. This initial read is
independent of `SuiExecutor::run_epoch`, which starts only after node startup.
Otherwise the barrier waits for key metadata, the syncer waits for these
objects, and the epoch execution loop waits for the barrier: a startup
deadlock even when the certificate and its artifact blobs are already local.
The normal epoch loop continues refreshing the objects afterwards. Initial
publication performs no checkpoint writes or epoch transitions.

The barrier fetches missing validator bundles inline using
`fetch_missing_prior_cert_mpc_data_blobs`. Waiting for the epoch's periodic
fetcher would deadlock because that task does not exist yet. A blob cached only
in memory does not satisfy the durable read that manager ingestion uses.

After the barrier, `DWalletMPCService::prepare_epoch` runs immediately before
spawning `ConsensusManager::start`. It ingests the current validator keys,
instantiates the inherited network keys, and waits for installation and share
derivation. It does not execute MPC sessions or consume consensus rounds.
Checkpoint components may already be constructed, but their replay barrier
still holds. The service loop retains dynamic adoption for outputs created
during the epoch; it is no longer the first initializer of inherited keys.

Preparation constructs a separate immutable network-key snapshot. A restart's
live overlay can already contain the **next** committee's reconfiguration
output or a later state. Only `dkg_at_epoch` comes from that overlay. The
certificate selects the bytes and output state; the entering epoch selects
the access structure. Preparing the live overlay instead could install the
wrong epoch's shares before replay.

## Failure and participation rules

Missing mappings, metadata, or certified artifacts hold the startup barrier
while their producers recover them. Malformed or missing durable validator
blobs are repaired from peers. A contradicted certificate fails closed as
specified in [`handoff.md`](handoff.md).

An error in parameter instantiation or AHE decryption fails startup. Readiness
checks the completed-installation record, which is written after decryption,
not merely the public-parameter map populated before decryption. VSS derivation
retains its existing terminal outcomes: `Derived`, `Failed`, or `NotApplicable`.
Preparation finishes that work; it does not redefine a non-VSS key or an
undealt validator as a consensus failure.

A validator marked MPC-inactive by root-seed resolution skips cryptographic
preparation and still participates in consensus. It must not try decrypting
with a mismatched seed. Committee members absent from the prior certified set
remain undealt; preparation does not impose an all-committee participation
requirement. Only the agreed certified members' blobs are required.

## Inputs that remain dynamic

These are not missing inherited configuration and cannot be moved wholesale
before epoch startup:

- **Genesis/first off-chain epoch:** no prior certificate exists. The epoch's
  own consensus freeze supplies the initial validator bundle and DKG produces
  the first network key. Gating consensus on either would deadlock genesis.
- **Fresh network DKG:** requests and outputs created during this epoch have
  no prior certified bytes. Their adoption, public parameters and shares are
  prepared when the output is agreed.
- **Next committee and next validator bundle:** membership, announcements,
  ready votes and the current epoch's freeze establish these during the epoch.
  They feed reconfiguration and become the next epoch's inherited inputs.
- **Requests and recovery:** the Sui bag event pump continuously publishes new
  and still-uncompleted requests, including older requests. Session-specific
  inputs and completed-status lookups are consumed with those requests, not
  loaded as an unbounded epoch-start snapshot.
- **Consensus-derived state:** sessions, presign pools, assignments, chain
  observations and checkpoint state are folded from commits. Restart rebuilds
  them through replay; see [`event-sourced-epoch.md`](event-sourced-epoch.md).
- **Current handoff and epoch-close decisions:** outputs, the next committee,
  session-completion target and quorum evidence must first be produced. They
  cannot be prerequisites for starting the epoch that produces them.

The lazy static maps in `dwallet-mpc-types::mpc_protocol_configuration` contain
small, fixed algorithm identifiers, with no network or disk loading and no
per-validator readiness choice. Runtime once-cells and the shared Mysticeti
client publish configuration or handles. They are not deferred inherited MPC
material. This boundary does not promise that every request-time allocation,
database read or library cache is eliminated.

## Regression evidence

- `epoch_start_data::tests` exercises absent mappings, missing or corrupt blobs,
  invalid validator bundles, and certificate bytes overriding a future overlay.
- `epoch_startup_prepares_inherited_key_material_before_any_round` uses real
  crypto and asserts public parameters, decrypted AHE shares and VSS caches
  after preparation alone, with no new-epoch round or session processed.
- `epoch_startup_preserves_seed_inactive_consensus_participation` ensures the
  deliberate seed-mismatch participation path does not attempt decryption.
- `missing_prior_cert_blob_is_refetched_from_peers_and_ingested` proves a
  memory-only cache entry cannot suppress durable peer repair.

Fault-injection controls remove the service's preparation call and substitute
live-overlay reconfiguration bytes. The startup test must fail with
`validator bundles must be ingested before startup`, and the snapshot test
must fail with `startup must use the certified shares, not the live overlay`.
Both expected assertions were observed; the clean controls pass.

`test_boot_into_epoch_waits_for_handoff_data` bounds restart at 120 seconds:
the deliberate 30-second anchor hold must finish, and the initial Sui object
publication must let key-metadata preparation complete without starting the
epoch execution loop first. The deployed-release rollout exercises the same
bootstrap with no persisted key-ID mapping.
