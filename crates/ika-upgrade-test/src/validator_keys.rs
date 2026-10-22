// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Certified validator-key checkpoints for the fixed-committee v1.4.1 rollout.
//! Expected identities contain public keys only; proof bytes never identify a key.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use anemo::{Config, Network, PeerId, Router};
use anyhow::{Context, Result, ensure};
use dwallet_mpc_types::dwallet_mpc::{MPCDataTrait, VersionedMPCData};
use fastcrypto::traits::{KeyPair, VerifyingKey};
use ika_config::node::NodeConfig;
use ika_network::mpc_artifacts::{
    fetch_blob, fetch_certified_handoff_attestation, mpc_data_blob_hash,
};
use ika_types::committee::{Committee, CommitteeTrait, ValidatorEncryptionKeysAndProofs};
use ika_types::crypto::{AuthorityName, NetworkKeyPair};
use ika_types::digests::ChainIdentifier;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use ika_types::intent::{Intent, IntentMessage, IntentScope};
use rand::thread_rng;
use tokio::time::{Instant, sleep, timeout_at};

use crate::cluster::{parse_metric_samples, required_labeled_metric, required_unlabeled_metric};
use crate::process::ValidatorProcess;

const KEY_NAMES: [&str; 7] = [
    "class-groups CRT key 0",
    "class-groups CRT key 1",
    "class-groups CRT key 2",
    "secp256k1 PVSS key",
    "secp256r1 PVSS key",
    "ristretto PVSS key",
    "VSS HPKE key",
];
type PublicKeys = [Vec<u8>; 7];

struct OriginalValidator {
    index: usize,
    authority: AuthorityName,
    peer: PeerId,
    address: SocketAddr,
}

/// Compare authenticated public keys across the existing live rollout.
/// Native derivation against the deployed fixture is covered by ika-core tests.
pub(crate) struct ValidatorKeyPreservation {
    validators: Vec<OriginalValidator>,
    committee: Committee,
    network: Network,
    baseline: Mutex<Option<BTreeMap<AuthorityName, PublicKeys>>>,
}

impl ValidatorKeyPreservation {
    pub(crate) fn prepare(
        configs: Vec<(usize, AuthorityName, NodeConfig)>,
        committee: Committee,
    ) -> Result<Self> {
        ensure!(
            !configs.is_empty(),
            "validator-key checkpoint requires original validators"
        );
        let chain = ChainIdentifier::from(configs[0].2.sui_connector_config.ika_system_object_id);
        let keypair = NetworkKeyPair::generate(&mut thread_rng());
        let mut config = Config::default();
        config.max_frame_size = Some(1 << 30);
        let network = Network::bind("127.0.0.1:0")
            .server_name(format!("ika-{chain}"))
            .private_key(keypair.copy().private().0.to_bytes())
            .config(config)
            .start(Router::new())?;
        let validators = configs
            .into_iter()
            .map(|(index, authority, config)| {
                let address = config.p2p_config.listen_address;
                let address = if address.ip().is_unspecified() {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
                } else {
                    address
                };
                OriginalValidator {
                    index,
                    authority,
                    peer: PeerId(config.network_key_pair().public().0.to_bytes()),
                    address,
                }
            })
            .collect::<Vec<_>>();
        let original: BTreeSet<_> = validators
            .iter()
            .map(|validator| validator.authority)
            .collect();
        let members: BTreeSet<_> = committee
            .voting_rights
            .iter()
            .map(|(authority, _)| *authority)
            .collect();
        ensure!(
            original == members && original.len() == validators.len(),
            "key preservation requires exactly the original fixed committee"
        );
        Ok(Self {
            validators,
            committee,
            network,
            baseline: Mutex::new(None),
        })
    }

    pub(crate) fn check_committee(&self, committee: &Committee) -> Result<()> {
        ensure!(
            committee.voting_rights == self.committee.voting_rights
                && committee.quorum_threshold() == self.committee.quorum_threshold(),
            "validator-key preservation checkpoint requires the original fixed committee and stake"
        );
        Ok(())
    }

    pub(crate) async fn assert_preserved(
        &self,
        processes: &[ValidatorProcess],
        active_epoch: u64,
        current: bool,
    ) -> Result<()> {
        let certificate_epoch = active_epoch
            .checked_sub(1)
            .context("key checkpoint needs a prior handoff")?;
        if current {
            ensure!(
                self.baseline
                    .lock()
                    .expect("key checkpoint mutex poisoned")
                    .is_some(),
                "current-key checkpoint requires an observed legacy baseline"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        timeout_at(deadline, async {
            let mut blobs = BTreeMap::new();
            loop {
                let mut ready = true;
                for validator in &self.validators {
                    let process = processes.get(validator.index).context("original validator process missing")?;
                    ensure!(process.is_running(), "original validator {} is not running", validator.index);
                    ready &= validator_ready(process, active_epoch, current).await?;
                }
                if ready {
                    let mut certificates = Vec::new();
                    for validator in &self.validators {
                        if self.network.peer(validator.peer).is_none() {
                            self.network.connect_with_peer_id(validator.address, validator.peer).await
                                .with_context(|| format!("connect to original validator {}", validator.index))?;
                        }
                        let Some(cert) = fetch_certified_handoff_attestation(&self.network, validator.peer, certificate_epoch).await? else {
                            ready = false;
                            continue;
                        };
                        let digests = verify_certificate(&cert, &self.committee, active_epoch)?;
                        for digest in digests.values() {
                            if !blobs.contains_key(digest) {
                                match fetch_blob(&self.network, validator.peer, *digest).await? {
                                    Some(blob) => {
                                        ensure!(mpc_data_blob_hash(&blob) == *digest, "certified validator bundle hash mismatch");
                                        blobs.insert(*digest, blob);
                                    }
                                    None => ready = false,
                                }
                            }
                        }
                        certificates.push(cert);
                    }
                    if ready {
                        let first = certificates.first().context("no original validator served a certificate")?;
                        ensure!(certificates.len() == self.validators.len(), "missing original validator certificate");
                        ensure!(certificates.iter().all(|cert| cert.attestation == first.attestation), "original validators served different handoff attestations");
                        let observed = verify_snapshot(first, &self.committee, active_epoch, &blobs)?;
                        // All peers served the same authenticated attestation. Re-read
                        // every live epoch after the fetch to exclude an epoch-crossing snapshot.
                        for validator in &self.validators {
                            let process = &processes[validator.index];
                            ensure!(validator_ready(process, active_epoch, current).await?, "validator {} lost exact epoch {active_epoch} readiness during key checkpoint", validator.index);
                        }
                        if current {
                            let baseline = self.baseline.lock().expect("key checkpoint mutex poisoned");
                            let baseline = baseline.as_ref().context("legacy baseline missing")?;
                            for (authority, keys) in &observed {
                                assert_preservation(&baseline[authority], keys, *authority)?;
                                tracing::info!(?authority, active_epoch, unchanged_class_group_keys = 6,
                                    unchanged_vss_hpke = true, "verified validator encryption-key preservation");
                            }
                        } else {
                            *self.baseline.lock().expect("key checkpoint mutex poisoned") = Some(observed);
                        }
                        tracing::info!(active_epoch, certificate_epoch, current, validators = self.validators.len(), keys_per_validator = 7,
                            "verified every original validator's active certified encryption keys");
                        return Ok(());
                    }
                }
                sleep(Duration::from_secs(1)).await;
            }
        }).await.with_context(|| format!("validator-key checkpoint for active epoch {active_epoch} did not become ready within 120s"))?
    }
}

fn assert_preservation(
    legacy: &PublicKeys,
    current: &PublicKeys,
    authority: AuthorityName,
) -> Result<()> {
    for (index, name) in KEY_NAMES.iter().enumerate() {
        ensure!(
            legacy[index] == current[index],
            "validator {authority} {name} unexpectedly changed across the binary upgrade"
        );
    }
    Ok(())
}

fn next_committee_hash(committee: &Committee) -> Result<[u8; 32]> {
    let names: BTreeSet<_> = committee
        .voting_rights
        .iter()
        .map(|(authority, _)| *authority)
        .collect();
    Ok(mpc_data_blob_hash(&bcs::to_bytes(
        &names.into_iter().collect::<Vec<_>>(),
    )?))
}

fn verify_certificate(
    cert: &CertifiedHandoffAttestation,
    committee: &Committee,
    active_epoch: u64,
) -> Result<BTreeMap<AuthorityName, [u8; 32]>> {
    ensure!(
        Some(cert.attestation.epoch) == active_epoch.checked_sub(1),
        "wrong handoff epoch for active epoch {active_epoch}"
    );
    ensure!(
        cert.attestation.next_committee_pubkey_set_hash == next_committee_hash(committee)?,
        "handoff next committee mismatch"
    );
    ensure!(
        cert.attestation
            .items
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0),
        "handoff items must be strictly sorted and unique"
    );
    let bytes = bcs::to_bytes(&IntentMessage::new(
        Intent::ika_app(IntentScope::HandoffAttestation),
        cert.attestation.clone(),
    ))?;
    let mut seen = HashSet::new();
    let mut stake = 0u64;
    for (signer, signature) in &cert.signatures {
        ensure!(seen.insert(*signer), "duplicate handoff signer");
        let weight = committee.weight(signer);
        ensure!(weight > 0, "handoff signer outside original committee");
        committee
            .consensus_key(signer)
            .context("handoff signer consensus key missing")?
            .verify(&bytes, signature)
            .context("invalid handoff signature")?;
        stake = stake
            .checked_add(weight)
            .context("handoff signing stake overflow")?;
    }
    ensure!(
        stake >= committee.quorum_threshold(),
        "handoff signature stake below quorum"
    );
    let digests: BTreeMap<_, _> = cert
        .attestation
        .items
        .iter()
        .filter_map(|(key, digest)| match key {
            HandoffItemKey::ValidatorMpcData { validator } => Some((*validator, *digest)),
            _ => None,
        })
        .collect();
    let expected: BTreeSet<_> = committee
        .voting_rights
        .iter()
        .map(|(authority, _)| *authority)
        .collect();
    ensure!(
        digests.keys().copied().collect::<BTreeSet<_>>() == expected,
        "certified validator set does not contain every original validator exactly once"
    );
    Ok(digests)
}

fn decode_public_keys(blob: &[u8]) -> Result<PublicKeys> {
    let VersionedMPCData::V1(data) =
        bcs::from_bytes(blob).context("decode certified MPC data envelope")?;
    let bundle: ValidatorEncryptionKeysAndProofs = bcs::from_bytes(&data.mpc_data_bytes())
        .context("decode certified encryption keys and proofs")?;
    public_keys(&bundle)
}

fn public_keys(bundle: &ValidatorEncryptionKeysAndProofs) -> Result<PublicKeys> {
    Ok([
        bcs::to_bytes(&bundle.class_groups[0].0)?,
        bcs::to_bytes(&bundle.class_groups[1].0)?,
        bcs::to_bytes(&bundle.class_groups[2].0)?,
        bcs::to_bytes(&bundle.secp256k1_pvss.0)?,
        bcs::to_bytes(&bundle.secp256r1_pvss.0)?,
        bcs::to_bytes(&bundle.ristretto_pvss.0)?,
        bcs::to_bytes(&bundle.vss_hpke_public_key_and_proof.0)?,
    ])
}

fn verify_snapshot(
    cert: &CertifiedHandoffAttestation,
    committee: &Committee,
    active_epoch: u64,
    blobs: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<BTreeMap<AuthorityName, PublicKeys>> {
    verify_certificate(cert, committee, active_epoch)?
        .into_iter()
        .map(|(authority, digest)| {
            let blob = blobs
                .get(&digest)
                .context("certified validator bundle missing")?;
            ensure!(
                mpc_data_blob_hash(blob) == digest,
                "certified validator bundle hash mismatch"
            );
            let actual = decode_public_keys(blob)?;
            Ok((authority, actual))
        })
        .collect()
}

async fn validator_ready(process: &ValidatorProcess, epoch: u64, current: bool) -> Result<bool> {
    let metrics = process.metrics().await?;
    if !metrics
        .lines()
        .any(|line| line.starts_with("ika_current_epoch ") || line.starts_with("current_epoch "))
    {
        return Ok(false);
    }
    let observed =
        required_unlabeled_metric(&metrics, &["ika_current_epoch", "current_epoch"], process)?;
    ensure!(
        observed <= epoch,
        "validator {} advanced to epoch {observed} during exact epoch {epoch} key checkpoint",
        process.index
    );
    if observed < epoch {
        return Ok(false);
    }
    if current {
        if !key_preparation_complete(&metrics, epoch)? {
            return Ok(false);
        }
        if !metrics.contains("ika_dwallet_mpc_seed_identity_state{") {
            return Ok(false);
        }
        let matches = required_labeled_metric(
            &metrics,
            "ika_dwallet_mpc_seed_identity_state",
            &[("state", "matches")],
            process,
        )?;
        ensure!(matches <= 1, "invalid seed-identity matches gauge");
        if matches != 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn key_preparation_complete(metrics: &str, epoch: u64) -> Result<bool> {
    let samples = parse_metric_samples(metrics, "ika_dwallet_mpc_validator_key_epoch")?;
    for stage in ["selected", "prepared"] {
        let matching = samples
            .iter()
            .filter(|sample| {
                sample
                    .labels
                    .get("stage")
                    .is_some_and(|value| value == stage)
            })
            .collect::<Vec<_>>();
        ensure!(
            matching.len() <= 1,
            "duplicate validator key epoch stage {stage}"
        );
        let Some(sample) = matching.first() else {
            return Ok(false);
        };
        ensure!(
            sample.value.is_finite() && sample.value >= -1.0 && sample.value.fract() == 0.0,
            "invalid validator key epoch stage {stage}"
        );
        if sample.value != epoch as f64 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use dwallet_mpc_types::dwallet_mpc::MPCDataV1;
    use fastcrypto::traits::Signer;
    use ika_types::handoff::HandoffAttestation;

    use super::*;

    const LEGACY_FIXTURE: &[u8] = include_bytes!(
        "../../ika-core/src/dwallet_mpc/integration_tests/fixtures/legacy-validator-mpc-data.bcs"
    );

    fn committee_and_signers() -> (Committee, Vec<NetworkKeyPair>) {
        let signers: Vec<_> = (0..4)
            .map(|_| NetworkKeyPair::generate(&mut thread_rng()))
            .collect();
        let members: Vec<_> = signers
            .iter()
            .map(|key| (AuthorityName::from_consensus_key(key.public()), 1))
            .collect();
        let keys = signers
            .iter()
            .map(|key| {
                (
                    AuthorityName::from_consensus_key(key.public()),
                    key.public().clone(),
                )
            })
            .collect();
        (
            Committee::new(5, members, HashMap::new(), keys, 3, 2),
            signers,
        )
    }

    fn sign_attestation(
        attestation: HandoffAttestation,
        signers: &[NetworkKeyPair],
    ) -> CertifiedHandoffAttestation {
        let message = bcs::to_bytes(&IntentMessage::new(
            Intent::ika_app(IntentScope::HandoffAttestation),
            attestation.clone(),
        ))
        .unwrap();
        let signatures = signers
            .iter()
            .take(3)
            .map(|key| {
                (
                    AuthorityName::from_consensus_key(key.public()),
                    key.sign(&message),
                )
            })
            .collect();
        CertifiedHandoffAttestation {
            attestation,
            signatures,
        }
    }

    fn certificate(
        committee: &Committee,
        signers: &[NetworkKeyPair],
        blob: &[u8],
    ) -> CertifiedHandoffAttestation {
        sign_attestation(
            HandoffAttestation {
                epoch: 5,
                next_committee_pubkey_set_hash: next_committee_hash(committee).unwrap(),
                items: committee
                    .voting_rights
                    .iter()
                    .map(|(validator, _)| {
                        (
                            HandoffItemKey::ValidatorMpcData {
                                validator: *validator,
                            },
                            mpc_data_blob_hash(blob),
                        )
                    })
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            },
            signers,
        )
    }

    fn expected_keys(
        committee: &Committee,
        keys: &PublicKeys,
    ) -> BTreeMap<AuthorityName, PublicKeys> {
        committee
            .voting_rights
            .iter()
            .map(|(authority, _)| (*authority, keys.clone()))
            .collect()
    }

    fn encode_bundle(bundle: &ValidatorEncryptionKeysAndProofs) -> Vec<u8> {
        bcs::to_bytes(&VersionedMPCData::V1(MPCDataV1 {
            mpc_data_bytes: bcs::to_bytes(bundle).unwrap(),
        }))
        .unwrap()
    }

    #[test]
    fn certificate_requires_exact_epoch_committee_quorum_and_all_validators() {
        let (committee, signers) = committee_and_signers();
        let cert = certificate(&committee, &signers, LEGACY_FIXTURE);
        assert_eq!(verify_certificate(&cert, &committee, 6).unwrap().len(), 4);
        assert!(
            verify_certificate(&cert, &committee, 7)
                .unwrap_err()
                .to_string()
                .contains("wrong handoff epoch")
        );

        let mut changed = cert.clone();
        changed.attestation.next_committee_pubkey_set_hash[0] ^= 1;
        assert!(
            verify_certificate(&changed, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("next committee mismatch")
        );

        let mut changed = cert.clone();
        changed.attestation.items[0].1[0] ^= 1;
        assert!(
            verify_certificate(&changed, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("invalid handoff signature")
        );

        let mut changed = cert.clone();
        changed.signatures.pop();
        assert!(
            verify_certificate(&changed, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("below quorum")
        );

        let mut changed = cert.clone();
        changed.signatures.push(changed.signatures[0].clone());
        assert!(
            verify_certificate(&changed, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("duplicate handoff signer")
        );

        let outsider = NetworkKeyPair::generate(&mut thread_rng());
        let outsider_cert = sign_attestation(cert.attestation.clone(), &[outsider]);
        assert!(
            verify_certificate(&outsider_cert, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("outside original committee")
        );

        let mut attestation = cert.attestation.clone();
        attestation.items.pop();
        let incomplete = sign_attestation(attestation, &signers);
        assert!(
            verify_certificate(&incomplete, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("every original validator")
        );

        let mut attestation = cert.attestation;
        attestation.items.insert(0, attestation.items[0].clone());
        let duplicate = sign_attestation(attestation, &signers);
        assert!(
            verify_certificate(&duplicate, &committee, 6)
                .unwrap_err()
                .to_string()
                .contains("strictly sorted and unique")
        );
    }

    #[test]
    fn snapshot_checks_blob_binding_and_all_validators() {
        let (committee, signers) = committee_and_signers();
        let keys = decode_public_keys(LEGACY_FIXTURE).unwrap();
        let expected = expected_keys(&committee, &keys);
        let cert = certificate(&committee, &signers, LEGACY_FIXTURE);
        let digest = mpc_data_blob_hash(LEGACY_FIXTURE);
        let blobs = BTreeMap::from([(digest, LEGACY_FIXTURE.to_vec())]);
        assert_eq!(
            verify_snapshot(&cert, &committee, 6, &blobs).unwrap(),
            expected
        );
        assert!(
            verify_snapshot(&cert, &committee, 6, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("bundle missing")
        );
        let corrupt = BTreeMap::from([(digest, vec![0])]);
        assert!(
            verify_snapshot(&cert, &committee, 6, &corrupt)
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
    }

    #[test]
    fn changed_proof_bytes_do_not_change_key_identity() {
        let (committee, signers) = committee_and_signers();
        let expected = expected_keys(&committee, &decode_public_keys(LEGACY_FIXTURE).unwrap());
        let VersionedMPCData::V1(data) = bcs::from_bytes(LEGACY_FIXTURE).unwrap();
        let mut bundle: ValidatorEncryptionKeysAndProofs =
            bcs::from_bytes(&data.mpc_data_bytes()).unwrap();
        // A different proof changes the authenticated blob but leaves the key
        // identities untouched. Certificate authentication alone is insufficient.
        bundle.class_groups[0].1 = bundle.class_groups[1].1.clone();
        let blob = encode_bundle(&bundle);
        assert_ne!(
            mpc_data_blob_hash(&blob),
            mpc_data_blob_hash(LEGACY_FIXTURE)
        );
        let cert = certificate(&committee, &signers, &blob);
        let blobs = BTreeMap::from([(mpc_data_blob_hash(&blob), blob)]);
        let observed = verify_snapshot(&cert, &committee, 6, &blobs).unwrap();
        assert_eq!(observed, expected);
        let authority = committee
            .voting_rights
            .iter()
            .map(|(authority, _)| *authority)
            .min()
            .unwrap();
        assert_preservation(&expected[&authority], &observed[&authority], authority).unwrap();
        for (index, name) in KEY_NAMES.iter().enumerate() {
            let mut changed = observed[&authority].clone();
            changed[index][0] ^= 1;
            let error =
                assert_preservation(&expected[&authority], &changed, authority).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "validator {authority} {name} unexpectedly changed across the binary upgrade"
                )
            );
            eprintln!("key-preservation fault caught: {error}");
        }
    }
    #[test]
    fn checkpoint_requires_exact_epoch_selection_and_preparation() {
        let metrics = "ika_dwallet_mpc_validator_key_epoch{stage=\"selected\"} 6\nika_dwallet_mpc_validator_key_epoch{stage=\"prepared\"} 6";
        assert!(key_preparation_complete(metrics, 6).unwrap());
        assert!(!key_preparation_complete(metrics, 7).unwrap());
        assert!(!key_preparation_complete("", 6).unwrap());
        for stage in ["selected", "prepared"] {
            let pending = metrics.replace(&format!("{stage}\"}} 6"), &format!("{stage}\"}} -1"));
            assert!(!key_preparation_complete(&pending, 6).unwrap());
        }
        assert!(key_preparation_complete(&format!("{metrics}\n{metrics}"), 6).is_err());
    }
}
