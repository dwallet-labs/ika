// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Certified validator-key checkpoints for the fixed-committee v1.4.1 rollout.
//! Expected identities contain public keys only; proof bytes never identify a key.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::read_to_string;
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
use tokio::task::spawn_blocking;
use tokio::time::{Instant, sleep, timeout_at};

use crate::cluster::{required_labeled_metric, required_unlabeled_metric};
use crate::process::ValidatorProcess;

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeDecryptionKey, construct_setup_parameters_per_crt_prime,
};
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, RistrettoDecryptionKey, RistrettoSetupParameters,
    Secp256k1DecryptionKey, Secp256k1SetupParameters, Secp256r1DecryptionKey,
    Secp256r1SetupParameters,
};
use dwallet_rng::RootSeed;
use group::sampling::{LegacyCsRng, legacy_seeded_rng};
use group::{GroupElement as _, ristretto, secp256k1, secp256r1};
use mpc::hybrid_public_key_encryption::generate_encryption_keypair;

/// Harness-only comparison of deployed and current native key derivations.
/// Validators use the production derivation exclusively.
#[derive(Clone, Copy)]
enum ValidatorKeyDerivation {
    Current,
    Legacy,
}

/// Public key BCS values in bundle order: three CRT keys, secp256k1 PVSS,
/// secp256r1 PVSS, ristretto PVSS, VSS HPKE. No proofs are generated.
/// Current and Legacy VSS keys are expected to be identical for one root.
fn derive_public_keys_without_proofs(
    root: &RootSeed,
    derivation: ValidatorKeyDerivation,
) -> Result<[Vec<u8>; 7]> {
    let crt_setup =
        construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)?;
    // The CRT generator samples all three secrets sequentially BEFORE proving
    // any of them. Never re-seed this RNG separately for each CRT prime.
    let mut current_crt_rng = root.class_groups_decryption_key_rng();
    let mut legacy_crt_rng = legacy_seeded_rng(root.class_groups_decryption_key_seed());
    let [first_crt, second_crt, third_crt] = crt_setup.map(|setup| -> Result<Vec<u8>> {
        let (public_parameters, _) = match derivation {
            ValidatorKeyDerivation::Current => {
                SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters(
                    setup,
                    &mut current_crt_rng,
                )
            }
            ValidatorKeyDerivation::Legacy => {
                SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters_legacy(
                    setup,
                    &mut legacy_crt_rng,
                )
            }
        }?;
        Ok(bcs::to_bytes(&public_parameters.encryption_key.value())?)
    });

    let secp256k1_setup =
        Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )?;
    let (secp256k1_public, _) = match derivation {
        ValidatorKeyDerivation::Current => Secp256k1DecryptionKey::generate_with_setup_parameters(
            secp256k1_setup,
            &mut root.pvss_secp256k1_decryption_key_rng(),
        ),
        ValidatorKeyDerivation::Legacy => {
            Secp256k1DecryptionKey::generate_with_setup_parameters_legacy(
                secp256k1_setup,
                &mut legacy_seeded_rng(root.pvss_secp256k1_decryption_key_seed()),
            )
        }
    }?;

    let secp256r1_setup =
        Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
            secp256r1::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )?;
    let (secp256r1_public, _) = match derivation {
        ValidatorKeyDerivation::Current => Secp256r1DecryptionKey::generate_with_setup_parameters(
            secp256r1_setup,
            &mut root.pvss_secp256r1_decryption_key_rng(),
        ),
        ValidatorKeyDerivation::Legacy => {
            Secp256r1DecryptionKey::generate_with_setup_parameters_legacy(
                secp256r1_setup,
                &mut legacy_seeded_rng(root.pvss_secp256r1_decryption_key_seed()),
            )
        }
    }?;

    let ristretto_setup =
        RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )?;
    let (ristretto_public, _) = match derivation {
        ValidatorKeyDerivation::Current => RistrettoDecryptionKey::generate_with_setup_parameters(
            ristretto_setup,
            &mut root.pvss_ristretto_decryption_key_rng(),
        ),
        ValidatorKeyDerivation::Legacy => {
            RistrettoDecryptionKey::generate_with_setup_parameters_legacy(
                ristretto_setup,
                &mut legacy_seeded_rng(root.pvss_ristretto_decryption_key_seed()),
            )
        }
    }?;

    let (_, vss_public) = match derivation {
        ValidatorKeyDerivation::Current => {
            generate_encryption_keypair(&mut root.vss_hpke_secret_key_rng())
        }
        ValidatorKeyDerivation::Legacy => {
            let mut rng = legacy_seeded_rng(root.vss_hpke_secret_key_seed());
            generate_encryption_keypair(&mut LegacyCsRng(&mut rng))
        }
    }?;

    Ok([
        first_crt?,
        second_crt?,
        third_crt?,
        bcs::to_bytes(&secp256k1_public.encryption_key.value())?,
        bcs::to_bytes(&secp256r1_public.encryption_key.value())?,
        bcs::to_bytes(&ristretto_public.encryption_key.value())?,
        bcs::to_bytes(&vss_public.value())?,
    ])
}

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

struct ExpectedValidator {
    index: usize,
    authority: AuthorityName,
    peer: PeerId,
    address: SocketAddr,
    legacy: PublicKeys,
    current: PublicKeys,
}

/// Only public expected keys and the fixed original committee survive preparation.
/// A successful legacy checkpoint is required before checking the current keys.
pub(crate) struct ValidatorKeyPreservation {
    validators: Vec<ExpectedValidator>,
    committee: Committee,
    network: Network,
    baseline: Mutex<Option<BTreeMap<AuthorityName, PublicKeys>>>,
}

impl ValidatorKeyPreservation {
    pub(crate) async fn prepare(
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
        let validators = spawn_blocking(move || {
            configs
                .into_iter()
                .map(|(index, authority, config)| {
                    let root = config
                        .root_seed_key_pair
                        .as_ref()
                        .context("validator root seed missing")?
                        .try_root_seed()?;
                    let legacy =
                        derive_public_keys_without_proofs(root, ValidatorKeyDerivation::Legacy)?;
                    let current =
                        derive_public_keys_without_proofs(root, ValidatorKeyDerivation::Current)?;
                    assert_preservation(&legacy, &current, authority)?;
                    let address = config.p2p_config.listen_address;
                    let address = if address.ip().is_unspecified() {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
                    } else {
                        address
                    };
                    Ok(ExpectedValidator {
                        index,
                        authority,
                        peer: PeerId(config.network_key_pair().public().0.to_bytes()),
                        address,
                        legacy,
                        current,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .await
        .context("derive expected validator public keys")??;
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

    pub(crate) async fn assert_derivation(
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
                    ready &= validator_ready(process, validator.authority, active_epoch, current).await?;
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
                        let expected = self.validators.iter().map(|validator| (validator.authority, if current { validator.current.clone() } else { validator.legacy.clone() })).collect();
                        let observed = verify_snapshot(first, &self.committee, active_epoch, &expected, &blobs)?;
                        // All peers served the same authenticated attestation. Re-read
                        // every live epoch after the fetch to exclude an epoch-crossing snapshot.
                        for validator in &self.validators {
                            let process = &processes[validator.index];
                            ensure!(validator_ready(process, validator.authority, active_epoch, current).await?, "validator {} lost exact epoch {active_epoch} readiness during key checkpoint", validator.index);
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
    expected: &BTreeMap<AuthorityName, PublicKeys>,
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
            let expected = expected
                .get(&authority)
                .context("original validator expected identity missing")?;
            for (index, name) in KEY_NAMES.iter().enumerate() {
                ensure!(
                    actual[index] == expected[index],
                    "validator {authority} {name} does not match expected sampler"
                );
            }
            Ok((authority, actual))
        })
        .collect()
}

async fn validator_ready(
    process: &ValidatorProcess,
    authority: AuthorityName,
    epoch: u64,
    current: bool,
) -> Result<bool> {
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
        let log = read_to_string(process.log_path()).context("read validator key-selection log")?;
        if !selected_current(&log, authority, epoch)? {
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

fn selected_current(log: &str, authority: AuthorityName, epoch: u64) -> Result<bool> {
    let expected_authority = authority.to_string();
    let expected_epoch = epoch.to_string();
    for raw in log.lines().rev() {
        // Tracing's ANSI SGR sequences can appear when the child inherits color settings.
        let line = raw
            .split('\u{1b}')
            .map(|part| {
                part.strip_prefix('[')
                    .and_then(|part| part.split_once('m').map(|(_, text)| text))
                    .unwrap_or(part)
            })
            .collect::<String>();
        if !line.contains("selected validator key derivation from the certified handoff") {
            continue;
        }
        let fields: BTreeMap<_, _> = line
            .split_whitespace()
            .filter_map(|word| word.split_once('='))
            .collect();
        if fields.get("authority").copied() != Some(expected_authority.as_str())
            || fields.get("epoch").copied() != Some(expected_epoch.as_str())
        {
            continue;
        }
        ensure!(
            fields.get("derivation").copied() == Some("Current"),
            "validator {authority} selected legacy or unknown derivation in active epoch {epoch}"
        );
        return Ok(true);
    }
    Ok(false)
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
    fn snapshot_checks_blob_binding_and_every_public_key_slot() {
        let (committee, signers) = committee_and_signers();
        let keys = decode_public_keys(LEGACY_FIXTURE).unwrap();
        let expected = expected_keys(&committee, &keys);
        let cert = certificate(&committee, &signers, LEGACY_FIXTURE);
        let digest = mpc_data_blob_hash(LEGACY_FIXTURE);
        let blobs = BTreeMap::from([(digest, LEGACY_FIXTURE.to_vec())]);
        assert_eq!(
            verify_snapshot(&cert, &committee, 6, &expected, &blobs).unwrap(),
            expected
        );
        assert!(
            verify_snapshot(&cert, &committee, 6, &expected, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("bundle missing")
        );
        let corrupt = BTreeMap::from([(digest, vec![0])]);
        assert!(
            verify_snapshot(&cert, &committee, 6, &expected, &corrupt)
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
        let authority = committee
            .voting_rights
            .iter()
            .map(|(authority, _)| *authority)
            .min()
            .unwrap();
        for (index, name) in KEY_NAMES.iter().enumerate() {
            let mut changed = expected.clone();
            changed.get_mut(&authority).unwrap()[index][0] ^= 1;
            assert_eq!(
                verify_snapshot(&cert, &committee, 6, &changed, &blobs)
                    .unwrap_err()
                    .to_string(),
                format!("validator {authority} {name} does not match expected sampler")
            );
        }
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
        let observed = verify_snapshot(&cert, &committee, 6, &expected, &blobs).unwrap();
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
    #[cfg(target_pointer_width = "64")]
    fn frozen_legacy_bundle_matches_both_native_derivations() {
        let root = RootSeed::new([31; 32]);
        let legacy =
            derive_public_keys_without_proofs(&root, ValidatorKeyDerivation::Legacy).unwrap();
        let current =
            derive_public_keys_without_proofs(&root, ValidatorKeyDerivation::Current).unwrap();
        assert_eq!(legacy, decode_public_keys(LEGACY_FIXTURE).unwrap());
        let (committee, signers) = committee_and_signers();
        let authority = committee
            .voting_rights
            .iter()
            .map(|(authority, _)| *authority)
            .min()
            .unwrap();
        assert_preservation(&legacy, &current, authority).unwrap();
        let cert = certificate(&committee, &signers, LEGACY_FIXTURE);
        let blobs = BTreeMap::from([(mpc_data_blob_hash(LEGACY_FIXTURE), LEGACY_FIXTURE.to_vec())]);
        let legacy_expected = expected_keys(&committee, &legacy);
        assert_eq!(
            verify_snapshot(&cert, &committee, 6, &legacy_expected, &blobs).unwrap(),
            legacy_expected
        );
        let current_expected = expected_keys(&committee, &current);
        assert_eq!(
            verify_snapshot(&cert, &committee, 6, &current_expected, &blobs).unwrap(),
            current_expected
        );
    }

    #[test]
    fn selection_log_requires_exact_authority_epoch_and_current_mode() {
        let authority = AuthorityName([1; 32]);
        let other = AuthorityName([2; 32]);
        let message = "selected validator key derivation from the certified handoff";
        let current = format!("INFO {message} authority={authority:?} epoch=6 derivation=Current");
        assert!(selected_current(&current, authority, 6).unwrap());
        let colored = format!(
            "INFO {message} \u{1b}[3mauthority\u{1b}[0m\u{1b}[2m=\u{1b}[0m{authority:?} epoch=6 derivation=Current"
        );
        assert!(selected_current(&colored, authority, 6).unwrap());
        assert!(!selected_current(&current, authority, 60).unwrap());
        assert!(!selected_current(&current, other, 6).unwrap());
        let historical =
            format!("{current}\nINFO {message} authority={authority:?} epoch=60 derivation=Legacy");
        assert!(selected_current(&historical, authority, 6).unwrap());
        let legacy =
            format!("{current}\nINFO {message} authority={authority:?} epoch=6 derivation=Legacy");
        assert!(
            selected_current(&legacy, authority, 6)
                .unwrap_err()
                .to_string()
                .contains("selected legacy or unknown derivation")
        );
    }
}
