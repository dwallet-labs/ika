// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch handoff cert storage and fetch. Joiners walk the
//! certs in epoch order to bootstrap their off-chain artifact view.

use anemo::{Network, PeerId};
use ika_types::committee::EpochId;
use ika_types::handoff::CertifiedHandoffAttestation;
use serde::{Deserialize, Serialize};

use super::ValidatorMetadataClient;

/// Asks for the `CertifiedHandoffAttestation` covering `epoch` — i.e.,
/// the cert produced by the committee that was active *during*
/// `epoch`, attesting to the handoff into `epoch + 1`. Joiners walk
/// these in epoch order to bootstrap their off-chain artifact view.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GetCertifiedHandoffAttestationRequest {
    pub epoch: EpochId,
}

/// Read-only lookup of certified handoff attestations by the epoch
/// they attest. Backed at runtime by
/// `AuthorityPerpetualTables::certified_handoff_attestations`;
/// returning `None` is "I don't have this epoch's cert", which is a
/// normal response for joiners asking about epochs the server is
/// too new to cover.
pub trait HandoffCertStorage: Send + Sync + 'static {
    fn get(&self, epoch: EpochId) -> Option<CertifiedHandoffAttestation>;
}

/// Fetch a `CertifiedHandoffAttestation` for `epoch` from `peer`.
/// Returns `Ok(None)` if the peer doesn't have a cert for that
/// epoch (it may be too new); `Err` is reserved for transport
/// failures. Callers MUST re-verify the returned cert against the
/// committee that produced it before trusting it — the network
/// layer doesn't.
pub async fn fetch_certified_handoff_attestation(
    network: &Network,
    peer_id: PeerId,
    epoch: EpochId,
) -> anyhow::Result<Option<CertifiedHandoffAttestation>> {
    let peer = network
        .peer(peer_id)
        .ok_or_else(|| anyhow::anyhow!("peer not connected: {peer_id}"))?;
    let mut client = ValidatorMetadataClient::new(peer);
    let response = client
        .get_certified_handoff_attestation(GetCertifiedHandoffAttestationRequest { epoch })
        .await
        .map_err(|status| {
            anyhow::anyhow!("get_certified_handoff_attestation failed: {status:?}")
        })?;
    Ok(response.into_inner())
}
