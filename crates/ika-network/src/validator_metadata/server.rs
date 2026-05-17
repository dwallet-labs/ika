// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{
    AnnouncementRelayHandle, GetCertifiedHandoffAttestationRequest, GetMpcDataBlobRequest,
    HandoffCertStorage, MpcDataBlob, MpcDataBlobStorage, SubmitMpcDataAnnouncementRequest,
    SubmitMpcDataAnnouncementResponse, ValidatorMetadata,
};
use anemo::{Request, Response, Result, rpc::Status};
use ika_types::handoff::CertifiedHandoffAttestation;
use std::sync::Arc;

pub struct Server<S, C> {
    pub(super) storage: Arc<S>,
    pub(super) relay: Arc<AnnouncementRelayHandle>,
    pub(super) cert_storage: Arc<C>,
}

#[anemo::async_trait]
impl<S, C> ValidatorMetadata for Server<S, C>
where
    S: MpcDataBlobStorage,
    C: HandoffCertStorage,
{
    async fn get_mpc_data_blob(
        &self,
        request: Request<GetMpcDataBlobRequest>,
    ) -> Result<Response<Option<MpcDataBlob>>, Status> {
        let blob = self
            .storage
            .get(&request.into_inner().blob_hash)
            .map(|bytes| MpcDataBlob { bytes });
        Ok(Response::new(blob))
    }

    async fn submit_mpc_data_announcement(
        &self,
        request: Request<SubmitMpcDataAnnouncementRequest>,
    ) -> Result<Response<SubmitMpcDataAnnouncementResponse>, Status> {
        let SubmitMpcDataAnnouncementRequest { announcement } = request.into_inner();
        let Some(relay) = self.relay.current() else {
            // Not yet armed — joiners get told to retry. We
            // explicitly do NOT return a transport error here; an
            // Anemo error would propagate as a peer fault.
            return Ok(Response::new(SubmitMpcDataAnnouncementResponse::Rejected {
                reason: "relay not installed".to_string(),
            }));
        };
        match relay.relay(announcement).await {
            Ok(()) => Ok(Response::new(SubmitMpcDataAnnouncementResponse::Accepted)),
            Err(reason) => Ok(Response::new(SubmitMpcDataAnnouncementResponse::Rejected {
                reason,
            })),
        }
    }

    async fn get_certified_handoff_attestation(
        &self,
        request: Request<GetCertifiedHandoffAttestationRequest>,
    ) -> Result<Response<Option<CertifiedHandoffAttestation>>, Status> {
        let GetCertifiedHandoffAttestationRequest { epoch } = request.into_inner();
        Ok(Response::new(self.cert_storage.get(epoch)))
    }
}
