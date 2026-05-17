// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{
    AnnouncementRelayHandle, GetMpcDataBlobRequest, MpcDataBlob, MpcDataBlobStorage,
    SubmitMpcDataAnnouncementRequest, SubmitMpcDataAnnouncementResponse, ValidatorMetadata,
};
use anemo::{Request, Response, Result, rpc::Status};
use std::sync::Arc;

pub struct Server<S> {
    pub(super) storage: Arc<S>,
    pub(super) relay: Arc<AnnouncementRelayHandle>,
}

#[anemo::async_trait]
impl<S> ValidatorMetadata for Server<S>
where
    S: MpcDataBlobStorage,
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
}
