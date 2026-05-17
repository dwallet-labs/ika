// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{GetMpcDataBlobRequest, MpcDataBlob, MpcDataBlobStorage, ValidatorMetadata};
use anemo::{Request, Response, Result, rpc::Status};
use std::sync::Arc;

pub struct Server<S> {
    pub(super) storage: Arc<S>,
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
}
