// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod adversarial;
pub mod batch_payment;
pub mod delegation;
pub mod expected_failure;
pub mod payload;
pub mod randomness;
pub mod shared_counter;
pub mod shared_object_deletion;
pub mod transfer_object;
pub mod workload;
pub mod workload_configuration;

use std::sync::Arc;

use crate::drivers::Interval;
use crate::workloads::payload::Payload;
use ika_types::base_types::{ObjectRef, IkaAddress};
use ika_types::crypto::AccountKeyPair;
use workload::*;

pub type GroupID = u32;

#[derive(Debug, Clone)]
pub struct WorkloadParams {
    pub group: GroupID,
    pub target_qps: u64,
    pub num_workers: u64,
    pub max_ops: u64,
    pub duration: Interval,
}

#[derive(Debug)]
pub struct WorkloadBuilderInfo {
    pub workload_params: WorkloadParams,
    pub workload_builder: Box<dyn WorkloadBuilder<dyn Payload>>,
}

#[derive(Debug)]
pub struct WorkloadInfo {
    pub workload_params: WorkloadParams,
    pub workload: Box<dyn Workload<dyn Payload>>,
}

pub type Gas = (ObjectRef, IkaAddress, Arc<AccountKeyPair>);

#[derive(Clone)]
pub struct GasCoinConfig {
    // amount of IKA to transfer to this gas coin
    pub amount: u64,
    // recipient of this gas coin
    pub address: IkaAddress,
    // recipient account key pair (useful for signing txns)
    pub keypair: Arc<AccountKeyPair>,
}
