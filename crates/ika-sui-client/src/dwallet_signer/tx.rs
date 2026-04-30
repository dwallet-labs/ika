// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! WalletContext-free transaction submission for the dWallet sign flow.
//!
//! Mirrors the PTB construction in [`crate::ika_dwallet_transactions`] for the
//! sign / global-presign / imported-key sign paths, but takes an `RpcClient` +
//! `SuiKeyPair` instead of a `WalletContext` so embedded signers don't need a
//! Sui CLI wallet config.

use anyhow::{Context, Result};
use ika_types::sui::{
    APPROVE_IMPORTED_KEY_MESSAGE_FUNCTION_NAME, APPROVE_MESSAGE_FUNCTION_NAME,
    DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME, REGISTER_SESSION_IDENTIFIER_FUNCTION_NAME,
    REQUEST_GLOBAL_PRESIGN_FUNCTION_NAME, REQUEST_IMPORTED_KEY_SIGN_AND_RETURN_ID_FUNCTION_NAME,
    REQUEST_SIGN_AND_RETURN_ID_FUNCTION_NAME, VERIFY_PRESIGN_CAP_FUNCTION_NAME,
};
use shared_crypto::intent::{Intent, IntentMessage};
use sui::fire_drill::get_gas_obj_ref;
use sui_json_rpc_types::{
    SuiTransactionBlockEffects, SuiTransactionBlockEffectsAPI, SuiTransactionBlockResponse,
};
use sui_rpc_api::Client as RpcClient;
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    crypto::{Signature, SuiKeyPair},
    object::Owner,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{
        Argument, CallArg, ObjectArg, SharedObjectMutability, Transaction, TransactionData,
    },
};

use crate::ika_dwallet_transactions::PaymentCoinArgs;

/// Resolve the dWallet 2PC-MPC coordinator as a shared `CallArg` without a `WalletContext`.
pub async fn coordinator_call_arg(
    rpc: &mut RpcClient,
    coordinator_object_id: ObjectID,
) -> Result<CallArg> {
    let owner = rpc
        .get_object(coordinator_object_id)
        .await
        .with_context(|| format!("failed to get coordinator object {coordinator_object_id}"))?
        .owner()
        .clone();
    let initial_shared_version = match owner {
        Owner::Shared {
            initial_shared_version,
        } => initial_shared_version,
        _ => anyhow::bail!("Coordinator object {coordinator_object_id} is not a shared object"),
    };
    Ok(CallArg::Object(ObjectArg::SharedObject {
        id: coordinator_object_id,
        initial_shared_version,
        mutability: SharedObjectMutability::Mutable,
    }))
}

/// Resolve [`PaymentCoinArgs`] into PTB inputs using only an [`RpcClient`].
pub async fn resolve_payment_coins(
    coins: &PaymentCoinArgs,
    ptb: &mut ProgrammableTransactionBuilder,
    rpc: &RpcClient,
) -> Result<(Argument, Argument)> {
    let ika_coin_ref = rpc
        .transaction_builder()
        .get_object_ref(coins.ika_coin_id)
        .await?;
    let ika = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(ika_coin_ref)))?;
    let sui = match coins.sui_coin_id {
        Some(id) => {
            let r = rpc.transaction_builder().get_object_ref(id).await?;
            ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(r)))?
        }
        None => Argument::GasCoin,
    };
    Ok((ika, sui))
}

/// Build an unsigned transaction without WalletContext (no dry-run; pass an explicit gas budget).
pub async fn build_tx_data(
    rpc: &RpcClient,
    sender: SuiAddress,
    ptb: ProgrammableTransactionBuilder,
    gas_budget: u64,
) -> Result<TransactionData> {
    let tx = ptb.finish();
    let rgp = rpc.get_reference_gas_price().await?;
    let gas_obj_ref = get_gas_obj_ref(sender, rpc, gas_budget).await?;
    Ok(TransactionData::new_programmable(
        sender,
        vec![gas_obj_ref],
        tx,
        gas_budget,
        rgp,
    ))
}

/// Sign a `TransactionData` with a `SuiKeyPair` and execute via the RPC client.
pub async fn sign_and_execute(
    keypair: &SuiKeyPair,
    rpc: &RpcClient,
    tx_data: TransactionData,
) -> Result<SuiTransactionBlockResponse> {
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data.clone());
    let signature = Signature::new_secure(&intent_msg, keypair);
    let tx = Transaction::from_data(tx_data, vec![signature]);
    let executed = rpc.execute_transaction_and_wait_for_checkpoint(&tx).await?;
    let effects: SuiTransactionBlockEffects = executed
        .effects
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to convert effects: {e}"))?;
    Ok(SuiTransactionBlockResponse {
        digest: *effects.transaction_digest(),
        effects: Some(effects),
        ..Default::default()
    })
}

// -----------------------------------------------------------------------------
// PTB helpers — duplicated from ika_dwallet_transactions because that module's
// helpers are pure (`&mut ptb`) but live alongside WalletContext code; importing
// them here keeps the call sites readable. If those helpers ever take rpc/context
// they should be re-pointed here.
// -----------------------------------------------------------------------------

fn register_session_identifier(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator: Argument,
    user_bytes: &[u8],
    package_id: ObjectID,
) -> Result<Argument> {
    let user_bytes_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&user_bytes.to_vec())?))?;
    Ok(ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REGISTER_SESSION_IDENTIFIER_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator, user_bytes_arg],
    ))
}

fn approve_message(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator: Argument,
    dwallet_cap: Argument,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: &[u8],
    package_id: ObjectID,
) -> Result<Argument> {
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;
    let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&hash_scheme)?))?;
    let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&message.to_vec())?))?;
    Ok(ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        APPROVE_MESSAGE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            dwallet_cap,
            sig_algo_arg,
            hash_scheme_arg,
            message_arg,
        ],
    ))
}

fn approve_imported_key_message(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator: Argument,
    imported_key_dwallet_cap: Argument,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: &[u8],
    package_id: ObjectID,
) -> Result<Argument> {
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;
    let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&hash_scheme)?))?;
    let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&message.to_vec())?))?;
    Ok(ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        APPROVE_IMPORTED_KEY_MESSAGE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            imported_key_dwallet_cap,
            sig_algo_arg,
            hash_scheme_arg,
            message_arg,
        ],
    ))
}

// -----------------------------------------------------------------------------
// Sign / presign tx builders — each takes (rpc, sui_keypair, sender, …).
// -----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn request_sign_tx_with_signer(
    rpc: &mut RpcClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    package_id: ObjectID,
    coordinator_object_id: ObjectID,
    dwallet_cap_id: ObjectID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    verified_presign_cap_id: ObjectID,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
    verify_presign: bool,
) -> Result<SuiTransactionBlockResponse> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let coordinator_arg = coordinator_call_arg(rpc, coordinator_object_id).await?;
    let coordinator = ptb.input(coordinator_arg)?;

    let session_id =
        register_session_identifier(&mut ptb, coordinator, &session_identifier_bytes, package_id)?;

    let dwallet_cap_ref = rpc
        .transaction_builder()
        .get_object_ref(dwallet_cap_id)
        .await?;
    let dwallet_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        dwallet_cap_ref,
    )))?;

    let message_approval = approve_message(
        &mut ptb,
        coordinator,
        dwallet_cap_arg,
        signature_algorithm,
        hash_scheme,
        &message,
        package_id,
    )?;

    let presign_cap_ref = rpc
        .transaction_builder()
        .get_object_ref(verified_presign_cap_id)
        .await?;
    let presign_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;
    let presign_cap_arg = if verify_presign {
        ptb.programmable_move_call(
            package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            VERIFY_PRESIGN_CAP_FUNCTION_NAME.to_owned(),
            vec![],
            vec![coordinator, presign_cap_input],
        )
    } else {
        presign_cap_input
    };

    let centralized_sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &message_centralized_signature,
    )?))?;

    let (ika_coin_arg, sui_coin_arg) = resolve_payment_coins(&coins, &mut ptb, rpc).await?;

    ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_SIGN_AND_RETURN_ID_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            presign_cap_arg,
            message_approval,
            centralized_sig_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let tx_data = build_tx_data(rpc, sender, ptb, gas_budget).await?;
    sign_and_execute(keypair, rpc, tx_data).await
}

#[allow(clippy::too_many_arguments)]
pub async fn request_imported_key_sign_tx_with_signer(
    rpc: &mut RpcClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    package_id: ObjectID,
    coordinator_object_id: ObjectID,
    dwallet_cap_id: ObjectID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    verified_presign_cap_id: ObjectID,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
    verify_presign: bool,
) -> Result<SuiTransactionBlockResponse> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let coordinator_arg = coordinator_call_arg(rpc, coordinator_object_id).await?;
    let coordinator = ptb.input(coordinator_arg)?;

    let session_id =
        register_session_identifier(&mut ptb, coordinator, &session_identifier_bytes, package_id)?;

    let dwallet_cap_ref = rpc
        .transaction_builder()
        .get_object_ref(dwallet_cap_id)
        .await?;
    let dwallet_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        dwallet_cap_ref,
    )))?;

    let message_approval = approve_imported_key_message(
        &mut ptb,
        coordinator,
        dwallet_cap_arg,
        signature_algorithm,
        hash_scheme,
        &message,
        package_id,
    )?;

    let presign_cap_ref = rpc
        .transaction_builder()
        .get_object_ref(verified_presign_cap_id)
        .await?;
    let presign_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;
    let presign_cap_arg = if verify_presign {
        ptb.programmable_move_call(
            package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            VERIFY_PRESIGN_CAP_FUNCTION_NAME.to_owned(),
            vec![],
            vec![coordinator, presign_cap_input],
        )
    } else {
        presign_cap_input
    };

    let centralized_sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &message_centralized_signature,
    )?))?;

    let (ika_coin_arg, sui_coin_arg) = resolve_payment_coins(&coins, &mut ptb, rpc).await?;

    ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_IMPORTED_KEY_SIGN_AND_RETURN_ID_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            presign_cap_arg,
            message_approval,
            centralized_sig_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let tx_data = build_tx_data(rpc, sender, ptb, gas_budget).await?;
    sign_and_execute(keypair, rpc, tx_data).await
}

#[allow(clippy::too_many_arguments)]
pub async fn request_global_presign_tx_with_signer(
    rpc: &mut RpcClient,
    keypair: &SuiKeyPair,
    sender: SuiAddress,
    package_id: ObjectID,
    coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    signature_algorithm: u32,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let coordinator_arg = coordinator_call_arg(rpc, coordinator_object_id).await?;
    let coordinator = ptb.input(coordinator_arg)?;

    let session_id =
        register_session_identifier(&mut ptb, coordinator, &session_identifier_bytes, package_id)?;

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;

    let (ika_coin_arg, sui_coin_arg) = resolve_payment_coins(&coins, &mut ptb, rpc).await?;

    let presign_cap = ptb.programmable_move_call(
        package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_GLOBAL_PRESIGN_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            encryption_key_id_arg,
            curve_arg,
            sig_algo_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    ptb.transfer_arg(sender, presign_cap);

    let tx_data = build_tx_data(rpc, sender, ptb, gas_budget).await?;
    sign_and_execute(keypair, rpc, tx_data).await
}
