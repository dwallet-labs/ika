// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Transaction builders for dWallet coordinator operations.
//!
//! These functions construct and execute Sui programmable transactions
//! that call into the `coordinator` Move module for dWallet operations
//! (DKG, presign, sign, encryption key management, share management).

use anyhow::Error;
use ika_types::sui::{
    ACCEPT_ENCRYPTED_USER_SHARE_FUNCTION_NAME, APPROVE_IMPORTED_KEY_MESSAGE_FUNCTION_NAME,
    APPROVE_MESSAGE_FUNCTION_NAME, DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME,
    REGISTER_ENCRYPTION_KEY_FUNCTION_NAME, REGISTER_SESSION_IDENTIFIER_FUNCTION_NAME,
    REQUEST_DWALLET_DKG_FUNCTION_NAME,
    REQUEST_DWALLET_DKG_WITH_PUBLIC_USER_SECRET_KEY_SHARE_FUNCTION_NAME,
    REQUEST_FUTURE_SIGN_FUNCTION_NAME, REQUEST_GLOBAL_PRESIGN_FUNCTION_NAME,
    REQUEST_IMPORTED_KEY_DWALLET_VERIFICATION_FUNCTION_NAME,
    REQUEST_IMPORTED_KEY_SIGN_AND_RETURN_ID_FUNCTION_NAME,
    REQUEST_MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_FUNCTION_NAME,
    REQUEST_PRESIGN_FUNCTION_NAME, REQUEST_RE_ENCRYPT_USER_SHARE_FOR_FUNCTION_NAME,
    REQUEST_SIGN_AND_RETURN_ID_FUNCTION_NAME,
    REQUEST_SIGN_WITH_PARTIAL_USER_SIGNATURE_AND_RETURN_ID_FUNCTION_NAME,
    SIGN_DURING_DKG_REQUEST_FUNCTION_NAME, VERIFY_PARTIAL_USER_SIGNATURE_CAP_FUNCTION_NAME,
    VERIFY_PRESIGN_CAP_FUNCTION_NAME,
};
use sui_json_rpc_types::SuiTransactionBlockResponse;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{Argument, CallArg, ObjectArg};

use crate::ika_validator_transactions::{
    construct_unsigned_txn, execute_transaction, get_dwallet_2pc_mpc_coordinator_call_arg,
};

/// Payment coin arguments for dWallet coordinator transactions.
///
/// `ika_coin_id` is always required (auto-detected by the CLI when not provided).
/// `sui_coin_id` is optional — when `None`, the transaction's gas coin is used
/// directly for SUI payment (matching the TypeScript SDK pattern of passing
/// `transaction.gas` as the SUI coin).
pub struct PaymentCoinArgs {
    pub ika_coin_id: ObjectID,
    pub sui_coin_id: Option<ObjectID>,
}

impl PaymentCoinArgs {
    /// Resolve both coins into PTB `Argument`s.
    async fn resolve(
        &self,
        ptb: &mut ProgrammableTransactionBuilder,
        context: &WalletContext,
    ) -> Result<(Argument, Argument), Error> {
        let client = context.grpc_client()?;
        let ika_coin_ref = client
            .transaction_builder()
            .get_object_ref(self.ika_coin_id)
            .await?;
        let ika_coin_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(ika_coin_ref)))?;
        let sui_coin_arg = match self.sui_coin_id {
            Some(id) => {
                let sui_coin_ref = client.transaction_builder().get_object_ref(id).await?;
                ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(sui_coin_ref)))?
            }
            None => Argument::GasCoin,
        };
        Ok((ika_coin_arg, sui_coin_arg))
    }
}

/// Register a session identifier on the coordinator.
///
/// Returns the `SessionIdentifier` Move object as a PTB `Argument` so it can
/// be composed into multi-step transactions (DKG, presign, sign, etc.).
pub fn register_session_identifier(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator_arg: Argument,
    session_identifier_bytes: &[u8],
    ika_dwallet_2pc_mpc_package_id: ObjectID,
) -> Result<Argument, Error> {
    let bytes_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &session_identifier_bytes.to_vec(),
    )?))?;

    Ok(ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REGISTER_SESSION_IDENTIFIER_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator_arg, bytes_arg],
    ))
}

/// Register a user encryption key on the coordinator.
pub async fn register_encryption_key(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    curve: u32,
    encryption_key: Vec<u8>,
    encryption_key_signature: Vec<u8>,
    signer_public_key: Vec<u8>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let encryption_key_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&encryption_key)?))?;
    let encryption_key_sig_arg =
        ptb.input(CallArg::Pure(bcs::to_bytes(&encryption_key_signature)?))?;
    let signer_pk_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signer_public_key)?))?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REGISTER_ENCRYPTION_KEY_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            curve_arg,
            encryption_key_arg,
            encryption_key_sig_arg,
            signer_pk_arg,
        ],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request dWallet DKG (encrypted user secret key share variant).
///
/// This is the primary DKG flow where the user's secret share is encrypted.
/// Returns the transaction response; the `DWalletCap` is extracted from created objects.
#[allow(clippy::too_many_arguments)]
pub async fn request_dwallet_dkg(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    centralized_public_key_share_and_proof: Vec<u8>,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    encryption_key_address: SuiAddress,
    user_public_output: Vec<u8>,
    signer_public_key: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    sign_during_dkg: Option<SignDuringDkgParams>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Build sign_during_dkg_request Option
    let sign_during_dkg_arg = match sign_during_dkg {
        Some(params) => {
            // Get the verified presign cap as owned object
            let client = context.grpc_client()?;
            let presign_cap_ref = client
                .transaction_builder()
                .get_object_ref(params.presign_cap_id)
                .await?;
            let presign_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
                presign_cap_ref,
            )))?;

            let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&params.hash_scheme)?))?;
            let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&params.message)?))?;
            let centralized_sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
                &params.message_centralized_signature,
            )?))?;

            let sign_req = ptb.programmable_move_call(
                ika_dwallet_2pc_mpc_package_id,
                DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
                SIGN_DURING_DKG_REQUEST_FUNCTION_NAME.to_owned(),
                vec![],
                vec![
                    coordinator,
                    presign_cap_arg,
                    hash_scheme_arg,
                    message_arg,
                    centralized_sig_arg,
                ],
            );

            // Wrap in Option::some
            build_option_some(&mut ptb, sign_req, ika_dwallet_2pc_mpc_package_id)?
        }
        None => build_option_none(&mut ptb, ika_dwallet_2pc_mpc_package_id)?,
    };

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let pub_key_share_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &centralized_public_key_share_and_proof,
    )?))?;
    let enc_secret_share_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &encrypted_centralized_secret_share_and_proof,
    )?))?;
    let encryption_key_addr_arg =
        ptb.input(CallArg::Pure(bcs::to_bytes(&encryption_key_address)?))?;
    let user_public_output_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&user_public_output)?))?;
    let signer_pk_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signer_public_key)?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let dwallet_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_DWALLET_DKG_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            encryption_key_id_arg,
            curve_arg,
            pub_key_share_arg,
            enc_secret_share_arg,
            encryption_key_addr_arg,
            user_public_output_arg,
            signer_pk_arg,
            sign_during_dkg_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    // Transfer DWalletCap to sender (first element of the returned tuple)
    let Argument::Result(cap_idx) = dwallet_cap else {
        anyhow::bail!("Failed to get result index from DKG call");
    };
    ptb.transfer_arg(sender, Argument::NestedResult(cap_idx, 0));

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request dWallet DKG with public user secret key share variant.
#[allow(clippy::too_many_arguments)]
pub async fn request_dwallet_dkg_with_public_share(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    centralized_public_key_share_and_proof: Vec<u8>,
    user_public_output: Vec<u8>,
    public_user_secret_key_share: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    sign_during_dkg: Option<SignDuringDkgParams>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let sign_during_dkg_arg = match sign_during_dkg {
        Some(params) => {
            let client = context.grpc_client()?;
            let presign_cap_ref = client
                .transaction_builder()
                .get_object_ref(params.presign_cap_id)
                .await?;
            let presign_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
                presign_cap_ref,
            )))?;
            let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&params.hash_scheme)?))?;
            let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&params.message)?))?;
            let centralized_sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
                &params.message_centralized_signature,
            )?))?;
            let sign_req = ptb.programmable_move_call(
                ika_dwallet_2pc_mpc_package_id,
                DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
                SIGN_DURING_DKG_REQUEST_FUNCTION_NAME.to_owned(),
                vec![],
                vec![
                    coordinator,
                    presign_cap_arg,
                    hash_scheme_arg,
                    message_arg,
                    centralized_sig_arg,
                ],
            );
            build_option_some(&mut ptb, sign_req, ika_dwallet_2pc_mpc_package_id)?
        }
        None => build_option_none(&mut ptb, ika_dwallet_2pc_mpc_package_id)?,
    };

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let pub_key_share_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &centralized_public_key_share_and_proof,
    )?))?;
    let user_public_output_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&user_public_output)?))?;
    let public_share_arg =
        ptb.input(CallArg::Pure(bcs::to_bytes(&public_user_secret_key_share)?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let dwallet_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_DWALLET_DKG_WITH_PUBLIC_USER_SECRET_KEY_SHARE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            encryption_key_id_arg,
            curve_arg,
            pub_key_share_arg,
            user_public_output_arg,
            public_share_arg,
            sign_during_dkg_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let Argument::Result(cap_idx) = dwallet_cap else {
        anyhow::bail!("Failed to get result index from DKG call");
    };
    ptb.transfer_arg(sender, Argument::NestedResult(cap_idx, 0));

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Approve a message for dWallet signing.
///
/// Returns the `MessageApproval` as a PTB `Argument` for composition with sign requests.
pub fn approve_message(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator_arg: Argument,
    dwallet_cap_arg: Argument,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: &[u8],
    ika_dwallet_2pc_mpc_package_id: ObjectID,
) -> Result<Argument, Error> {
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;
    let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&hash_scheme)?))?;
    let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&message.to_vec())?))?;

    Ok(ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        APPROVE_MESSAGE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator_arg,
            dwallet_cap_arg,
            sig_algo_arg,
            hash_scheme_arg,
            message_arg,
        ],
    ))
}

/// Request a presign for a dWallet.
///
/// Returns the `UnverifiedPresignCap` as a PTB `Argument` for composition.
#[allow(clippy::too_many_arguments)]
pub fn request_presign(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator_arg: Argument,
    dwallet_id: ObjectID,
    signature_algorithm: u32,
    session_id_arg: Argument,
    ika_coin_arg: Argument,
    sui_coin_arg: Argument,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
) -> Result<Argument, Error> {
    let dwallet_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&dwallet_id)?))?;
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;

    Ok(ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_PRESIGN_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator_arg,
            dwallet_id_arg,
            sig_algo_arg,
            session_id_arg,
            ika_coin_arg,
            sui_coin_arg,
        ],
    ))
}

/// Request a presign as a standalone transaction.
#[allow(clippy::too_many_arguments)]
pub async fn request_presign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    signature_algorithm: u32,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let presign_cap = request_presign(
        &mut ptb,
        coordinator,
        dwallet_id,
        signature_algorithm,
        session_id,
        ika_coin_arg,
        sui_coin_arg,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    ptb.transfer_arg(sender, presign_cap);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request multiple presigns for a dWallet in a single transaction.
///
/// Each presign gets its own session identifier. Returns one transaction with
/// all presign caps transferred to the sender.
#[allow(clippy::too_many_arguments)]
pub async fn request_batch_presign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    signature_algorithm: u32,
    session_identifier_bytes_list: Vec<Vec<u8>>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    for session_bytes in &session_identifier_bytes_list {
        let session_id = register_session_identifier(
            &mut ptb,
            coordinator,
            session_bytes,
            ika_dwallet_2pc_mpc_package_id,
        )?;

        let presign_cap = request_presign(
            &mut ptb,
            coordinator,
            dwallet_id,
            signature_algorithm,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
            ika_dwallet_2pc_mpc_package_id,
        )?;

        ptb.transfer_arg(sender, presign_cap);
    }

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request multiple global presigns in a single transaction.
#[allow(clippy::too_many_arguments)]
pub async fn request_batch_global_presign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    signature_algorithm: u32,
    session_identifier_bytes_list: Vec<Vec<u8>>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    for session_bytes in &session_identifier_bytes_list {
        let session_id = register_session_identifier(
            &mut ptb,
            coordinator,
            session_bytes,
            ika_dwallet_2pc_mpc_package_id,
        )?;

        let presign_cap = ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
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
    }

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request a global presign using network encryption key.
#[allow(clippy::too_many_arguments)]
pub async fn request_global_presign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    signature_algorithm: u32,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let presign_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
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

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Verify a presign capability.
pub async fn verify_presign_cap(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    presign_cap_id: ObjectID,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let client = context.grpc_client()?;
    let presign_cap_ref = client
        .transaction_builder()
        .get_object_ref(presign_cap_id)
        .await?;
    let presign_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;

    let verified_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        VERIFY_PRESIGN_CAP_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator, presign_cap_arg],
    );

    ptb.transfer_arg(sender, verified_cap);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request a sign operation (approve + optional verify + sign in one PTB).
///
/// When `verify_presign` is true, the presign cap is treated as unverified and
/// `verify_presign_cap` is called in the PTB before signing.
#[allow(clippy::too_many_arguments)]
pub async fn request_sign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
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
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Get dwallet_cap as owned object
    let client = context.grpc_client()?;
    let dwallet_cap_ref = client
        .transaction_builder()
        .get_object_ref(dwallet_cap_id)
        .await?;
    let dwallet_cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        dwallet_cap_ref,
    )))?;

    // Approve message
    let message_approval = approve_message(
        &mut ptb,
        coordinator,
        dwallet_cap_arg,
        signature_algorithm,
        hash_scheme,
        &message,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Get presign cap and optionally verify it in the PTB
    let presign_cap_ref = client
        .transaction_builder()
        .get_object_ref(verified_presign_cap_id)
        .await?;
    let presign_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;
    let presign_cap_arg = if verify_presign {
        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
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

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    // Request sign and return session ID
    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
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

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Approve an imported key message for signing.
///
/// Returns the `ImportedKeyMessageApproval` as a PTB `Argument` for composition with sign
/// requests.
pub fn approve_imported_key_message(
    ptb: &mut ProgrammableTransactionBuilder,
    coordinator_arg: Argument,
    imported_key_dwallet_cap_arg: Argument,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: &[u8],
    ika_dwallet_2pc_mpc_package_id: ObjectID,
) -> Result<Argument, Error> {
    let sig_algo_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signature_algorithm)?))?;
    let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&hash_scheme)?))?;
    let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&message.to_vec())?))?;

    Ok(ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        APPROVE_IMPORTED_KEY_MESSAGE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator_arg,
            imported_key_dwallet_cap_arg,
            sig_algo_arg,
            hash_scheme_arg,
            message_arg,
        ],
    ))
}

/// Request a sign operation for an imported key dWallet.
///
/// Uses `approve_imported_key_message` + `request_imported_key_sign_and_return_id` in one PTB.
/// When `verify_presign` is true, `verify_presign_cap` is called in the PTB before signing.
#[allow(clippy::too_many_arguments)]
pub async fn request_imported_key_sign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    imported_key_dwallet_cap_id: ObjectID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    verified_presign_cap_id: ObjectID,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
    verify_presign: bool,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Get imported key dwallet cap as owned object
    let client = context.grpc_client()?;
    let cap_ref = client
        .transaction_builder()
        .get_object_ref(imported_key_dwallet_cap_id)
        .await?;
    let cap_arg = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(cap_ref)))?;

    // Approve imported key message
    let message_approval = approve_imported_key_message(
        &mut ptb,
        coordinator,
        cap_arg,
        signature_algorithm,
        hash_scheme,
        &message,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Get presign cap and optionally verify it in the PTB
    let presign_cap_ref = client
        .transaction_builder()
        .get_object_ref(verified_presign_cap_id)
        .await?;
    let presign_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;
    let presign_cap_arg = if verify_presign {
        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
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

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    // Request imported key sign and return session ID
    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
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

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request a future sign (partial user signature flow).
///
/// When `verify_presign` is true, `verify_presign_cap` is called in the PTB before signing.
#[allow(clippy::too_many_arguments)]
pub async fn request_future_sign_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    verified_presign_cap_id: ObjectID,
    message: Vec<u8>,
    hash_scheme: u32,
    message_centralized_signature: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
    verify_presign: bool,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let dwallet_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&dwallet_id)?))?;

    let client = context.grpc_client()?;
    let presign_cap_ref = client
        .transaction_builder()
        .get_object_ref(verified_presign_cap_id)
        .await?;
    let presign_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        presign_cap_ref,
    )))?;
    let presign_cap_arg = if verify_presign {
        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            VERIFY_PRESIGN_CAP_FUNCTION_NAME.to_owned(),
            vec![],
            vec![coordinator, presign_cap_input],
        )
    } else {
        presign_cap_input
    };

    let message_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&message)?))?;
    let hash_scheme_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&hash_scheme)?))?;
    let centralized_sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &message_centralized_signature,
    )?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let partial_sig_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_FUTURE_SIGN_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            dwallet_id_arg,
            presign_cap_arg,
            message_arg,
            hash_scheme_arg,
            centralized_sig_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    ptb.transfer_arg(sender, partial_sig_cap);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request imported key dWallet verification.
#[allow(clippy::too_many_arguments)]
pub async fn request_imported_key_dwallet_verification(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: u32,
    centralized_party_message: Vec<u8>,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    encryption_key_address: SuiAddress,
    user_public_output: Vec<u8>,
    signer_public_key: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let encryption_key_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &dwallet_network_encryption_key_id,
    )?))?;
    let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
    let centralized_msg_arg =
        ptb.input(CallArg::Pure(bcs::to_bytes(&centralized_party_message)?))?;
    let enc_secret_share_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &encrypted_centralized_secret_share_and_proof,
    )?))?;
    let encryption_key_addr_arg =
        ptb.input(CallArg::Pure(bcs::to_bytes(&encryption_key_address)?))?;
    let user_public_output_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&user_public_output)?))?;
    let signer_pk_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&signer_public_key)?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    let imported_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_IMPORTED_KEY_DWALLET_VERIFICATION_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            encryption_key_id_arg,
            curve_arg,
            centralized_msg_arg,
            enc_secret_share_arg,
            encryption_key_addr_arg,
            user_public_output_arg,
            signer_pk_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    ptb.transfer_arg(sender, imported_cap);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request to make dWallet user secret key shares public.
#[allow(clippy::too_many_arguments)]
pub async fn request_make_shares_public(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    public_user_secret_key_shares: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let dwallet_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&dwallet_id)?))?;
    let shares_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &public_user_secret_key_shares,
    )?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            dwallet_id_arg,
            shares_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Request re-encryption of user share for a different address.
#[allow(clippy::too_many_arguments)]
pub async fn request_re_encrypt_user_share(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    destination_encryption_key_address: SuiAddress,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    source_encrypted_user_secret_key_share_id: ObjectID,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    let dwallet_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&dwallet_id)?))?;
    let dest_addr_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &destination_encryption_key_address,
    )?))?;
    let enc_share_proof_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &encrypted_centralized_secret_share_and_proof,
    )?))?;
    let source_share_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &source_encrypted_user_secret_key_share_id,
    )?))?;

    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_RE_ENCRYPT_USER_SHARE_FOR_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            dwallet_id_arg,
            dest_addr_arg,
            enc_share_proof_arg,
            source_share_id_arg,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Accept a re-encrypted user share.
pub async fn accept_encrypted_user_share(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_id: ObjectID,
    encrypted_user_secret_key_share_id: ObjectID,
    user_output_signature: Vec<u8>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let dwallet_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&dwallet_id)?))?;
    let share_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(
        &encrypted_user_secret_key_share_id,
    )?))?;
    let sig_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&user_output_signature)?))?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        ACCEPT_ENCRYPTED_USER_SHARE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator, dwallet_id_arg, share_id_arg, sig_arg],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Standalone approve message transaction (for composability outside of sign flow).
#[allow(clippy::too_many_arguments)]
pub async fn approve_message_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    dwallet_cap_id: ObjectID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: Vec<u8>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let client = context.grpc_client()?;
    let dwallet_cap_ref = client
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
        ika_dwallet_2pc_mpc_package_id,
    )?;

    ptb.transfer_arg(sender, message_approval);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Parameters for sign-during-DKG.
pub struct SignDuringDkgParams {
    pub presign_cap_id: ObjectID,
    pub hash_scheme: u32,
    pub message: Vec<u8>,
    pub message_centralized_signature: Vec<u8>,
}

/// Build an `Option::some(value)` in PTB using Move stdlib.
fn build_option_some(
    ptb: &mut ProgrammableTransactionBuilder,
    value: Argument,
    _package_id: ObjectID,
) -> Result<Argument, Error> {
    // Use Move stdlib option::some
    Ok(ptb.programmable_move_call(
        sui_types::MOVE_STDLIB_PACKAGE_ID,
        ika_types::sui::OPTION_MODULE_NAME.into(),
        move_core_types::ident_str!("some").to_owned(),
        // The type parameter will be inferred by Move VM from the value
        vec![],
        vec![value],
    ))
}

/// Build an `Option::none<SignDuringDKGRequest>()` in PTB using Move stdlib.
fn build_option_none(
    ptb: &mut ProgrammableTransactionBuilder,
    package_id: ObjectID,
) -> Result<Argument, Error> {
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::{StructTag, TypeTag};

    let sign_during_dkg_type = TypeTag::Struct(Box::new(StructTag {
        address: package_id.into(),
        module: Identifier::new("coordinator_inner").map_err(|e| anyhow::anyhow!("{e}"))?,
        name: Identifier::new("SignDuringDKGRequest").map_err(|e| anyhow::anyhow!("{e}"))?,
        type_params: vec![],
    }));

    Ok(ptb.programmable_move_call(
        sui_types::MOVE_STDLIB_PACKAGE_ID,
        ika_types::sui::OPTION_MODULE_NAME.into(),
        move_core_types::ident_str!("none").to_owned(),
        vec![sign_during_dkg_type],
        vec![],
    ))
}

/// Create a zero-value IKA coin and transfer it to the sender.
///
/// Used when no IKA coins exist in the wallet but the operation requires one
/// (e.g., zero-fee operations on localnet). The created coin persists in the
/// wallet and is reused by subsequent commands.
pub async fn create_zero_ika_coin(
    context: &mut WalletContext,
    ika_package_id: ObjectID,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::{StructTag, TypeTag};
    use sui_types::SUI_FRAMEWORK_PACKAGE_ID;

    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let ika_type = TypeTag::Struct(Box::new(StructTag {
        address: ika_package_id.into(),
        module: Identifier::new("ika").map_err(|e| anyhow::anyhow!("{e}"))?,
        name: Identifier::new("IKA").map_err(|e| anyhow::anyhow!("{e}"))?,
        type_params: vec![],
    }));

    let zero_coin = ptb.programmable_move_call(
        SUI_FRAMEWORK_PACKAGE_ID,
        Identifier::new("coin").map_err(|e| anyhow::anyhow!("{e}"))?,
        Identifier::new("zero").map_err(|e| anyhow::anyhow!("{e}"))?,
        vec![ika_type],
        vec![],
    );

    ptb.transfer_arg(sender, zero_coin);

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}

/// Fulfill a future sign: verify partial user signature cap + approve message + request sign.
///
/// This is the second step of the future-sign two-step flow. The first step (`request_future_sign_tx`)
/// creates the partial user signature cap. This function verifies it, creates a message approval,
/// and submits the final sign request.
#[allow(clippy::too_many_arguments)]
pub async fn request_future_sign_fulfill_tx(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    partial_user_signature_cap_id: ObjectID,
    dwallet_cap_id: ObjectID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: Vec<u8>,
    session_identifier_bytes: Vec<u8>,
    coins: PaymentCoinArgs,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let session_id = register_session_identifier(
        &mut ptb,
        coordinator,
        &session_identifier_bytes,
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Verify the partial user signature cap
    let client = context.grpc_client()?;
    let partial_cap_ref = client
        .transaction_builder()
        .get_object_ref(partial_user_signature_cap_id)
        .await?;
    let partial_cap_input = ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        partial_cap_ref,
    )))?;
    let verified_cap = ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        VERIFY_PARTIAL_USER_SIGNATURE_CAP_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator, partial_cap_input],
    );

    // Create message approval
    let dwallet_cap_ref = client
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
        ika_dwallet_2pc_mpc_package_id,
    )?;

    // Get coin refs
    let (ika_coin_arg, sui_coin_arg) = coins.resolve(&mut ptb, context).await?;

    // Request sign with partial user signature
    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        REQUEST_SIGN_WITH_PARTIAL_USER_SIGNATURE_AND_RETURN_ID_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            coordinator,
            verified_cap,
            message_approval,
            session_id,
            ika_coin_arg,
            sui_coin_arg,
        ],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;
    execute_transaction(context, tx_data).await
}
