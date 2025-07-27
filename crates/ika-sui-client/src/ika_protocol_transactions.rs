use crate::ika_validator_transactions;
use crate::ika_validator_transactions::{
    add_ika_system_command_to_ptb, construct_unsigned_txn,
    get_dwallet_2pc_mpc_coordinator_call_arg, new_pricing_info,
};
use fastcrypto::encoding::Base64;
use fastcrypto::encoding::Encoding;
use ika_types::messages_dwallet_mpc::DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME;
use ika_types::sui::{
    PricingInfoKey, PricingInfoValue, VEC_MAP_FROM_KEYS_VALUES_FUNCTION_NAME,
    VEC_MAP_INSERT_FUNCTION_NAME, VEC_MAP_MODULE_NAME, VEC_MAP_NEW_FUNCTION_NAME,
    VEC_MAP_STRUCT_NAME,
};
use move_core_types::ident_str;
use move_core_types::identifier::IdentStr;
use move_core_types::language_storage::{StructTag, TypeTag};
use std::collections::HashMap;
use sui_json_rpc_types::SuiTransactionBlockResponse;
use sui_sdk::wallet_context::WalletContext;
use sui_types::SUI_FRAMEWORK_PACKAGE_ID;
use sui_types::base_types::ObjectID;
use sui_types::collection_types::Entry;
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{Argument, CallArg, ObjectArg};

const VERIFY_PROTOCOL_CAP_FUNCTION_NAME: &IdentStr = ident_str!("verify_protocol_cap");
const SET_PAUSED_CURVES_AND_SIGNATURE_ALGORITHMS_FUNCTION_NAME: &IdentStr =
    ident_str!("set_paused_curves_and_signature_algorithms");
const SET_APPROVED_UPGRADE_BY_CAP_FUNCTION_NAME: &IdentStr =
    ident_str!("set_approved_upgrade_by_cap");
const AUTHORIZE_UPGRADE_FUNCTION_NAME: &IdentStr = ident_str!("authorize_upgrade");
const COMMIT_UPGRADE_FUNCTION_NAME: &IdentStr = ident_str!("commit_upgrade");
const FINALIZE_UPGRADE_FUNCTION_NAME: &IdentStr = ident_str!("finalize_upgrade");
const TRY_MIGRATE_FUNCTION_NAME: &IdentStr = ident_str!("try_migrate");
const SET_SUPPORTED_AND_PRICING_FUNCTION_NAME: &IdentStr = ident_str!("set_supported_and_pricing");
const SET_GAS_FEE_REIMBURSEMENT_SUI_SYSTEM_CALL_VALUE_BY_CAP_FUNCTION_NAME: &IdentStr =
    ident_str!("set_gas_fee_reimbursement_sui_system_call_value_by_cap");

/// Set approved upgrade by cap
pub async fn set_approved_upgrade_by_cap(
    context: &mut WalletContext,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    protocol_cap_id: ObjectID,
    package_id: ObjectID,
    digest: Option<Vec<u8>>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let client = context.get_client().await?;
    let protocol_cap_ref = client
        .transaction_builder()
        .get_object_ref(protocol_cap_id)
        .await?;

    let mut ptb = ProgrammableTransactionBuilder::new();
    let package_id = ptb.input(CallArg::Pure(bcs::to_bytes(&package_id)?))?;
    let digest = ptb.input(CallArg::Pure(bcs::to_bytes(&digest)?))?;
    let call_args = vec![
        package_id,
        digest,
        ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
            protocol_cap_ref,
        )))?,
    ];

    let sender = context.active_address()?;

    add_ika_system_command_to_ptb(
        context,
        SET_APPROVED_UPGRADE_BY_CAP_FUNCTION_NAME,
        call_args,
        ika_system_object_id,
        ika_system_package_id,
        &mut ptb,
    )
    .await?;

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

/// Perform approved upgrade
pub async fn perform_approved_upgrade(
    context: &mut WalletContext,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_coordinator_object_id: ObjectID,
    package_id: ObjectID,
    modules: Vec<String>,
    dependencies: Vec<ObjectID>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();
    let package_id_arg = ptb.input(CallArg::Pure(bcs::to_bytes(&package_id)?))?;

    let sender = context.active_address()?;

    let authorized_upgrade = add_ika_system_command_to_ptb(
        context,
        AUTHORIZE_UPGRADE_FUNCTION_NAME,
        vec![package_id_arg],
        ika_system_object_id,
        ika_system_package_id,
        &mut ptb,
    )
    .await?;

    let Argument::Result(authorized_upgrade) = authorized_upgrade else {
        return Err(anyhow::anyhow!(
            "Expected an result argument form calling authorize upgrade"
        ));
    };

    let upgrade_ticket = Argument::NestedResult(authorized_upgrade, 0);
    let approver = Argument::NestedResult(authorized_upgrade, 1);

    let modules = modules
        .iter()
        .map(|m| Base64::decode(m))
        .collect::<Result<Vec<_>, _>>()?;

    let upgrade_recipient = ptb.upgrade(package_id, upgrade_ticket, dependencies, modules);

    add_ika_system_command_to_ptb(
        context,
        COMMIT_UPGRADE_FUNCTION_NAME,
        vec![upgrade_recipient, approver],
        ika_system_object_id,
        ika_system_package_id,
        &mut ptb,
    )
    .await?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(context, ika_dwallet_coordinator_object_id)
            .await?,
    )?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        COMMIT_UPGRADE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator, approver],
    );

    add_ika_system_command_to_ptb(
        context,
        FINALIZE_UPGRADE_FUNCTION_NAME,
        vec![approver],
        ika_system_object_id,
        ika_system_package_id,
        &mut ptb,
    )
    .await?;

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

/// Try to migrate the system to a new package
pub async fn try_migrate_system(
    context: &mut WalletContext,
    new_ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let sender = context.active_address()?;

    add_ika_system_command_to_ptb(
        context,
        TRY_MIGRATE_FUNCTION_NAME,
        vec![],
        ika_system_object_id,
        new_ika_system_package_id,
        &mut ptb,
    )
    .await?;

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

/// Try to migrate the coordinator to a new package
pub async fn try_migrate_coordinator(
    context: &mut WalletContext,
    new_ika_dwallet_2pc_mpc_package_id: ObjectID,
    ika_dwallet_coordinator_object_id: ObjectID,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let sender = context.active_address()?;

    let coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(context, ika_dwallet_coordinator_object_id)
            .await?,
    )?;

    ptb.programmable_move_call(
        new_ika_dwallet_2pc_mpc_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        TRY_MIGRATE_FUNCTION_NAME.to_owned(),
        vec![],
        vec![coordinator],
    );

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

/// Set paused curves and signature algorithms
pub async fn set_paused_curves_and_signature_algorithms(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_coordinator_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    protocol_cap_id: ObjectID,
    paused_curves: Vec<u32>,
    paused_signature_algorithms: Vec<u32>,
    paused_hash_schemes: Vec<u32>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let verified_protocol_cap = get_verified_protocol_cap(
        context,
        ika_system_package_id,
        ika_system_object_id,
        protocol_cap_id,
        &mut ptb,
    )
    .await?;

    let paused_curves = ptb.input(CallArg::Pure(bcs::to_bytes(&paused_curves)?))?;
    let paused_signature_algorithms =
        ptb.input(CallArg::Pure(bcs::to_bytes(&paused_signature_algorithms)?))?;
    let paused_hash_schemes = ptb.input(CallArg::Pure(bcs::to_bytes(&paused_hash_schemes)?))?;

    let dwallet_2pc_mpc_coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let args = vec![
        dwallet_2pc_mpc_coordinator,
        paused_curves,
        paused_signature_algorithms,
        paused_hash_schemes,
        verified_protocol_cap,
    ];

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_coordinator_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        SET_PAUSED_CURVES_AND_SIGNATURE_ALGORITHMS_FUNCTION_NAME.to_owned(),
        vec![],
        args,
    );

    let sender = context.active_address()?;

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

/// Set supported and pricing
pub async fn set_supported_and_pricing(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_coordinator_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    protocol_cap_id: ObjectID,
    default_pricing: Vec<Entry<PricingInfoKey, PricingInfoValue>>,
    supported_curves_to_signature_algorithms_to_hash_schemes: HashMap<u32, HashMap<u32, Vec<u32>>>,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let verified_protocol_cap = get_verified_protocol_cap(
        context,
        ika_system_package_id,
        ika_system_object_id,
        protocol_cap_id,
        &mut ptb,
    )
    .await?;

    let default_pricing = new_pricing_info(
        ika_dwallet_2pc_mpc_coordinator_package_id,
        default_pricing,
        &mut ptb,
    )
    .await?;

    let supported_curves_to_signature_algorithms_to_hash_schemes =
        new_supported_curves_to_signature_algorithms_to_hash_schemes_argument(
            &mut ptb,
            supported_curves_to_signature_algorithms_to_hash_schemes,
        )?;

    let dwallet_2pc_mpc_coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    let args = vec![
        dwallet_2pc_mpc_coordinator,
        default_pricing,
        supported_curves_to_signature_algorithms_to_hash_schemes,
        verified_protocol_cap,
    ];
    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_coordinator_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        SET_SUPPORTED_AND_PRICING_FUNCTION_NAME.to_owned(),
        vec![],
        args,
    );

    let sender = context.active_address()?;

    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

pub async fn set_gas_fee_reimbursement_sui_system_call_value_by_cap(
    context: &mut WalletContext,
    ika_dwallet_2pc_mpc_coordinator_package_id: ObjectID,
    ika_dwallet_2pc_mpc_coordinator_object_id: ObjectID,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    protocol_cap_id: ObjectID,
    gas_fee_reimbursement_sui_system_call_value: u64,
    gas_budget: u64,
) -> Result<SuiTransactionBlockResponse, anyhow::Error> {
    let mut ptb = ProgrammableTransactionBuilder::new();

    let verified_protocol_cap = get_verified_protocol_cap(
        context,
        ika_system_package_id,
        ika_system_object_id,
        protocol_cap_id,
        &mut ptb,
    )
    .await?;

    let gas_fee_reimbursement_sui_system_call_value = ptb.input(CallArg::Pure(bcs::to_bytes(
        &gas_fee_reimbursement_sui_system_call_value,
    )?))?;

    let dwallet_2pc_mpc_coordinator = ptb.input(
        get_dwallet_2pc_mpc_coordinator_call_arg(
            context,
            ika_dwallet_2pc_mpc_coordinator_object_id,
        )
        .await?,
    )?;

    ptb.programmable_move_call(
        ika_dwallet_2pc_mpc_coordinator_package_id,
        DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
        SET_GAS_FEE_REIMBURSEMENT_SUI_SYSTEM_CALL_VALUE_BY_CAP_FUNCTION_NAME.to_owned(),
        vec![],
        vec![
            dwallet_2pc_mpc_coordinator,
            gas_fee_reimbursement_sui_system_call_value,
            verified_protocol_cap,
        ],
    );

    let sender = context.active_address()?;
    let tx_data = construct_unsigned_txn(context, sender, gas_budget, ptb).await?;

    ika_validator_transactions::execute_transaction(context, tx_data).await
}

fn new_supported_curves_to_signature_algorithms_to_hash_schemes_argument(
    ptb: &mut ProgrammableTransactionBuilder,
    supported_curves_to_signature_algorithms_to_hash_schemes: HashMap<u32, HashMap<u32, Vec<u32>>>,
) -> anyhow::Result<Argument> {
    let supported_curves_to_signature_algorithms_to_hash_schemes_arg = ptb.programmable_move_call(
        SUI_FRAMEWORK_PACKAGE_ID,
        VEC_MAP_MODULE_NAME.into(),
        VEC_MAP_NEW_FUNCTION_NAME.into(),
        vec![
            TypeTag::U32,
            TypeTag::Struct(Box::new(StructTag {
                address: SUI_FRAMEWORK_PACKAGE_ID.into(),
                module: VEC_MAP_MODULE_NAME.into(),
                name: VEC_MAP_STRUCT_NAME.into(),
                type_params: vec![TypeTag::U32, TypeTag::Vector(Box::new(TypeTag::U32))],
            })),
        ],
        vec![],
    );

    supported_curves_to_signature_algorithms_to_hash_schemes
        .into_iter()
        .try_for_each(|(curve, signature_algorithms_to_hash_schemes)| {
            let (keys, values): (Vec<u32>, Vec<Vec<u32>>) =
                signature_algorithms_to_hash_schemes.into_iter().unzip();
            let keys = ptb.input(CallArg::Pure(bcs::to_bytes(&keys)?))?;
            let values = ptb.input(CallArg::Pure(bcs::to_bytes(&values)?))?;

            let signature_algorithms_to_hash_schemes_arg = ptb.programmable_move_call(
                SUI_FRAMEWORK_PACKAGE_ID,
                VEC_MAP_MODULE_NAME.into(),
                VEC_MAP_FROM_KEYS_VALUES_FUNCTION_NAME.into(),
                vec![TypeTag::U32, TypeTag::Vector(Box::new(TypeTag::U32))],
                vec![keys, values],
            );

            let key = ptb.input(CallArg::Pure(bcs::to_bytes(&curve)?))?;
            ptb.programmable_move_call(
                SUI_FRAMEWORK_PACKAGE_ID,
                VEC_MAP_MODULE_NAME.into(),
                VEC_MAP_INSERT_FUNCTION_NAME.into(),
                vec![
                    TypeTag::U32,
                    TypeTag::Struct(Box::new(StructTag {
                        address: SUI_FRAMEWORK_PACKAGE_ID.into(),
                        module: VEC_MAP_MODULE_NAME.into(),
                        name: VEC_MAP_STRUCT_NAME.into(),
                        type_params: vec![TypeTag::U32, TypeTag::Vector(Box::new(TypeTag::U32))],
                    })),
                ],
                vec![
                    supported_curves_to_signature_algorithms_to_hash_schemes_arg,
                    key,
                    signature_algorithms_to_hash_schemes_arg,
                ],
            );

            Ok::<(), anyhow::Error>(())
        })?;

    Ok(supported_curves_to_signature_algorithms_to_hash_schemes_arg)
}

async fn get_verified_protocol_cap(
    context: &mut WalletContext,
    ika_system_package_id: ObjectID,
    ika_system_object_id: ObjectID,
    protocol_cap_id: ObjectID,
    ptb: &mut ProgrammableTransactionBuilder,
) -> Result<Argument, anyhow::Error> {
    let client = context.get_client().await?;
    let protocol_cap_ref = client
        .transaction_builder()
        .get_object_ref(protocol_cap_id)
        .await?;

    let args = vec![ptb.input(CallArg::Object(ObjectArg::ImmOrOwnedObject(
        protocol_cap_ref,
    )))?];

    add_ika_system_command_to_ptb(
        context,
        VERIFY_PROTOCOL_CAP_FUNCTION_NAME,
        args,
        ika_system_object_id,
        ika_system_package_id,
        ptb,
    )
    .await
}
