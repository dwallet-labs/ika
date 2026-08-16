// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Compatibility bridge from Sui core PTBs to the standalone transaction
//! builder.
//!
//! Ika's transaction constructors still expose Sui core arguments internally.
//! Replaying the completed PTB here moves input resolution, gas selection, and
//! simulation to `sui-transaction-builder` without requiring an all-at-once
//! rewrite of every protocol call site.

use sui_sdk_types::{Digest, Identifier};
use sui_transaction_builder::{
    Argument as SdkArgument, Error as SdkBuilderError, Function, ObjectInput, TransactionBuilder,
};
use sui_types::base_types::SuiAddress;
use sui_types::sui_sdk_types_conversions::type_tag_core_to_sdk;
use sui_types::transaction::{
    Argument, CallArg, Command, ObjectArg, ProgrammableTransaction, Reservation,
    SharedObjectMutability, TransactionData, TransactionDataAPI, TransactionKind, WithdrawFrom,
    WithdrawalTypeArg,
};

use crate::grpc::SuiGrpcClient;

enum CommandResult {
    None,
    Single(SdkArgument),
    Nested(Vec<SdkArgument>),
}

/// Builds a Sui core `TransactionData` through the standalone SDK builder.
pub async fn build_transaction_data(
    client: &SuiGrpcClient,
    sender: SuiAddress,
    _fallback_gas_budget: u64,
    programmable_transaction: ProgrammableTransaction,
) -> Result<TransactionData, TransactionBuildError> {
    let expected_program = replayed_program(sender, programmable_transaction.clone())?;
    let mut builder = replay(programmable_transaction)?;
    builder.set_sender(sender.into());
    // Leaving the budget unset asks the Sui simulation handler to estimate it.
    // The old Sui-main builder also treated the caller-provided budget as a
    // fallback, not as the authoritative budget.
    let transaction = client
        .build_transaction(builder)
        .await
        .map_err(TransactionBuildError::Builder)?;
    let transaction = TransactionData::try_from(transaction)
        .map_err(|error| TransactionBuildError::Conversion(error.to_string()))?;
    validate_transaction_program(&expected_program, &transaction)?;
    Ok(transaction)
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionBuildError {
    #[error("transaction builder failed: {0}")]
    Builder(SdkBuilderError),
    #[error("transaction conversion failed: {0}")]
    Conversion(String),
    #[error("transaction returned by the RPC endpoint does not match the locally built PTB")]
    ProgramMismatch,
    #[error(transparent)]
    Replay(#[from] anyhow::Error),
}

impl TransactionBuildError {
    pub fn is_simulation_failure(&self) -> bool {
        matches!(self, Self::Builder(SdkBuilderError::SimulationFailure(_)))
    }
}

fn validate_transaction_program(
    expected: &ProgrammableTransaction,
    transaction: &TransactionData,
) -> Result<(), TransactionBuildError> {
    match transaction.kind() {
        TransactionKind::ProgrammableTransaction(actual)
            if actual.commands == expected.commands
                && actual.inputs.len() == expected.inputs.len()
                && actual
                    .inputs
                    .iter()
                    .zip(&expected.inputs)
                    .all(|(actual, expected)| input_matches(expected, actual)) =>
        {
            Ok(())
        }
        _ => Err(TransactionBuildError::ProgramMismatch),
    }
}

fn input_matches(expected: &CallArg, actual: &CallArg) -> bool {
    if expected == actual {
        return true;
    }
    matches!(
        (expected, actual),
        (
            CallArg::Object(ObjectArg::SharedObject {
                id: expected_id,
                initial_shared_version: expected_version,
                mutability: SharedObjectMutability::Mutable,
            }),
            CallArg::Object(ObjectArg::SharedObject {
                id: actual_id,
                initial_shared_version: actual_version,
                mutability: SharedObjectMutability::Immutable,
            }),
        ) if expected_id == actual_id && expected_version == actual_version
    )
}

fn replayed_program(
    sender: SuiAddress,
    programmable_transaction: ProgrammableTransaction,
) -> Result<ProgrammableTransaction, TransactionBuildError> {
    let mut builder = replay(programmable_transaction)?;
    builder.set_sender(sender.into());
    builder.set_gas_budget(1);
    builder.set_gas_price(1);
    builder.add_gas_objects([ObjectInput::owned(sender.into(), 1, Digest::ZERO)]);
    let transaction = builder
        .try_build()
        .map_err(|error| TransactionBuildError::Replay(error.into()))?;
    let transaction = TransactionData::try_from(transaction)
        .map_err(|error| TransactionBuildError::Conversion(error.to_string()))?;
    match transaction.kind() {
        TransactionKind::ProgrammableTransaction(programmable_transaction) => {
            Ok(programmable_transaction.clone())
        }
        _ => Err(TransactionBuildError::ProgramMismatch),
    }
}

fn replay(
    programmable_transaction: ProgrammableTransaction,
) -> Result<TransactionBuilder, anyhow::Error> {
    let mut builder = TransactionBuilder::new();
    let gas = builder.gas();
    let inputs = programmable_transaction
        .inputs
        .into_iter()
        .map(|input| replay_input(&mut builder, input))
        .collect::<Result<Vec<_>, _>>()?;
    let mut results = Vec::with_capacity(programmable_transaction.commands.len());

    for command in programmable_transaction.commands {
        let map = |argument| map_argument(argument, gas, &inputs, &results);
        let result = match command {
            Command::MoveCall(call) => {
                let function = Function::new(
                    call.package.into(),
                    Identifier::new(call.module)?,
                    Identifier::new(call.function)?,
                )
                .with_type_args(
                    call.type_arguments
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()?,
                );
                let arguments = call
                    .arguments
                    .into_iter()
                    .map(map)
                    .collect::<Result<Vec<_>, _>>()?;
                CommandResult::Single(builder.move_call(function, arguments))
            }
            Command::TransferObjects(objects, address) => {
                let objects = objects
                    .into_iter()
                    .map(map)
                    .collect::<Result<Vec<_>, _>>()?;
                builder.transfer_objects(objects, map(address)?);
                CommandResult::None
            }
            Command::SplitCoins(coin, amounts) => {
                let amounts = amounts
                    .into_iter()
                    .map(map)
                    .collect::<Result<Vec<_>, _>>()?;
                CommandResult::Nested(builder.split_coins(map(coin)?, amounts))
            }
            Command::MergeCoins(coin, coins) => {
                let coins = coins.into_iter().map(map).collect::<Result<Vec<_>, _>>()?;
                builder.merge_coins(map(coin)?, coins);
                CommandResult::None
            }
            Command::Publish(modules, dependencies) => CommandResult::Single(
                builder.publish(modules, dependencies.into_iter().map(Into::into).collect()),
            ),
            Command::MakeMoveVec(type_, elements) => {
                let type_ = type_.map(TryInto::try_into).transpose()?;
                let elements = elements
                    .into_iter()
                    .map(map)
                    .collect::<Result<Vec<_>, _>>()?;
                CommandResult::Single(builder.make_move_vec(type_, elements))
            }
            Command::Upgrade(modules, dependencies, package, ticket) => {
                CommandResult::Single(builder.upgrade(
                    modules,
                    dependencies.into_iter().map(Into::into).collect(),
                    package.into(),
                    map(ticket)?,
                ))
            }
        };
        results.push(result);
    }

    Ok(builder)
}

fn replay_input(
    builder: &mut TransactionBuilder,
    input: CallArg,
) -> Result<SdkArgument, anyhow::Error> {
    Ok(match input {
        CallArg::Pure(bytes) => builder.pure_bytes_unique(bytes),
        CallArg::Object(ObjectArg::ImmOrOwnedObject((id, version, digest))) => builder.object(
            ObjectInput::owned(id.into(), version.value(), digest.into()),
        ),
        CallArg::Object(ObjectArg::SharedObject {
            id,
            initial_shared_version,
            mutability,
        }) => {
            anyhow::ensure!(
                mutability != SharedObjectMutability::NonExclusiveWrite,
                "standalone transaction builder does not support non-exclusive shared-object writes"
            );
            builder.object(ObjectInput::shared(
                id.into(),
                initial_shared_version.value(),
                matches!(mutability, SharedObjectMutability::Mutable),
            ))
        }
        CallArg::Object(ObjectArg::Receiving((id, version, digest))) => builder.object(
            ObjectInput::receiving(id.into(), version.value(), digest.into()),
        ),
        CallArg::FundsWithdrawal(withdrawal) => {
            anyhow::ensure!(
                withdrawal.withdraw_from == WithdrawFrom::Sender,
                "standalone transaction builder does not support sponsor funds withdrawals"
            );
            let Reservation::MaxAmountU64(amount) = withdrawal.reservation;
            let WithdrawalTypeArg::Balance(coin_type) = withdrawal.type_arg;
            builder.funds_withdrawal(type_tag_core_to_sdk(coin_type)?, amount)
        }
    })
}

fn map_argument(
    argument: Argument,
    gas: SdkArgument,
    inputs: &[SdkArgument],
    results: &[CommandResult],
) -> Result<SdkArgument, anyhow::Error> {
    match argument {
        Argument::GasCoin => Ok(gas),
        Argument::Input(index) => inputs
            .get(usize::from(index))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("PTB input index {index} is out of bounds")),
        Argument::Result(index) => match results.get(usize::from(index)) {
            Some(CommandResult::Single(argument)) => Ok(*argument),
            Some(CommandResult::Nested(arguments)) if arguments.len() == 1 => Ok(arguments[0]),
            Some(CommandResult::Nested(_)) => anyhow::bail!(
                "PTB command {index} has multiple results; use a nested result argument"
            ),
            Some(CommandResult::None) => anyhow::bail!("PTB command {index} has no result"),
            None => anyhow::bail!("PTB command result index {index} is out of bounds"),
        },
        Argument::NestedResult(index, nested_index) => match results.get(usize::from(index)) {
            Some(CommandResult::Single(argument)) => argument
                .to_nested(usize::from(nested_index) + 1)
                .get(usize::from(nested_index))
                .copied()
                .ok_or_else(|| anyhow::anyhow!("PTB nested result is out of bounds")),
            Some(CommandResult::Nested(arguments)) => arguments
                .get(usize::from(nested_index))
                .copied()
                .ok_or_else(|| anyhow::anyhow!("PTB nested result is out of bounds")),
            Some(CommandResult::None) => anyhow::bail!("PTB command {index} has no result"),
            None => anyhow::bail!("PTB command result index {index} is out of bounds"),
        },
    }
}

#[cfg(test)]
mod tests {
    use sui_types::base_types::ObjectID;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::transaction::{CallArg, GasData, TransactionDataV1, TransactionExpiration};

    use super::*;

    #[test]
    fn replays_core_ptb_argument_dependencies() {
        let mut core = ProgrammableTransactionBuilder::new();
        let amount = core.pure(10_u64).unwrap();
        let coin = core.command(Command::SplitCoins(Argument::GasCoin, vec![amount]));
        let recipient = core
            .input(CallArg::Pure(bcs::to_bytes(&SuiAddress::ZERO).unwrap()))
            .unwrap();
        core.command(Command::TransferObjects(vec![coin], recipient));

        replay(core.finish()).expect("core PTB must replay into standalone builder");
    }

    #[test]
    fn rejects_endpoint_transaction_with_different_program() {
        let mut expected = ProgrammableTransactionBuilder::new();
        let recipient = expected
            .input(CallArg::Pure(bcs::to_bytes(&SuiAddress::ZERO).unwrap()))
            .unwrap();
        expected.command(Command::TransferObjects(vec![Argument::GasCoin], recipient));
        let expected = expected.finish();

        let mut tampered = ProgrammableTransactionBuilder::new();
        let recipient = tampered
            .input(CallArg::Pure(
                bcs::to_bytes(&SuiAddress::random_for_testing_only()).unwrap(),
            ))
            .unwrap();
        tampered.command(Command::TransferObjects(vec![Argument::GasCoin], recipient));
        let transaction = TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(tampered.finish()),
            sender: SuiAddress::ZERO,
            gas_data: GasData {
                payment: vec![],
                owner: SuiAddress::ZERO,
                price: 1,
                budget: 1,
            },
            expiration: TransactionExpiration::None,
        });

        assert!(matches!(
            validate_transaction_program(&expected, &transaction),
            Err(TransactionBuildError::ProgramMismatch)
        ));
    }

    #[test]
    fn accepts_standalone_builder_result_normalization() {
        let mut core = ProgrammableTransactionBuilder::new();
        let amount = core.pure(10_u64).unwrap();
        let coin = core.command(Command::SplitCoins(Argument::GasCoin, vec![amount]));
        let recipient = core
            .input(CallArg::Pure(bcs::to_bytes(&SuiAddress::ZERO).unwrap()))
            .unwrap();
        core.command(Command::TransferObjects(vec![coin], recipient));
        let expected = replayed_program(SuiAddress::ZERO, core.finish()).unwrap();

        let mut builder = replay(expected.clone()).unwrap();
        builder.set_sender(SuiAddress::ZERO.into());
        builder.set_gas_budget(1);
        builder.set_gas_price(1);
        builder.add_gas_objects([ObjectInput::owned(SuiAddress::ZERO.into(), 1, Digest::ZERO)]);
        let transaction = builder.try_build().unwrap().try_into().unwrap();

        validate_transaction_program(&expected, &transaction).unwrap();
    }

    #[test]
    fn accepts_only_shared_object_mutability_downgrade() {
        let shared_object_id = ObjectID::random();
        let mutable = CallArg::Object(ObjectArg::SharedObject {
            id: shared_object_id,
            initial_shared_version: 1.into(),
            mutability: SharedObjectMutability::Mutable,
        });
        let immutable = CallArg::Object(ObjectArg::SharedObject {
            id: shared_object_id,
            initial_shared_version: 1.into(),
            mutability: SharedObjectMutability::Immutable,
        });
        let transaction = |input| {
            TransactionData::V1(TransactionDataV1 {
                kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    inputs: vec![input],
                    commands: vec![],
                }),
                sender: SuiAddress::ZERO,
                gas_data: GasData {
                    payment: vec![],
                    owner: SuiAddress::ZERO,
                    price: 1,
                    budget: 1,
                },
                expiration: TransactionExpiration::None,
            })
        };
        let mutable_program = ProgrammableTransaction {
            inputs: vec![mutable.clone()],
            commands: vec![],
        };
        let immutable_program = ProgrammableTransaction {
            inputs: vec![immutable.clone()],
            commands: vec![],
        };

        validate_transaction_program(&mutable_program, &transaction(immutable)).unwrap();
        assert!(matches!(
            validate_transaction_program(&immutable_program, &transaction(mutable)),
            Err(TransactionBuildError::ProgramMismatch)
        ));
    }
}
