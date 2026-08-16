// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Compatibility bridge from Sui core PTBs to the standalone transaction
//! builder.
//!
//! Ika's transaction constructors still expose Sui core arguments internally.
//! Replaying the completed PTB here moves input resolution, gas selection, and
//! simulation to `sui-transaction-builder` without requiring an all-at-once
//! rewrite of every protocol call site.

use sui_transaction_builder::{Argument as SdkArgument, Function, ObjectInput, TransactionBuilder};
use sui_types::base_types::SuiAddress;
use sui_types::transaction::{
    Argument, CallArg, Command, ObjectArg, ProgrammableTransaction, Reservation,
    SharedObjectMutability, TransactionData, WithdrawFrom, WithdrawalTypeArg,
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
    gas_budget: u64,
    programmable_transaction: ProgrammableTransaction,
) -> Result<TransactionData, anyhow::Error> {
    let mut builder = replay(programmable_transaction)?;
    builder.set_sender(sender.into());
    builder.set_gas_budget(gas_budget);
    let transaction = client.build_transaction(builder).await?;
    Ok(transaction.try_into()?)
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
                    sui_sdk_types::Identifier::new(call.module)?,
                    sui_sdk_types::Identifier::new(call.function)?,
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
            ObjectInput::new(id.into())
                .with_version(version.value())
                .with_digest(digest.into()),
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
            builder.funds_withdrawal(coin_type.to_string().parse()?, amount)
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
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::transaction::CallArg;

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
}
