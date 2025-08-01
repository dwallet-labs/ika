// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{collections::BTreeMap, sync::Arc};

use move_core_types::{identifier::Identifier, language_storage::TypeTag};
use ika_types::{
    base_types::{ObjectID, ObjectRef, IkaAddress},
    crypto::AccountKeyPair,
    object::Owner,
    transaction::{CallArg, Transaction, TransactionData, TransactionDataAPI},
    utils::to_sender_signed_transaction,
};

use crate::ProgrammableTransactionBuilder;
use crate::{convert_move_call_args, workloads::Gas, BenchMoveCallArg, ExecutionEffects};
use ika_types::transaction::Command;

/// A Ika account and all of the objects it owns
#[derive(Debug)]
pub struct IkaAccount {
    key: Arc<AccountKeyPair>,
    /// object this account uses to pay for gas
    pub gas: ObjectRef,
    /// objects owned by this account. does not include `gas`
    owned: BTreeMap<ObjectID, ObjectRef>,
    // TODO: optional type info
}

impl IkaAccount {
    pub fn new(key: Arc<AccountKeyPair>, gas: ObjectRef, objs: Vec<ObjectRef>) -> Self {
        let owned = objs.into_iter().map(|obj| (obj.0, obj)).collect();
        IkaAccount { key, gas, owned }
    }

    /// Update the state associated with `obj`, adding it if it doesn't exist
    pub fn add_or_update(&mut self, obj: ObjectRef) -> Option<ObjectRef> {
        if self.gas.0 == obj.0 {
            let old_gas = self.gas;
            self.gas = obj;
            Some(old_gas)
        } else {
            self.owned.insert(obj.0, obj)
        }
    }

    /// Delete `id` and return the old value
    pub fn delete(&mut self, id: &ObjectID) -> Option<ObjectRef> {
        debug_assert!(self.gas.0 != *id, "Deleting gas object");

        self.owned.remove(id)
    }

    /// Get a ref to the keypair for this account
    pub fn key(&self) -> &AccountKeyPair {
        self.key.as_ref()
    }
}

/// Utility struct tracking keys for known accounts, owned objects, shared objects, and immutable objects
#[derive(Debug, Default)]
pub struct InMemoryWallet {
    accounts: BTreeMap<IkaAddress, IkaAccount>, // TODO: track shared and immutable objects as well
}

impl InMemoryWallet {
    pub fn new(gas: &Gas) -> Self {
        let mut wallet = InMemoryWallet {
            accounts: BTreeMap::new(),
        };
        wallet.add_account(gas.1, gas.2.clone(), gas.0, Vec::new());
        wallet
    }

    pub fn add_account(
        &mut self,
        addr: IkaAddress,
        key: Arc<AccountKeyPair>,
        gas: ObjectRef,
        objs: Vec<ObjectRef>,
    ) {
        self.accounts.insert(addr, IkaAccount::new(key, gas, objs));
    }

    /// Apply updates from `effects` to `self`
    pub fn update(&mut self, effects: &ExecutionEffects) {
        for (obj, owner) in effects.mutated().into_iter().chain(effects.created()) {
            if let Owner::AddressOwner(a) = owner {
                if let Some(account) = self.accounts.get_mut(&a) {
                    account.add_or_update(obj);
                } // else, doesn't belong to an account we can spend from, we don't care
            } // TODO: support owned, shared objects
        }
        if let Some(sender_account) = self.accounts.get_mut(&effects.sender()) {
            for obj in effects.deleted() {
                // by construction, every deleted object either
                // 1. belongs to the tx sender directly (e.g., sender owned the object)
                // 2. belongs to the sender indirectly (e.g., deleted object was a dynamic field of a object the sender owned)
                // 3. is shared (though we do not yet support deletion of shared objects)
                // so, we just try to delete everything from the sender's account here, though it's
                // worth noting that (2) and (3) are possible.
                sender_account.delete(&obj.0);
            }
        } // else, tx sender is not an account we can spend from, we don't care
    }

    pub fn account_mut(&mut self, addr: &IkaAddress) -> Option<&mut IkaAccount> {
        self.accounts.get_mut(addr)
    }

    pub fn account(&self, addr: &IkaAddress) -> Option<&IkaAccount> {
        self.accounts.get(addr)
    }

    pub fn gas(&self, addr: &IkaAddress) -> Option<&ObjectRef> {
        self.accounts.get(addr).map(|a| &a.gas)
    }

    pub fn owned_object(&self, addr: &IkaAddress, id: &ObjectID) -> Option<&ObjectRef> {
        self.accounts.get(addr).and_then(|a| a.owned.get(id))
    }

    pub fn owned_objects(&self, addr: &IkaAddress) -> Option<impl Iterator<Item = &ObjectRef>> {
        self.accounts.get(addr).map(|a| a.owned.values())
    }

    pub fn create_tx(&self, data: TransactionData) -> Transaction {
        let sender = data.sender();
        to_sender_signed_transaction(data, self.accounts.get(&sender).unwrap().key.as_ref())
    }

    pub fn move_call(
        &self,
        sender: IkaAddress,
        package: ObjectID,
        module: &str,
        function: &str,
        type_arguments: Vec<TypeTag>,
        arguments: Vec<CallArg>,
        gas_budget: u64,
        computation_price: u64,
    ) -> Transaction {
        let account = self.account(&sender).unwrap();
        let data = TransactionData::new_move_call(
            sender,
            package,
            Identifier::new(module).unwrap(),
            Identifier::new(function).unwrap(),
            type_arguments,
            account.gas,
            arguments,
            gas_budget,
            computation_price,
        )
        .unwrap();
        to_sender_signed_transaction(data, account.key.as_ref())
    }

    pub fn move_call_pt(
        &self,
        sender: IkaAddress,
        package: ObjectID,
        module: &str,
        function: &str,
        type_arguments: Vec<TypeTag>,
        arguments: Vec<BenchMoveCallArg>,
        gas_budget: u64,
        computation_price: u64,
    ) -> Transaction {
        let account = self.account(&sender).unwrap();
        move_call_pt_impl(
            sender,
            &account.key,
            package,
            module,
            function,
            type_arguments,
            arguments,
            &account.gas,
            gas_budget,
            computation_price,
        )
    }

    pub fn keypair(&self, addr: &IkaAddress) -> Option<Arc<AccountKeyPair>> {
        self.accounts.get(addr).map(|a| a.key.clone())
    }

    pub fn num_addresses(&self) -> usize {
        self.accounts.len()
    }

    pub fn addresses(&self) -> impl Iterator<Item = &IkaAddress> {
        self.accounts.keys()
    }

    pub fn total_objects(&self) -> usize {
        let mut total = 0;
        for account in self.accounts.values() {
            total += account.owned.len()
        }
        total
    }
}

pub fn move_call_pt_impl(
    sender: IkaAddress,
    keypair: &AccountKeyPair,
    package: ObjectID,
    module: &str,
    function: &str,
    type_arguments: Vec<TypeTag>,
    arguments: Vec<BenchMoveCallArg>,
    gas_ref: &ObjectRef,
    gas_budget: u64,
    computation_price: u64,
) -> Transaction {
    let mut builder = ProgrammableTransactionBuilder::new();
    let args = convert_move_call_args(&arguments, &mut builder);

    builder.command(Command::move_call(
        package,
        Identifier::new(module).unwrap(),
        Identifier::new(function).unwrap(),
        type_arguments,
        args,
    ));
    let data = TransactionData::new_programmable(
        sender,
        vec![*gas_ref],
        builder.finish(),
        gas_budget,
        computation_price,
    );
    to_sender_signed_transaction(data, keypair)
}
