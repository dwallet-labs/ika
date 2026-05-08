// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use move_core_types::{
    annotated_value::MoveStructLayout,
    ident_str,
    identifier::IdentStr,
    language_storage::{StructTag, TypeTag},
};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};

use sui_types::{
    base_types::{ObjectID, SequenceNumber},
    coin::Coin,
    error::ExecutionError,
    execution_status::ExecutionErrorKind,
    object::{Data, MoveObject, Object},
};

/// The number of NIka per Ika token
pub const INKU_PER_IKA: u64 = 1_000_000_000;

/// Total supply denominated in Ika
pub const TOTAL_SUPPLY_IKA: u64 = 10_000_000_000;

// Note: cannot use checked arithmetic here since `const unwrap` is still unstable.
/// Total supply denominated in NIka
pub const TOTAL_SUPPLY_INKU: u64 = TOTAL_SUPPLY_IKA * INKU_PER_IKA;

pub const IKA_MODULE_NAME: &IdentStr = ident_str!("ika");
pub const IKA_STRUCT_NAME: &IdentStr = ident_str!("IKA");

pub use checked::*;

#[sui_macros::with_checked_arithmetic]
mod checked {
    use super::*;
    use move_core_types::account_address::AccountAddress;

    #[allow(clippy::upper_case_acronyms)]
    pub struct IKA {}
    impl IKA {
        pub fn type_(ika_package_address: AccountAddress) -> StructTag {
            StructTag {
                address: ika_package_address,
                name: IKA_STRUCT_NAME.to_owned(),
                module: IKA_MODULE_NAME.to_owned(),
                type_params: Vec::new(),
            }
        }

        pub fn type_tag(ika_package_address: AccountAddress) -> TypeTag {
            TypeTag::Struct(Box::new(Self::type_(ika_package_address)))
        }
    }

    /// Rust version of the Move sui::coin::Coin<ika::ika::IKA> type
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct IKACoin(pub Coin);

    impl IKACoin {
        pub fn new(id: ObjectID, value: u64) -> Self {
            Self(Coin::new(id, value))
        }

        pub fn value(&self) -> u64 {
            self.0.value()
        }

        pub fn type_(ika_package_address: AccountAddress) -> StructTag {
            Coin::type_(TypeTag::Struct(Box::new(IKA::type_(ika_package_address))))
        }

        pub fn type_tag(ika_package_address: AccountAddress) -> TypeTag {
            TypeTag::Struct(Box::new(Self::type_(ika_package_address)))
        }

        pub fn id(&self) -> &ObjectID {
            self.0.id()
        }

        pub fn to_bcs_bytes(&self) -> Vec<u8> {
            bcs::to_bytes(&self).unwrap()
        }

        pub fn to_object(&self, version: SequenceNumber) -> MoveObject {
            MoveObject::new_gas_coin(version, *self.id(), self.value())
        }

        pub fn layout(ika_package_address: AccountAddress) -> MoveStructLayout {
            Coin::layout(TypeTag::Struct(Box::new(IKA::type_(ika_package_address))))
        }

        #[cfg(any(feature = "test-utils", test))]
        pub fn new_for_testing(value: u64) -> Self {
            Self::new(ObjectID::random(), value)
        }

        #[cfg(any(feature = "test-utils", test))]
        pub fn new_for_testing_with_id(id: ObjectID, value: u64) -> Self {
            Self::new(id, value)
        }
    }

    impl TryFrom<&MoveObject> for IKACoin {
        type Error = ExecutionError;

        fn try_from(value: &MoveObject) -> Result<IKACoin, ExecutionError> {
            if !value.type_().is_gas_coin() {
                return Err(ExecutionError::new_with_source(
                    ExecutionErrorKind::InvalidGasObject,
                    format!("Gas object type is not a gas coin: {}", value.type_()),
                ));
            }
            let gas_coin: IKACoin = bcs::from_bytes(value.contents()).map_err(|err| {
                ExecutionError::new_with_source(
                    ExecutionErrorKind::InvalidGasObject,
                    format!("Unable to deserialize gas object: {err:?}"),
                )
            })?;
            Ok(gas_coin)
        }
    }

    impl TryFrom<&Object> for IKACoin {
        type Error = ExecutionError;

        fn try_from(value: &Object) -> Result<IKACoin, ExecutionError> {
            match &value.data {
                Data::Move(obj) => obj.try_into(),
                Data::Package(_) => Err(ExecutionError::new_with_source(
                    ExecutionErrorKind::InvalidGasObject,
                    format!("Gas object type is not a gas coin: {value:?}"),
                )),
            }
        }
    }

    impl Display for IKACoin {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Coin {{ id: {}, value: {} }}", self.id(), self.value())
        }
    }
}
