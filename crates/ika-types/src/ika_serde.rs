// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::fmt::Debug;

use ika_protocol_config::ProtocolVersion;
use schemars::JsonSchema;
use serde;
use serde::de::{Deserializer, Error};
use serde::ser::{Error as SerError, Serializer};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::{Bytes, DeserializeAs, SerializeAs};
use sui_types::sui_serde::BigInt;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Copy, JsonSchema)]
#[serde(rename = "ProtocolVersion")]
pub struct AsProtocolVersion(#[schemars(with = "BigInt<u64>")] u64);

impl SerializeAs<ProtocolVersion> for AsProtocolVersion {
    fn serialize_as<S>(value: &ProtocolVersion, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = value.as_u64().to_string();
        s.serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, ProtocolVersion> for AsProtocolVersion {
    fn deserialize_as<D>(deserializer: D) -> Result<ProtocolVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = BigInt::<u64>::deserialize(deserializer)?;
        Ok(ProtocolVersion::from(*b))
    }
}

#[inline]
pub(crate) fn to_custom_deser_error<'de, D, E>(e: E) -> D::Error
where
    E: Debug,
    D: Deserializer<'de>,
{
    Error::custom(format!("byte deserialization failed, cause by: {e:?}"))
}

#[inline]
pub(crate) fn to_custom_ser_error<S, E>(e: E) -> S::Error
where
    E: Debug,
    S: Serializer,
{
    S::Error::custom(format!("byte serialization failed, cause by: {e:?}"))
}

/// Serializes and deserializes a RoaringBitmap with its own on-disk standard.
/// <https://github.com/RoaringBitmap/RoaringFormatSpec>
pub(crate) struct IkaBitmap;

impl SerializeAs<roaring::RoaringBitmap> for IkaBitmap {
    fn serialize_as<S>(source: &roaring::RoaringBitmap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        source
            .serialize_into(&mut bytes)
            .map_err(to_custom_ser_error::<S, _>)?;
        Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for IkaBitmap {
    fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Bytes::deserialize_as(deserializer)?;
        deserialize_ika_bitmap(&bytes).map_err(to_custom_deser_error::<'de, D, _>)
    }
}

// RoaringBitmap::deserialize_from() or iter() do not check for duplicates.
// So this function is needed to sanitize the bitmap to ensure unique entries.
fn deserialize_ika_bitmap(bytes: &[u8]) -> std::io::Result<roaring::RoaringBitmap> {
    let orig_bitmap = roaring::RoaringBitmap::deserialize_from(bytes)?;
    // Ensure there is no duplicated entries in the bitmap.
    let mut seen = std::collections::BTreeSet::new();
    let mut new_bitmap = roaring::RoaringBitmap::new();
    for v in orig_bitmap.iter() {
        if seen.insert(v) {
            new_bitmap.insert(v);
        }
    }
    Ok(new_bitmap)
}

#[cfg(test)]
mod test {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn test_ika_bitmap_unique_deserialize() {
        // Malformed bitmap with duplicate container keys is now correctly rejected
        // by the roaring crate's stricter validation.
        let raw = "OjAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAAAAFoAAABcAAAAXgAAAGAAAABiAAAAZAAAAGYAAABoAAAAagAAAAEAAQABAAEAAQABAAEAAQABAAEA";
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .unwrap();

        assert!(roaring::RoaringBitmap::deserialize_from(&bytes[..]).is_err());
        assert!(deserialize_ika_bitmap(&bytes[..]).is_err());

        // Valid bitmap round-trips correctly.
        let mut valid_bitmap = roaring::RoaringBitmap::new();
        valid_bitmap.insert(1);
        valid_bitmap.insert(5);
        valid_bitmap.insert(10);
        let mut valid_bytes = vec![];
        valid_bitmap.serialize_into(&mut valid_bytes).unwrap();

        let deserialized = deserialize_ika_bitmap(&valid_bytes[..]).unwrap();
        assert_eq!(deserialized.len(), 3);
        let values: Vec<u32> = deserialized.iter().collect();
        assert_eq!(values, vec![1, 5, 10]);
    }
}
