// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Metadata that describes a validator. Attached to the `StakingPool`
module ika_system::validator_metadata;

use std::string::String;
use sui::vec_map::{Self, VecMap};

// === Structs ===

/// Standard metadata for a validator. Created during the validator registration.
public struct ValidatorMetadata has copy, drop, store {
    image_url: String,
    project_url: String,
    description: String,
    extra_fields: VecMap<String, String>,
}

// === Public Functions ===

/// Create a new `ValidatorMetadata` instance
public fun new(image_url: String, project_url: String, description: String): ValidatorMetadata {
    ValidatorMetadata {
        image_url,
        project_url,
        description,
        extra_fields: vec_map::empty(),
    }
}

/// Set the image URL of the Validator.
public fun set_image_url(metadata: &mut ValidatorMetadata, image_url: String) {
    metadata.image_url = image_url;
}

/// Set the project URL of the Validator.
public fun set_project_url(metadata: &mut ValidatorMetadata, project_url: String) {
    metadata.project_url = project_url;
}

/// Set the description of the Validator.
public fun set_description(metadata: &mut ValidatorMetadata, description: String) {
    metadata.description = description;
}

/// Set an extra field of the Validator.
public fun set_extra_fields(
    metadata: &mut ValidatorMetadata,
    extra_fields: VecMap<String, String>,
) {
    metadata.extra_fields = extra_fields;
}

// === Accessors ===

/// Returns the image URL of the Validator.
public fun image_url(metadata: &ValidatorMetadata): String { metadata.image_url }

/// Returns the project URL of the Validator.
public fun project_url(metadata: &ValidatorMetadata): String { metadata.project_url }

/// Returns the description of the Validator.
public fun description(metadata: &ValidatorMetadata): String { metadata.description }

/// Returns the extra fields of the Validator.
public fun extra_fields(metadata: &ValidatorMetadata): &VecMap<String, String> {
    &metadata.extra_fields
}

/// Create a default empty `ValidatorMetadata` instance.
public(package) fun default(): ValidatorMetadata {
    ValidatorMetadata {
        image_url: b"".to_string(),
        project_url: b"".to_string(),
        description: b"".to_string(),
        extra_fields: vec_map::empty(),
    }
}

// === Tests ===

#[test]
fun test_validator_metadata() {
    use std::unit_test::assert_eq;

    let mut metadata = new(
        b"image_url".to_string(),
        b"project_url".to_string(),
        b"description".to_string(),
    );

    assert_eq!(metadata.image_url(), b"image_url".to_string());
    assert_eq!(metadata.project_url(), b"project_url".to_string());
    assert_eq!(metadata.description(), b"description".to_string());
    assert!(metadata.extra_fields().is_empty());

    metadata.set_image_url(b"new_image_url".to_string());
    metadata.set_project_url(b"new_project_url".to_string());
    metadata.set_description(b"new_description".to_string());

    assert_eq!(metadata.image_url(), b"new_image_url".to_string());
    assert_eq!(metadata.project_url(), b"new_project_url".to_string());
    assert_eq!(metadata.description(), b"new_description".to_string());
}
