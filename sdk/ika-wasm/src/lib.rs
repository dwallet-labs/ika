// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party,
    advance_centralized_sign_party_with_centralized_party_dkg_output,
    centralized_and_decentralized_parties_dkg_output_match_inner, create_dkg_output_by_curve_v2,
    create_dkg_output_v1, create_imported_dwallet_centralized_step_inner_v2, decrypt_user_share_v2,
    dwallet_version_inner, encrypt_secret_key_share_and_prove_v1,
    encrypt_secret_key_share_and_prove_v2, generate_cg_keypair_from_seed,
    network_dkg_public_output_to_protocol_pp_inner, network_key_version_inner,
    parse_signature_from_sign_output_inner, public_key_from_centralized_dkg_output_by_curve,
    public_key_from_dwallet_output_by_curve, reconfiguration_public_output_to_protocol_pp_inner,
    sample_dwallet_keypair_inner, verify_secp_signature_inner, verify_secret_share_v2,
};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn create_dkg_centralized_output_v1(
    protocol_pp: Vec<u8>,
    decentralized_first_round_public_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    let dkg_centralized_result =
        &create_dkg_output_v1(protocol_pp, decentralized_first_round_public_output)
            .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&(
        dkg_centralized_result.public_key_share_and_proof.clone(),
        dkg_centralized_result.public_output.clone(),
        dkg_centralized_result.centralized_secret_output.clone(),
    ))
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn create_dkg_centralized_output_v2(
    curve: u32,
    protocol_pp: Vec<u8>,
    session_identifier: Vec<u8>,
) -> Result<JsValue, JsError> {
    let dkg_centralized_result =
        &create_dkg_output_by_curve_v2(curve, protocol_pp, session_identifier)
            .map_err(|e| JsError::new(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&(
        dkg_centralized_result.public_key_share_and_proof.clone(),
        dkg_centralized_result.public_output.clone(),
        dkg_centralized_result.centralized_secret_output.clone(),
    ))
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn public_key_from_dwallet_output(
    curve: u32,
    dwallet_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(
        &public_key_from_dwallet_output_by_curve(curve, &dwallet_output)
            .map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn public_key_from_centralized_dkg_output(
    curve: u32,
    centralized_dkg_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(
        &public_key_from_centralized_dkg_output_by_curve(curve, &centralized_dkg_output)
            .map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn network_key_version(network_key_bytes: Vec<u8>) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(
        &network_key_version_inner(network_key_bytes).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn dwallet_version(dwallet_output_bytes: Vec<u8>) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(
        &dwallet_version_inner(dwallet_output_bytes).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Derives a class groups keypair from a given seed.
///
/// The class groups public encryption key being used to encrypt a keypair will be
/// different from the encryption key used to encrypt a Ristretto keypair.
/// The plaintext space/fundamental group will correspond to the order
/// of the respective elliptic curve.
/// The secret decryption key may be the same in terms of correctness,
/// but to simplify security analysis and implementation current version maintain distinct key-pairs.
#[wasm_bindgen]
pub fn generate_secp_cg_keypair_from_seed(curve: u32, seed: &[u8]) -> Result<JsValue, JsError> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| JsError::new("seed must be 32 bytes long"))?;
    let (public_key, private_key) =
        generate_cg_keypair_from_seed(curve, seed).map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&(public_key, private_key))?)
}

#[wasm_bindgen]
pub fn network_dkg_public_output_to_protocol_pp(
    curve: u32,
    network_dkg_public_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    let protocol_pp =
        network_dkg_public_output_to_protocol_pp_inner(curve, network_dkg_public_output)
            .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&protocol_pp)?)
}

#[wasm_bindgen]
pub fn reconfiguration_public_output_to_protocol_pp(
    curve: u32,
    reconfig_public_output: Vec<u8>,
    network_dkg_public_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    let protocol_pp = reconfiguration_public_output_to_protocol_pp_inner(
        curve,
        reconfig_public_output,
        network_dkg_public_output,
    )
    .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&protocol_pp)?)
}

#[wasm_bindgen]
pub fn centralized_and_decentralized_parties_dkg_output_match(
    curve: u32,
    centralized_dkg_output: Vec<u8>,
    decentralized_dkg_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    let result = centralized_and_decentralized_parties_dkg_output_match_inner(
        curve,
        &centralized_dkg_output,
        &decentralized_dkg_output,
    )
    .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Encrypts the given secret share to the given encryption key.
/// Returns a tuple of the encryption key and proof of encryption.
#[wasm_bindgen]
pub fn encrypt_secret_share(
    curve: u32,
    secret_key_share: Vec<u8>,
    encryption_key: Vec<u8>,
    protocol_pp: Vec<u8>,
) -> Result<JsValue, JsError> {
    let encryption_and_proof =
        encrypt_secret_key_share_and_prove_v2(curve, secret_key_share, encryption_key, protocol_pp)
            .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&encryption_and_proof)?)
}

/// Decrypts the given encrypted user share using the given decryption key.
#[wasm_bindgen]
pub fn decrypt_user_share(
    curve: u32,
    decryption_key: Vec<u8>,
    dwallet_dkg_output: Vec<u8>,
    encrypted_user_share_and_proof: Vec<u8>,
    protocol_pp: Vec<u8>,
) -> Result<JsValue, JsError> {
    let decrypted_secret_share = decrypt_user_share_v2(
        curve,
        decryption_key,
        dwallet_dkg_output,
        encrypted_user_share_and_proof,
        protocol_pp,
    )
    .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&decrypted_secret_share)?)
}

/// Verifies that the given secret key share matches the given dWallet public key share.
/// DKG output->centralized_party_public_key_share.
#[wasm_bindgen]
pub fn verify_user_share(
    curve: u32,
    secret_share: Vec<u8>,
    dkg_output: Vec<u8>,
    network_dkg_public_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    Ok(JsValue::from(
        verify_secret_share_v2(curve, secret_share, dkg_output, &network_dkg_public_output)
            .map_err(to_js_err)?,
    ))
}

#[wasm_bindgen]
pub fn sample_dwallet_keypair(network_dkg_public_output: Vec<u8>) -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &sample_dwallet_keypair_inner(network_dkg_public_output).map_err(to_js_err)?,
    )?)
}

#[wasm_bindgen]
pub fn verify_secp_signature(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
    network_dkg_public_output: Vec<u8>,
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
) -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &verify_secp_signature_inner(
            public_key,
            signature,
            message,
            network_dkg_public_output,
            curve,
            signature_algorithm,
            hash_scheme,
        )
        .map_err(to_js_err)?,
    )?)
}

#[wasm_bindgen]
pub fn create_imported_dwallet_centralized_step(
    curve: u32,
    network_dkg_public_output: Vec<u8>,
    session_identifier: Vec<u8>,
    secret_share: Vec<u8>,
) -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &create_imported_dwallet_centralized_step_inner_v2(
            curve,
            &network_dkg_public_output,
            &session_identifier,
            &secret_share,
        )
        .map_err(to_js_err)?,
    )?)
}

#[wasm_bindgen]
pub fn create_sign_centralized_party_message(
    protocol_pp: Vec<u8>,
    decentralized_party_dkg_public_output: Vec<u8>,
    centralized_party_dkg_secret_output: Vec<u8>,
    presign: Vec<u8>,
    message: Vec<u8>,
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
) -> Result<JsValue, JsError> {
    let signed_message = advance_centralized_sign_party(
        protocol_pp,
        decentralized_party_dkg_public_output,
        centralized_party_dkg_secret_output,
        presign,
        message,
        curve,
        signature_algorithm,
        hash_scheme,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&signed_message).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn create_sign_centralized_party_message_with_centralized_party_dkg_output(
    protocol_pp: Vec<u8>,
    centralized_party_dkg_public_output: Vec<u8>,
    centralized_party_dkg_secret_output: Vec<u8>,
    presign: Vec<u8>,
    message: Vec<u8>,
    hash_scheme: u32,
    signature_algorithm: u32,
    curve: u32,
) -> Result<JsValue, JsError> {
    let signed_message = advance_centralized_sign_party_with_centralized_party_dkg_output(
        protocol_pp,
        centralized_party_dkg_public_output,
        centralized_party_dkg_secret_output,
        presign,
        message,
        hash_scheme,
        signature_algorithm,
        curve,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&signed_message).map_err(|e| JsError::new(&e.to_string()))
}

// There is no way to implement From<anyhow::Error> for JsErr
// since the current From<Error> is generic, and it results in a conflict.
fn to_js_err(e: anyhow::Error) -> JsError {
    JsError::new(format!("{e}").as_str())
}

#[wasm_bindgen]
pub fn parse_signature_from_sign_output(
    curve: u32,
    signature_algorithm: u32,
    signature_output: Vec<u8>,
) -> Result<JsValue, JsError> {
    let signature =
        parse_signature_from_sign_output_inner(curve, signature_algorithm, signature_output)
            .map_err(to_js_err)?;
    Ok(serde_wasm_bindgen::to_value(&signature)?)
}
