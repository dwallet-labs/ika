use dwallet_mpc_centralized_party::create_dkg_output_by_curve_v2;

fn main() {
    let session_id = "35+xT6dCJ2lpEjpPspWncsFGbzeejVKTXPypwCj+VPo=";

    let protocol_pp_base64 = std::fs::read_to_string("./protocol_pp_base64.txt")
        .expect("Failed to read protocol_pp_base64.txt");
    let protocol_pp_bytes = base64::decode(protocol_pp_base64.trim())
        .expect("Failed to decode base64 protocol parameters");
    let session_id_bytes = base64::decode(session_id).expect("Failed to decode base64 session ID");
    let result = create_dkg_output_by_curve_v2(0, protocol_pp_bytes, session_id_bytes).unwrap();
    println!("DKG Output: {:?}", result.public_key_share_and_proof);
}
