//! Verify the party_id ↔ validator mapping by going through the actual ika
//! production types.
//!
//! Reads the System object's inner JSON dump (sui CLI `sui client object … --json`
//! after navigating the dynamic field), reconstructs the BlsCommittee.members
//! exactly the way `ika-types::sui::system_inner_v1::read_bls_committee` does,
//! constructs an `ika_types::Committee` via `Committee::new`, and prints the
//! party_id ↔ validator_id mapping for both the active and the next-epoch
//! committees.

use std::collections::HashMap;
use std::env;
use std::fs;

use ika_types::committee::{Committee, ClassGroupsEncryptionKeyAndProof, StakeUnit};
use ika_types::crypto::{AuthorityName, AuthorityPublicKey, AuthorityPublicKeyBytes, ToFromBytes};

fn read_byte_array(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|b| b.as_u64().expect("byte u64") as u8)
        .collect()
}

fn read_members(committee: &serde_json::Value) -> Vec<(String, Vec<u8>)> {
    let members = committee
        .pointer("/fields/members")
        .expect("committee.fields.members");
    members
        .as_array()
        .expect("members array")
        .iter()
        .map(|m| {
            let f = m.pointer("/fields").expect("member.fields");
            let validator_id = f
                .pointer("/validator_id")
                .expect("validator_id")
                .as_str()
                .expect("validator_id str")
                .to_string();
            let pk_bytes = read_byte_array(
                f.pointer("/protocol_pubkey/fields/bytes")
                    .expect("protocol_pubkey.fields.bytes"),
            );
            (validator_id, pk_bytes)
        })
        .collect()
}

fn build_committee(epoch: u64, members: &[(String, Vec<u8>)]) -> Committee {
    // Mirror of ika-types::sui::system_inner_v1::read_bls_committee:
    //   bls_committee.members.iter().map(|v| (v.validator_id, ((&AuthorityPublicKey::from_bytes(v.protocol_pubkey...)).into(), 1))).collect()
    let voting_rights: Vec<(AuthorityName, StakeUnit)> = members
        .iter()
        .map(|(_vid, pk_bytes)| {
            let pk = AuthorityPublicKey::from_bytes(pk_bytes)
                .expect("AuthorityPublicKey::from_bytes");
            let name: AuthorityPublicKeyBytes = (&pk).into();
            (name, 1u64)
        })
        .collect();

    let n = voting_rights.len() as u64;
    // quorum_threshold and validity_threshold are not used for party_id derivation;
    // pick safe values so Committee::new doesn't panic.
    let quorum_threshold = (2 * n).div_ceil(3);
    let validity_threshold = n.div_ceil(3);

    Committee::new(
        epoch,
        voting_rights,
        HashMap::<AuthorityName, ClassGroupsEncryptionKeyAndProof>::new(),
        quorum_threshold,
        validity_threshold,
    )
}

fn dump_party_ids(label: &str, committee: &Committee, members: &[(String, Vec<u8>)]) {
    println!("=== {label} (n={}, threshold(quorum)={}) ===", members.len(), committee.quorum_threshold);
    println!(
        "{:>8}  {:<66}  {:<24}  {}",
        "party_id", "validator_id", "authority_name(short)", "(verify) chain_index+1"
    );
    for (chain_index, (vid, pk_bytes)) in members.iter().enumerate() {
        // Recompute party_id via the production code path
        let pk = AuthorityPublicKey::from_bytes(pk_bytes).expect("pk");
        let name: AuthorityPublicKeyBytes = (&pk).into();
        let party_id = committee
            .authority_index(&name)
            .expect("authority_index")
            + 1; // ika-core/src/dwallet_mpc/mod.rs:49
        let name_short = format!("{name:?}");
        let name_short = if name_short.len() > 24 {
            format!("{}…", &name_short[..23])
        } else {
            name_short
        };
        println!(
            "{:>8}  {}  {:<24}  {}",
            party_id,
            vid,
            name_short,
            chain_index + 1
        );
        assert_eq!(party_id as usize, chain_index + 1, "ordering invariant");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(String::as_str).unwrap_or("/tmp/sys_inner.json");
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");

    let value = json
        .pointer("/content/fields/value/fields")
        .expect("content.fields.value.fields");

    let epoch: u64 = value
        .pointer("/epoch")
        .and_then(|v| v.as_str())
        .expect("epoch str")
        .parse()
        .expect("epoch u64");

    let validator_set = value.pointer("/validator_set").expect("validator_set");
    let active = validator_set
        .pointer("/fields/active_committee")
        .expect("active_committee");
    let next = validator_set
        .pointer("/fields/next_epoch_active_committee")
        .expect("next_epoch_active_committee");

    let active_members = read_members(active);
    let next_members = read_members(next);

    let active_committee = build_committee(epoch, &active_members);
    let next_committee = build_committee(epoch + 1, &next_members);

    dump_party_ids("CURRENT (active_committee)", &active_committee, &active_members);
    println!();
    dump_party_ids("UPCOMING (next_epoch_active_committee)", &next_committee, &next_members);

    // Highlight the three we care about for the bug
    println!("\n=== bug-relevant identifications ===");
    let dealer_19 = &active_members[18];
    let recip_19 = &next_members[18];
    let recip_31 = &next_members[30];
    println!("dealer current.party_id=19  → validator_id={}", dealer_19.0);
    println!("excluded recipient upcoming.party_id=19 → validator_id={}", recip_19.0);
    println!("excluded recipient upcoming.party_id=31 → validator_id={}", recip_31.0);
}
