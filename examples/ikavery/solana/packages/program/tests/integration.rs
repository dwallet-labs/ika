//! On-chain integration tests via QuasarSVM.
//!
//! Loads the freshly-built `target/deploy/ikavery.so`, drives the program
//! through the same external entrypoints a client would, and asserts on
//! the post-state of every PDA the instruction touches. Run `quasar build`
//! before `cargo test --test integration`.

use ikavery::auth::{SCHEME_SOLANA_ADDRESS, SOLANA_ADDRESS_LEN};
use ikavery::cpi::*;
use ikavery::error::IkaveryError;
use ikavery::instructions::create_recovery::CREATE_MEMBERS_BYTES;
use ikavery::precompile::INSTRUCTIONS_SYSVAR_ID;
use ikavery::state::{
    AUTH_PUBKEY_BYTES, AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, MAX_MEMBERS,
    MAX_MESSAGE_BYTES, MEMBER_SLOT_LEN, STATUS_ACTIVE, STATUS_APPROVED, STATUS_EXECUTED,
};
use quasar_lang::prelude::Address;
use quasar_lang::traits::HasSeeds;
use quasar_svm::{Account, Instruction, Pubkey, QuasarSvm};
use solana_sha256_hasher::hashv as sha256_hashv;

fn load_program_elf() -> Vec<u8> {
    std::fs::read("target/deploy/ikavery.so")
        .or_else(|_| std::fs::read("../../target/deploy/ikavery.so"))
        .expect("ikavery.so not found")
}

// ---------------------------------------------------------------------------
// Pubkey/Address bridge
// ---------------------------------------------------------------------------

fn pk_to_addr(pk: Pubkey) -> Address {
    Address::new_from_array(pk.to_bytes())
}

fn addr_to_pk(addr: Address) -> Pubkey {
    Pubkey::new_from_array(addr.to_bytes())
}

// ---------------------------------------------------------------------------
// SVM bootstrap
// ---------------------------------------------------------------------------

fn ikavery_svm() -> QuasarSvm {
    let elf = load_program_elf();
    QuasarSvm::new().with_program(&addr_to_pk(ikavery::ID), &elf)
}

fn signer(addr: Address) -> Account {
    Account {
        address: addr_to_pk(addr),
        owner: quasar_svm::system_program::ID,
        lamports: 10_000_000_000,
        data: vec![],
        executable: false,
    }
}

fn empty_pda(addr: Address) -> Account {
    Account {
        address: addr_to_pk(addr),
        owner: quasar_svm::system_program::ID,
        lamports: 0,
        data: vec![],
        executable: false,
    }
}

// ---------------------------------------------------------------------------
// PDA helpers
// ---------------------------------------------------------------------------

fn recovery_pda(recovery_id: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let id_bytes = recovery_id.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::Recovery as HasSeeds>::SEED_PREFIX,
            &id_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn proposal_pda(recovery: Address, proposal_index: u32) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let rec_bytes = recovery.to_bytes();
    let idx_bytes = proposal_index.to_le_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::Proposal as HasSeeds>::SEED_PREFIX,
            &rec_bytes,
            &idx_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn approval_pda(proposal: Address, member: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let prop_bytes = proposal.to_bytes();
    let mem_bytes = member.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::Approval as HasSeeds>::SEED_PREFIX,
            &prop_bytes,
            &mem_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn roster_change_pda(recovery: Address, index: u32) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let rec_bytes = recovery.to_bytes();
    let idx_bytes = index.to_le_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::RosterChangeProposal as HasSeeds>::SEED_PREFIX,
            &rec_bytes,
            &idx_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn roster_approval_pda(roster_change: Address, member: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let rc_bytes = roster_change.to_bytes();
    let mem_bytes = member.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::RosterChangeApproval as HasSeeds>::SEED_PREFIX,
            &rc_bytes,
            &mem_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn enrollment_pda(recovery: Address, index: u32) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let rec_bytes = recovery.to_bytes();
    let idx_bytes = index.to_le_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::EnrollmentProposal as HasSeeds>::SEED_PREFIX,
            &rec_bytes,
            &idx_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn enrollment_approval_pda_for_credential(enrollment: Address, member_id_hash: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let enr_bytes = enrollment.to_bytes();
    let h_bytes = member_id_hash.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::EnrollmentApproval as HasSeeds>::SEED_PREFIX,
            &enr_bytes,
            &h_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

// ---------------------------------------------------------------------------
// Member packing
// ---------------------------------------------------------------------------

fn pack_solana_members(addrs: &[Address]) -> ([u8; CREATE_MEMBERS_BYTES], u8) {
    assert!(addrs.len() <= MAX_MEMBERS);
    let mut members = [0u8; CREATE_MEMBERS_BYTES];
    for (i, a) in addrs.iter().enumerate() {
        let off = i * MEMBER_SLOT_LEN;
        members[off] = SCHEME_SOLANA_ADDRESS;
        members[off + 1..off + 1 + SOLANA_ADDRESS_LEN].copy_from_slice(a.as_array());
    }
    (members, addrs.len() as u8)
}

fn empty_packed() -> [u8; CREATE_MEMBERS_BYTES] {
    [0u8; CREATE_MEMBERS_BYTES]
}

// ---------------------------------------------------------------------------
// Credential helpers — wire up the multi-scheme auth fields the program now
// expects on every membership-gated instruction. Tests in this file all use
// `SCHEME_SOLANA_ADDRESS`: verification falls through to "credential pubkey
// matches the on-tx Signer", no precompile inspection needed. The
// instructions sysvar account still has to be present at the canonical
// address (the handler asserts that) but its data is unread.
// ---------------------------------------------------------------------------

fn instructions_sysvar_addr() -> Address {
    INSTRUCTIONS_SYSVAR_ID
}

fn instructions_sysvar_account() -> Account {
    // Sysvar accounts are owned by the Sysvar program. QuasarSVM populates
    // its sysvar cache by deserialising whatever account data we hand in, so
    // an empty buffer makes bincode trip ("account data too small"). The
    // canonical empty-tx layout is `[u16 num=0][u16 current_index=0]` =
    // 4 zero bytes; that's exactly what the runtime emits when there are
    // no peer instructions to introspect.
    Account {
        address: addr_to_pk(INSTRUCTIONS_SYSVAR_ID),
        owner: addr_to_pk(Address::from_str_const(
            "Sysvar1111111111111111111111111111111111111",
        )),
        lamports: 0,
        data: vec![0u8, 0u8, 0u8, 0u8],
        executable: false,
    }
}

fn pad_solana_pubkey(addr: Address) -> [u8; AUTH_PUBKEY_BYTES] {
    let mut out = [0u8; AUTH_PUBKEY_BYTES];
    out[..SOLANA_ADDRESS_LEN].copy_from_slice(addr.as_array());
    out
}

fn empty_cdj() -> [u8; MAX_CLIENT_DATA_JSON_BYTES] {
    [0u8; MAX_CLIENT_DATA_JSON_BYTES]
}

fn empty_auth_sig() -> [u8; AUTH_SIGNATURE_BYTES] {
    [0u8; AUTH_SIGNATURE_BYTES]
}

/// Hash that the `Approval` / `RosterChangeApproval` PDA is keyed on for a
/// Solana-address credential.
fn solana_member_id_hash(addr: Address) -> Address {
    let mut id = [0u8; 1 + SOLANA_ADDRESS_LEN];
    id[0] = SCHEME_SOLANA_ADDRESS;
    id[1..].copy_from_slice(addr.as_array());
    Address::new_from_array(sha256_hashv(&[&id]).to_bytes())
}

fn approval_pda_for_credential(proposal: Address, member_id_hash: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let prop_bytes = proposal.to_bytes();
    let hash_bytes = member_id_hash.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::Approval as HasSeeds>::SEED_PREFIX,
            &prop_bytes,
            &hash_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

fn roster_approval_pda_for_credential(roster_change: Address, member_id_hash: Address) -> Address {
    let prog = addr_to_pk(ikavery::ID);
    let rc_bytes = roster_change.to_bytes();
    let hash_bytes = member_id_hash.to_bytes();
    let (pk, _) = Pubkey::find_program_address(
        &[
            <ikavery::state::RosterChangeApproval as HasSeeds>::SEED_PREFIX,
            &rc_bytes,
            &hash_bytes,
        ],
        &prog,
    );
    pk_to_addr(pk)
}

// ---------------------------------------------------------------------------
// Instruction builders — every test in this file uses Solana-Signer auth, so
// the credential args are filled in mechanically from the Signer address. New
// per-scheme tests call the raw `*Instruction` types directly.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_propose_ix(
    recovery: Address,
    recovery_id: Address,
    proposal: Address,
    proposer: Address,
    proposal_index: u32,
    message_bytes: [u8; MAX_MESSAGE_BYTES],
    message_len: u16,
    user_pubkey: [u8; 32],
    signature_scheme: u16,
) -> Instruction {
    ProposeInstruction {
        recovery,
        recovery_id,
        proposal,
        proposer,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        proposal_index,
        message_bytes,
        message_len,
        user_pubkey,
        signature_scheme,
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(proposer),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into()
}

fn propose_accounts(proposer: Address, proposal: Address) -> Vec<Account> {
    vec![
        signer(proposer),
        empty_pda(proposal),
        instructions_sysvar_account(),
    ]
}

fn build_approve_ix(
    recovery: Address,
    proposal: Address,
    member: Address,
) -> (Instruction, Address, Address) {
    let id_hash = solana_member_id_hash(member);
    let approval = approval_pda_for_credential(proposal, id_hash);
    let ix: Instruction = ApproveInstruction {
        recovery,
        proposal,
        member_id: id_hash,
        approval,
        payer: member,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(member),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into();
    (ix, approval, id_hash)
}

fn approve_accounts(member: Address, member_id_hash: Address, approval: Address) -> Vec<Account> {
    vec![
        signer(member),
        empty_pda(member_id_hash),
        empty_pda(approval),
        instructions_sysvar_account(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn build_propose_roster_change_ix(
    recovery: Address,
    recovery_id: Address,
    roster_change: Address,
    proposer: Address,
    roster_change_index: u32,
    payload_hash: [u8; 32],
    additions_packed: [u8; CREATE_MEMBERS_BYTES],
    addition_count: u8,
    addition_approver_only_bitmap: u16,
    removals_packed: [u8; CREATE_MEMBERS_BYTES],
    removal_count: u8,
    new_threshold: u16,
    has_new_threshold: u8,
) -> Instruction {
    ProposeRosterChangeInstruction {
        recovery,
        recovery_id,
        roster_change,
        payer: proposer,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        roster_change_index,
        payload_hash,
        additions_packed,
        addition_count,
        addition_approver_only_bitmap,
        removals_packed,
        removal_count,
        new_threshold,
        has_new_threshold,
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(proposer),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into()
}

fn propose_roster_change_accounts(proposer: Address, roster_change: Address) -> Vec<Account> {
    vec![
        signer(proposer),
        empty_pda(roster_change),
        instructions_sysvar_account(),
    ]
}

fn build_approve_roster_change_ix(
    recovery: Address,
    roster_change: Address,
    member: Address,
) -> (Instruction, Address, Address) {
    let id_hash = solana_member_id_hash(member);
    let approval = roster_approval_pda_for_credential(roster_change, id_hash);
    let ix: Instruction = ApproveRosterChangeInstruction {
        recovery,
        roster_change,
        member_id: id_hash,
        approval,
        payer: member,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(member),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into();
    (ix, approval, id_hash)
}

fn approve_roster_change_accounts(
    member: Address,
    member_id_hash: Address,
    approval: Address,
) -> Vec<Account> {
    vec![
        signer(member),
        empty_pda(member_id_hash),
        empty_pda(approval),
        instructions_sysvar_account(),
    ]
}

fn build_execute_roster_change_ix(
    recovery: Address,
    roster_change: Address,
    payer: Address,
) -> Instruction {
    ExecuteRosterChangeInstruction {
        recovery,
        roster_change,
        payer,
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
    }
    .into()
}

#[allow(clippy::too_many_arguments)]
fn build_propose_enrollment_ix(
    recovery: Address,
    recovery_id: Address,
    enrollment: Address,
    proposer: Address,
    enrollment_index: u32,
    new_member_packed: [u8; MEMBER_SLOT_LEN],
    new_encryption_key_address: [u8; 32],
    addition_approver_only: u8,
) -> Instruction {
    ProposeEnrollmentInstruction {
        recovery,
        recovery_id,
        enrollment,
        payer: proposer,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        enrollment_index,
        new_member_packed,
        new_encryption_key_address,
        addition_approver_only,
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(proposer),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into()
}

fn propose_enrollment_accounts(proposer: Address, enrollment: Address) -> Vec<Account> {
    vec![
        signer(proposer),
        empty_pda(enrollment),
        instructions_sysvar_account(),
    ]
}

fn build_approve_enrollment_ix(
    recovery: Address,
    enrollment: Address,
    member: Address,
) -> (Instruction, Address, Address) {
    let id_hash = solana_member_id_hash(member);
    let approval = enrollment_approval_pda_for_credential(enrollment, id_hash);
    let ix: Instruction = ApproveEnrollmentInstruction {
        recovery,
        enrollment,
        member_id: id_hash,
        approval,
        payer: member,
        instructions_sysvar: instructions_sysvar_addr(),
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        auth_scheme: SCHEME_SOLANA_ADDRESS,
        auth_pubkey: pad_solana_pubkey(member),
        client_data_json: empty_cdj(),
        client_data_json_len: 0,
        auth_signature: empty_auth_sig(),
    }
    .into();
    (ix, approval, id_hash)
}

fn approve_enrollment_accounts(
    member: Address,
    member_id_hash: Address,
    approval: Address,
) -> Vec<Account> {
    vec![
        signer(member),
        empty_pda(member_id_hash),
        empty_pda(approval),
        instructions_sysvar_account(),
    ]
}

fn build_execute_enrollment_ix(
    recovery: Address,
    enrollment: Address,
    payer: Address,
) -> Instruction {
    ExecuteEnrollmentInstruction {
        recovery,
        enrollment,
        payer,
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
    }
    .into()
}

// ---------------------------------------------------------------------------
// Account-data offsets (fixed-region layout pinned by `#[account]`).
// ---------------------------------------------------------------------------

const DISC_LEN: usize = 1;

// Recovery layout: disc + recovery_id(32) + creator(32) + dwallet(32) +
// dwallet_curve(2) + threshold(2) + approver_only_bitmap(2) +
// proposal_count(4) + roster_change_count(4) + enrollment_count(4) = 115.
// Then PodVec<MemberSlot,10,2>: 2-byte length prefix + N*34 payload.
const RECOVERY_FIXED_LEN: usize = DISC_LEN + 32 + 32 + 32 + 2 + 2 + 2 + 4 + 4 + 4;
const RECOVERY_MEMBERS_LEN_OFFSET: usize = RECOVERY_FIXED_LEN;

// RosterChangeProposal: disc + recovery(32) + roster_change_index(4) +
// proposer_id(34) + payload_hash(32) + addition_approver_only_bitmap(2) +
// new_threshold(2) + has_new_threshold(1) + approval_count(2) + status(1) = 111.
const ROSTER_APPROVAL_COUNT_OFFSET: usize = DISC_LEN + 32 + 4 + 34 + 32 + 2 + 2 + 1;
const ROSTER_STATUS_OFFSET: usize = ROSTER_APPROVAL_COUNT_OFFSET + 2;

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

// ---------------------------------------------------------------------------
// Recovery bootstrap
// ---------------------------------------------------------------------------

fn bootstrap_recovery(
    svm: &mut QuasarSvm,
    members: &[Address],
    threshold: u16,
) -> (Address, Address) {
    let creator = members[0];
    let recovery_id = pk_to_addr(Pubkey::new_unique());
    let recovery = recovery_pda(recovery_id);

    let (members_packed, member_count) = pack_solana_members(members);
    svm.process_instruction(
        &CreateRecoveryInstruction {
            creator,
            recovery_id,
            recovery,
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            dwallet: [0u8; 32],
            dwallet_curve: 2,
            threshold,
            member_count,
            approver_only_bitmap: 0,
            members_packed,
        }
        .into(),
        &[signer(creator), signer(recovery_id), empty_pda(recovery)],
    )
    .assert_success();
    (recovery_id, recovery)
}

// ---------------------------------------------------------------------------
// Message-bytes builder — single-instruction System::Transfer MessageV0
// ---------------------------------------------------------------------------

fn build_transfer_message(from: Address, to: Address, lamports: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.push(0x80); // version
    out.push(0x01); // num_required_signatures
    out.push(0x00); // num_readonly_signed
    out.push(0x01); // num_readonly_unsigned (system program)
    out.push(0x03); // 3 account keys
    out.extend_from_slice(from.as_array());
    out.extend_from_slice(to.as_array());
    out.extend_from_slice(&[0u8; 32]); // system program
    out.extend_from_slice(&[0x33u8; 32]); // recent blockhash
    out.push(0x01); // 1 instruction
    out.push(0x02); // program_id_index = 2
    out.push(0x02); // 2 account indices
    out.push(0x00);
    out.push(0x01);
    out.push(0x0c); // data length = 12
    out.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // u32 LE 2 = Transfer
    out.extend_from_slice(&lamports.to_le_bytes());
    out.push(0x00); // 0 lookups
    out
}

fn pad_message(msg: &[u8]) -> ([u8; MAX_MESSAGE_BYTES], u16) {
    assert!(msg.len() <= MAX_MESSAGE_BYTES);
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    out[..msg.len()].copy_from_slice(msg);
    (out, msg.len() as u16)
}

// ---------------------------------------------------------------------------
// Sysvar pseudo-accounts
// ---------------------------------------------------------------------------

fn rent_sysvar_addr() -> Address {
    Address::new_from_array(solana_sdk_ids_rent::ID.to_bytes())
}

mod solana_sdk_ids_rent {
    pub const ID: solana_pubkey::Pubkey =
        solana_pubkey::pubkey!("SysvarRent111111111111111111111111111111111");
}

mod solana_sdk_ids_system {
    pub const ID: solana_pubkey::Pubkey =
        solana_pubkey::pubkey!("11111111111111111111111111111111");
}

fn system_program_addr() -> Address {
    Address::new_from_array(solana_sdk_ids_system::ID.to_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn create_recovery_then_propose_then_approve_one_of_one() {
    let mut svm = ikavery_svm();

    let creator = pk_to_addr(Pubkey::new_unique());
    let recovery_id = pk_to_addr(Pubkey::new_unique());
    let recovery = recovery_pda(recovery_id);
    let dwallet = [7u8; 32];
    let user_pubkey = [9u8; 32];

    let (members_packed, member_count) = pack_solana_members(&[creator]);

    let create_ix: Instruction = CreateRecoveryInstruction {
        creator,
        recovery_id,
        recovery,
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        dwallet,
        dwallet_curve: 2,
        threshold: 1,
        member_count,
        approver_only_bitmap: 0,
        members_packed,
    }
    .into();

    let r = svm.process_instruction(
        &create_ix,
        &[signer(creator), signer(recovery_id), empty_pda(recovery)],
    );
    r.print_logs();
    r.assert_success();

    let to = pk_to_addr(Pubkey::new_unique());
    let msg = build_transfer_message(creator, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_ix(
            recovery,
            recovery_id,
            proposal,
            creator,
            0,
            message_bytes,
            message_len,
            user_pubkey,
            0,
        ),
        &propose_accounts(creator, proposal),
    )
    .assert_success();

    let (approve_ix, approval, member_id_hash) = build_approve_ix(recovery, proposal, creator);
    svm.process_instruction(
        &approve_ix,
        &approve_accounts(creator, member_id_hash, approval),
    )
    .assert_success();

    let proposal_acct = svm.get_account(&addr_to_pk(proposal)).expect("proposal");
    let status = proposal_acct.data[proposal_acct.data.len() - 1];
    assert_eq!(
        status, STATUS_APPROVED,
        "proposal should be approved at threshold 1-of-1"
    );
}

#[test]
fn propose_rejects_non_member() {
    let mut svm = ikavery_svm();

    let creator = pk_to_addr(Pubkey::new_unique());
    let stranger = pk_to_addr(Pubkey::new_unique());
    let recovery_id = pk_to_addr(Pubkey::new_unique());
    let recovery = recovery_pda(recovery_id);

    let (members_packed, member_count) = pack_solana_members(&[creator]);
    let create_ix: Instruction = CreateRecoveryInstruction {
        creator,
        recovery_id,
        recovery,
        rent: rent_sysvar_addr(),
        system_program: system_program_addr(),
        dwallet: [0u8; 32],
        dwallet_curve: 2,
        threshold: 1,
        member_count,
        approver_only_bitmap: 0,
        members_packed,
    }
    .into();
    svm.process_instruction(
        &create_ix,
        &[signer(creator), signer(recovery_id), empty_pda(recovery)],
    )
    .assert_success();

    let to = pk_to_addr(Pubkey::new_unique());
    let msg = build_transfer_message(stranger, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let proposal = proposal_pda(recovery, 0);
    let result = svm.process_instruction(
        &build_propose_ix(
            recovery,
            recovery_id,
            proposal,
            stranger,
            0,
            message_bytes,
            message_len,
            [0u8; 32],
            0,
        ),
        &propose_accounts(stranger, proposal),
    );
    assert!(result.is_err(), "stranger must not be able to propose");
    assert_program_error(&result, IkaveryError::NotAMember as u32);
}

#[test]
fn approve_rejects_non_member_and_blocks_double_approval() {
    let mut svm = ikavery_svm();

    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let charlie = pk_to_addr(Pubkey::new_unique());
    let stranger = pk_to_addr(Pubkey::new_unique());
    let recovery_id = pk_to_addr(Pubkey::new_unique());
    let recovery = recovery_pda(recovery_id);

    let (members_packed, member_count) = pack_solana_members(&[alice, bob, charlie]);
    svm.process_instruction(
        &CreateRecoveryInstruction {
            creator: alice,
            recovery_id,
            recovery,
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            dwallet: [0u8; 32],
            dwallet_curve: 2,
            threshold: 2,
            member_count,
            approver_only_bitmap: 0,
            members_packed,
        }
        .into(),
        &[signer(alice), signer(recovery_id), empty_pda(recovery)],
    )
    .assert_success();

    let to = pk_to_addr(Pubkey::new_unique());
    let msg = build_transfer_message(alice, to, 5_000);
    let (message_bytes, message_len) = pad_message(&msg);
    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_ix(
            recovery,
            recovery_id,
            proposal,
            alice,
            0,
            message_bytes,
            message_len,
            [0u8; 32],
            0,
        ),
        &propose_accounts(alice, proposal),
    )
    .assert_success();

    // Stranger cannot approve
    let (stranger_ix, stranger_approval, stranger_hash) =
        build_approve_ix(recovery, proposal, stranger);
    let result = svm.process_instruction(
        &stranger_ix,
        &approve_accounts(stranger, stranger_hash, stranger_approval),
    );
    assert!(result.is_err(), "stranger must not approve");
    assert_program_error(&result, IkaveryError::NotAMember as u32);

    // Alice approves: count = 1, still ACTIVE because threshold=2
    let (alice_ix, alice_approval, alice_hash) = build_approve_ix(recovery, proposal, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let proposal_acct = svm.get_account(&addr_to_pk(proposal)).expect("proposal");
    let status = proposal_acct.data[proposal_acct.data.len() - 1];
    assert_eq!(
        status, STATUS_ACTIVE,
        "proposal must remain active until threshold is reached"
    );

    // Alice cannot approve a second time — Approval PDA already initialized.
    let (alice_ix2, _, _) = build_approve_ix(recovery, proposal, alice);
    let result = svm.process_instruction(
        &alice_ix2,
        &[
            signer(alice),
            empty_pda(alice_hash),
            instructions_sysvar_account(),
        ],
    );
    assert!(
        result.is_err(),
        "duplicate approval from same member must fail"
    );

    // Bob approves: 2-of-3, status flips to APPROVED
    let (bob_ix, bob_approval, bob_hash) = build_approve_ix(recovery, proposal, bob);
    svm.process_instruction(&bob_ix, &approve_accounts(bob, bob_hash, bob_approval))
        .assert_success();

    let proposal_acct = svm.get_account(&addr_to_pk(proposal)).expect("proposal");
    let status = proposal_acct.data[proposal_acct.data.len() - 1];
    assert_eq!(status, STATUS_APPROVED, "2-of-3 should flip to APPROVED");
}

// ---------------------------------------------------------------------------
// Roster-change tests
// ---------------------------------------------------------------------------

#[test]
fn propose_roster_change_succeeds_for_member() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 1);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);

    svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            alice,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(alice, roster_change),
    )
    .assert_success();

    let acct = svm
        .get_account(&addr_to_pk(roster_change))
        .expect("roster_change PDA");
    assert_eq!(
        acct.data[ROSTER_STATUS_OFFSET], STATUS_ACTIVE,
        "fresh roster change must be ACTIVE"
    );
    assert_eq!(
        read_u16_le(&acct.data, ROSTER_APPROVAL_COUNT_OFFSET),
        0,
        "no approvals yet"
    );
}

#[test]
fn propose_roster_change_rejects_non_member() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let stranger = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice], 1);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);

    let result = svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            stranger,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(stranger, roster_change),
    );
    assert!(result.is_err());
    assert_program_error(&result, IkaveryError::NotAMember as u32);
}

#[test]
fn approve_roster_change_increments_count() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            alice,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(alice, roster_change),
    )
    .assert_success();

    let (alice_ix, alice_approval, alice_hash) =
        build_approve_roster_change_ix(recovery, roster_change, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_roster_change_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let acct = svm
        .get_account(&addr_to_pk(roster_change))
        .expect("roster_change PDA");
    assert_eq!(
        read_u16_le(&acct.data, ROSTER_APPROVAL_COUNT_OFFSET),
        1,
        "one approval recorded"
    );
    assert_eq!(
        acct.data[ROSTER_STATUS_OFFSET], STATUS_ACTIVE,
        "still ACTIVE below threshold (2-of-2)"
    );
}

#[test]
fn approve_roster_change_rejects_non_member() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let stranger = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice], 1);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            alice,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(alice, roster_change),
    )
    .assert_success();

    let (stranger_ix, stranger_approval, stranger_hash) =
        build_approve_roster_change_ix(recovery, roster_change, stranger);
    let result = svm.process_instruction(
        &stranger_ix,
        &approve_roster_change_accounts(stranger, stranger_hash, stranger_approval),
    );
    assert!(result.is_err());
    assert_program_error(&result, IkaveryError::NotAMember as u32);
}

#[test]
fn execute_roster_change_grows_member_set() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice], 1);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            alice,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(alice, roster_change),
    )
    .assert_success();

    let (alice_ix, alice_approval, alice_hash) =
        build_approve_roster_change_ix(recovery, roster_change, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_roster_change_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    svm.process_instruction(
        &build_execute_roster_change_ix(recovery, roster_change, alice),
        &[signer(alice)],
    )
    .assert_success();

    let rc_acct = svm
        .get_account(&addr_to_pk(roster_change))
        .expect("roster_change PDA");
    assert_eq!(
        rc_acct.data[ROSTER_STATUS_OFFSET], STATUS_EXECUTED,
        "roster change must be EXECUTED"
    );

    let rec_acct = svm
        .get_account(&addr_to_pk(recovery))
        .expect("recovery PDA");
    assert_eq!(
        read_u16_le(&rec_acct.data, RECOVERY_MEMBERS_LEN_OFFSET),
        2,
        "members Vec must now hold 2 entries"
    );
}

// ---------------------------------------------------------------------------
// Enrollment flow — single-member-add with encryption-key binding. Mirrors
// Sui's `propose_enrollment` / `approve_enrollment` / `execute_enrollment`.
// On Solana ika pre-alpha there's no re-encrypt CPI yet (mock user shares),
// so execute is roster-add only; the encryption-key address is stored for
// when mainnet exposes share encryption.
// ---------------------------------------------------------------------------

#[test]
fn execute_enrollment_grows_member_set() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    // Pack `dave` as a single SolanaAddress new-member slot.
    let mut new_member_packed = [0u8; MEMBER_SLOT_LEN];
    new_member_packed[0] = SCHEME_SOLANA_ADDRESS;
    new_member_packed[1..1 + SOLANA_ADDRESS_LEN].copy_from_slice(dave.as_array());

    let enrollment = enrollment_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_enrollment_ix(
            recovery,
            recovery_id,
            enrollment,
            alice,
            0,
            new_member_packed,
            [0u8; 32],
            0, // not approver-only — Solana addresses are key-holding
        ),
        &propose_enrollment_accounts(alice, enrollment),
    )
    .assert_success();

    let alice_hash = solana_member_id_hash(alice);
    let (alice_ix, alice_approval, _) = build_approve_enrollment_ix(recovery, enrollment, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_enrollment_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let bob_hash = solana_member_id_hash(bob);
    let (bob_ix, bob_approval, _) = build_approve_enrollment_ix(recovery, enrollment, bob);
    svm.process_instruction(
        &bob_ix,
        &approve_enrollment_accounts(bob, bob_hash, bob_approval),
    )
    .assert_success();

    svm.process_instruction(
        &build_execute_enrollment_ix(recovery, enrollment, alice),
        &[signer(alice)],
    )
    .assert_success();

    let rec_acct = svm
        .get_account(&addr_to_pk(recovery))
        .expect("recovery PDA");
    assert_eq!(
        read_u16_le(&rec_acct.data, RECOVERY_MEMBERS_LEN_OFFSET),
        3,
        "enrollment must grow members from 2 to 3"
    );
}

#[test]
fn propose_enrollment_rejects_duplicate_member() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    // Try to enroll `alice` again — already a member.
    let mut new_member_packed = [0u8; MEMBER_SLOT_LEN];
    new_member_packed[0] = SCHEME_SOLANA_ADDRESS;
    new_member_packed[1..1 + SOLANA_ADDRESS_LEN].copy_from_slice(alice.as_array());

    let enrollment = enrollment_pda(recovery, 0);
    let result = svm.process_instruction(
        &build_propose_enrollment_ix(
            recovery,
            recovery_id,
            enrollment,
            alice,
            0,
            new_member_packed,
            [0u8; 32],
            0,
        ),
        &propose_enrollment_accounts(alice, enrollment),
    );
    assert!(result.is_err(), "duplicate enrollment must be rejected");
}

#[test]
fn execute_enrollment_rejects_below_threshold() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    let mut new_member_packed = [0u8; MEMBER_SLOT_LEN];
    new_member_packed[0] = SCHEME_SOLANA_ADDRESS;
    new_member_packed[1..1 + SOLANA_ADDRESS_LEN].copy_from_slice(dave.as_array());

    let enrollment = enrollment_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_enrollment_ix(
            recovery,
            recovery_id,
            enrollment,
            alice,
            0,
            new_member_packed,
            [0u8; 32],
            0,
        ),
        &propose_enrollment_accounts(alice, enrollment),
    )
    .assert_success();

    // Only one approval, threshold is 2 — execute must fail.
    let alice_hash = solana_member_id_hash(alice);
    let (alice_ix, alice_approval, _) = build_approve_enrollment_ix(recovery, enrollment, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_enrollment_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let result = svm.process_instruction(
        &build_execute_enrollment_ix(recovery, enrollment, alice),
        &[signer(alice)],
    );
    assert!(
        result.is_err(),
        "execute must reject below-threshold enrollment"
    );
}

#[test]
fn execute_roster_change_rejects_below_threshold() {
    let mut svm = ikavery_svm();
    let alice = pk_to_addr(Pubkey::new_unique());
    let bob = pk_to_addr(Pubkey::new_unique());
    let dave = pk_to_addr(Pubkey::new_unique());
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    let (additions_packed, addition_count) = pack_solana_members(&[dave]);
    let roster_change = roster_change_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_roster_change_ix(
            recovery,
            recovery_id,
            roster_change,
            alice,
            0,
            [0u8; 32],
            additions_packed,
            addition_count,
            0,
            empty_packed(),
            0,
            0,
            0,
        ),
        &propose_roster_change_accounts(alice, roster_change),
    )
    .assert_success();

    // Only one approval, threshold is 2.
    let (alice_ix, alice_approval, alice_hash) =
        build_approve_roster_change_ix(recovery, roster_change, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_roster_change_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let result = svm.process_instruction(
        &build_execute_roster_change_ix(recovery, roster_change, alice),
        &[signer(alice)],
    );
    assert!(result.is_err(), "execute below threshold must fail");
    assert_program_error(&result, IkaveryError::ProposalNotActive as u32);
}

// ---------------------------------------------------------------------------
// Negative `execute` tests — every guard before the CPI into the dWallet
// coordinator. Happy path requires a live coordinator and is exercised
// end-to-end in the SDK suite.
// ---------------------------------------------------------------------------

fn unique_addr() -> Address {
    pk_to_addr(Pubkey::new_unique())
}

/// Bring a recovery to STATUS_APPROVED with a transfer message from `proposer`
/// for `lamports` lamports. Returns (recovery_id, recovery, proposal,
/// message_bytes_padded, message_len, destination).
fn approved_proposal(
    svm: &mut QuasarSvm,
    members: &[Address],
    threshold: u16,
    lamports: u64,
) -> (
    Address,
    Address,
    Address,
    [u8; MAX_MESSAGE_BYTES],
    u16,
    Address,
) {
    let (recovery_id, recovery) = bootstrap_recovery(svm, members, threshold);
    let proposer = members[0];
    let to = unique_addr();

    let msg = build_transfer_message(proposer, to, lamports);
    let (message_bytes, message_len) = pad_message(&msg);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_ix(
            recovery,
            recovery_id,
            proposal,
            proposer,
            0,
            message_bytes,
            message_len,
            [0u8; 32],
            0,
        ),
        &propose_accounts(proposer, proposal),
    )
    .assert_success();

    for (i, m) in members.iter().enumerate().take(threshold as usize) {
        let (ix, approval, hash) = build_approve_ix(recovery, proposal, *m);
        svm.process_instruction(&ix, &approve_accounts(*m, hash, approval))
            .assert_success();
        let _ = i;
    }

    (
        recovery_id,
        recovery,
        proposal,
        message_bytes,
        message_len,
        to,
    )
}

fn build_execute_ix(
    recovery: Address,
    proposal: Address,
    payer: Address,
    message_bytes: [u8; MAX_MESSAGE_BYTES],
    message_len: u16,
) -> Instruction {
    ExecuteInstruction {
        recovery,
        proposal,
        payer,
        coordinator: unique_addr(),
        message_approval: unique_addr(),
        dwallet: unique_addr(),
        caller_program: unique_addr(),
        cpi_authority: unique_addr(),
        dwallet_program: unique_addr(),
        system_program: system_program_addr(),
        message_bytes,
        message_len,
        message_approval_bump: 0,
        cpi_authority_bump: 0,
    }
    .into()
}

#[test]
fn execute_can_be_fired_by_any_signer_once_approved() {
    // Membership auth on `execute` was intentionally dropped — once the
    // proposal hits STATUS_APPROVED a sponsor wallet (no roster membership
    // required) can broadcast the dWallet CPI. We can't actually run the CPI
    // in QuasarSVM (no live coordinator), so this test only confirms the
    // pre-CPI guards no longer reject the sponsor.
    let mut svm = ikavery_svm();
    let alice = unique_addr();
    let sponsor = unique_addr();
    let (_recovery_id, recovery, proposal, message_bytes, message_len, _to) =
        approved_proposal(&mut svm, &[alice], 1, 1_000);

    let result = svm.process_instruction(
        &build_execute_ix(recovery, proposal, sponsor, message_bytes, message_len),
        &[signer(sponsor)],
    );
    // The CPI itself fails (no coordinator wired up), but if the program
    // had still been gating on membership the failure would surface as
    // `NotAMember` *before* the CPI fires. Confirm we don't see that code.
    let err_msg = std::format!("{:?}", result.raw_result);
    assert!(
        !err_msg.contains(&std::format!("Custom({})", IkaveryError::NotAMember as u32)),
        "sponsor must not be rejected with NotAMember — got {err_msg}"
    );
}

#[test]
fn execute_rejects_when_not_approved() {
    let mut svm = ikavery_svm();
    let alice = unique_addr();
    let bob = unique_addr();
    let (recovery_id, recovery) = bootstrap_recovery(&mut svm, &[alice, bob], 2);

    let to = unique_addr();
    let msg = build_transfer_message(alice, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &build_propose_ix(
            recovery,
            recovery_id,
            proposal,
            alice,
            0,
            message_bytes,
            message_len,
            [0u8; 32],
            0,
        ),
        &propose_accounts(alice, proposal),
    )
    .assert_success();

    let (alice_ix, alice_approval, alice_hash) = build_approve_ix(recovery, proposal, alice);
    svm.process_instruction(
        &alice_ix,
        &approve_accounts(alice, alice_hash, alice_approval),
    )
    .assert_success();

    let result = svm.process_instruction(
        &build_execute_ix(recovery, proposal, alice, message_bytes, message_len),
        &[signer(alice)],
    );
    assert!(
        result.is_err(),
        "execute on STATUS_ACTIVE proposal must fail"
    );
    assert_program_error(&result, IkaveryError::NotApproved as u32);
}

#[test]
fn execute_rejects_intent_digest_mismatch() {
    let mut svm = ikavery_svm();
    let alice = unique_addr();
    let (_recovery_id, recovery, proposal, _orig_bytes, _orig_len, to) =
        approved_proposal(&mut svm, &[alice], 1, 1_000);

    let tampered = build_transfer_message(alice, to, 9_999);
    let (message_bytes, message_len) = pad_message(&tampered);

    let result = svm.process_instruction(
        &build_execute_ix(recovery, proposal, alice, message_bytes, message_len),
        &[signer(alice)],
    );
    assert!(result.is_err(), "tampered message bytes must be rejected");
    assert_program_error(&result, IkaveryError::IntentDigestMismatch as u32);
}

// ---------------------------------------------------------------------------
// Multi-scheme tests — Ed25519, Secp256r1, and WebAuthn. QuasarSVM doesn't
// run Solana's signature precompiles, so these tests construct synthetic
// Instructions-sysvar bytes that *look like* verified precompile invocations.
// They prove the on-chain dispatcher accepts the right shape and rejects
// the wrong one; real signature verification fires on devnet at #107.
// ---------------------------------------------------------------------------

use ikavery::auth::{
    ED25519_PUBKEY_LEN, SCHEME_ED25519, SCHEME_SECP256K1, SCHEME_SECP256R1, SCHEME_WEBAUTHN,
    SECP256K1_PUBKEY_LEN, SECP256R1_PUBKEY_LEN, WEBAUTHN_PUBKEY_LEN,
};
use ikavery::challenges;
use ikavery::precompile::{ED25519_PRECOMPILE_ID, SECP256R1_PRECOMPILE_ID};

const SAME_INSTRUCTION_SENTINEL: u16 = 0xFFFF;
const PRECOMPILE_OFFSETS_LEN: usize = 14;

fn build_precompile_data(sig: &[u8], pubkey: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![1u8, 0u8];
    out.extend_from_slice(&[0u8; PRECOMPILE_OFFSETS_LEN]);
    let sig_off = out.len() as u16;
    out.extend_from_slice(sig);
    let pk_off = out.len() as u16;
    out.extend_from_slice(pubkey);
    let msg_off = out.len() as u16;
    out.extend_from_slice(message);

    let mut p = 2usize;
    out[p..p + 2].copy_from_slice(&sig_off.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION_SENTINEL.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&pk_off.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION_SENTINEL.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&msg_off.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&(message.len() as u16).to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION_SENTINEL.to_le_bytes());
    out
}

fn build_sysvar_with_precompile(program_id: Address, precompile_data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&1u16.to_le_bytes());
    let offset_pos = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    let inst_start = out.len();
    out[offset_pos..offset_pos + 2].copy_from_slice(&(inst_start as u16).to_le_bytes());

    out.extend_from_slice(&0u16.to_le_bytes()); // 0 account metas
    out.extend_from_slice(program_id.as_array());
    out.extend_from_slice(&(precompile_data.len() as u16).to_le_bytes());
    out.extend_from_slice(precompile_data);
    // Trailing current_instruction_index — runtime would set this; zero is fine.
    out.extend_from_slice(&[0u8, 0u8]);
    out
}

fn instructions_sysvar_account_with(data: Vec<u8>) -> Account {
    Account {
        address: addr_to_pk(INSTRUCTIONS_SYSVAR_ID),
        owner: addr_to_pk(Address::from_str_const(
            "Sysvar1111111111111111111111111111111111111",
        )),
        lamports: 0,
        data,
        executable: false,
    }
}

fn pad_pubkey<const N: usize>(key: &[u8; N]) -> [u8; AUTH_PUBKEY_BYTES] {
    let mut out = [0u8; AUTH_PUBKEY_BYTES];
    out[..N].copy_from_slice(key);
    out
}

/// Bootstrap a recovery with one non-Solana credential plus a Solana sponsor
/// (the `payer` Signer that pays for the propose-init rent). Returns
/// (sponsor, recovery_id, recovery).
fn bootstrap_recovery_packed(
    svm: &mut QuasarSvm,
    threshold: u16,
    members_packed: [u8; CREATE_MEMBERS_BYTES],
    member_count: u8,
) -> (Address, Address, Address) {
    let creator = unique_addr();
    let recovery_id = unique_addr();
    let recovery = recovery_pda(recovery_id);
    svm.process_instruction(
        &CreateRecoveryInstruction {
            creator,
            recovery_id,
            recovery,
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            dwallet: [0u8; 32],
            dwallet_curve: 2,
            threshold,
            member_count,
            approver_only_bitmap: 0,
            members_packed,
        }
        .into(),
        &[signer(creator), signer(recovery_id), empty_pda(recovery)],
    )
    .assert_success();
    (creator, recovery_id, recovery)
}

fn pack_one(scheme: u8, key: &[u8]) -> ([u8; CREATE_MEMBERS_BYTES], u8) {
    let mut out = [0u8; CREATE_MEMBERS_BYTES];
    out[0] = scheme;
    out[1..1 + key.len()].copy_from_slice(key);
    (out, 1)
}

#[test]
fn propose_with_ed25519_credential_via_precompile() {
    let mut svm = ikavery_svm();
    let pk = [0x77u8; ED25519_PUBKEY_LEN];
    let (members_packed, member_count) = pack_one(SCHEME_ED25519, &pk);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    // Reproduce the program's challenge derivation so the synthetic
    // precompile record claims to have signed exactly that digest.
    let bundle = challenges::bundle_hash(&[&msg]).unwrap();
    let challenge = challenges::propose(recovery_id.as_array(), &bundle, 0);

    let precompile_data = build_precompile_data(&[0u8; 64], &pk, &challenge);
    let sysvar_bytes = build_sysvar_with_precompile(ED25519_PRECOMPILE_ID, &precompile_data);
    let sysvar_acct = instructions_sysvar_account_with(sysvar_bytes);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_ED25519,
            auth_pubkey: pad_pubkey(&pk),
            client_data_json: empty_cdj(),
            client_data_json_len: 0,
            auth_signature: empty_auth_sig(),
        }
        .into(),
        &[signer(sponsor), empty_pda(proposal), sysvar_acct],
    )
    .assert_success();
}

#[test]
fn propose_with_secp256r1_credential_via_precompile() {
    let mut svm = ikavery_svm();
    let pk = [0x88u8; SECP256R1_PUBKEY_LEN];
    let (members_packed, member_count) = pack_one(SCHEME_SECP256R1, &pk);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let bundle = challenges::bundle_hash(&[&msg]).unwrap();
    let challenge = challenges::propose(recovery_id.as_array(), &bundle, 0);

    let precompile_data = build_precompile_data(&[0u8; 64], &pk, &challenge);
    let sysvar_bytes = build_sysvar_with_precompile(SECP256R1_PRECOMPILE_ID, &precompile_data);
    let sysvar_acct = instructions_sysvar_account_with(sysvar_bytes);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_SECP256R1,
            auth_pubkey: pad_pubkey(&pk),
            client_data_json: empty_cdj(),
            client_data_json_len: 0,
            auth_signature: empty_auth_sig(),
        }
        .into(),
        &[signer(sponsor), empty_pda(proposal), sysvar_acct],
    )
    .assert_success();
}

#[test]
fn propose_with_webauthn_passkey_via_precompile() {
    let mut svm = ikavery_svm();
    let pk = [0x44u8; WEBAUTHN_PUBKEY_LEN];
    let (members_packed, member_count) = pack_one(SCHEME_WEBAUTHN, &pk);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let bundle = challenges::bundle_hash(&[&msg]).unwrap();
    let challenge = challenges::propose(recovery_id.as_array(), &bundle, 0);

    // Construct a canonical clientDataJSON that base64url-embeds our
    // challenge, and the matching authenticatorData (rpIdHash + UP flag +
    // sign counter). The "signed payload" the secp256r1 precompile claims to
    // have verified is `auth_data || sha256(client_data_json)`.
    let cdj_string = build_canonical_client_data_json(&challenge);
    let cdj = cdj_string.as_bytes();
    let mut cdj_padded = empty_cdj();
    cdj_padded[..cdj.len()].copy_from_slice(cdj);
    let cdj_len = cdj.len() as u16;

    let mut auth_data: Vec<u8> = vec![0x77u8; 32]; // rpIdHash placeholder
    auth_data.push(0x01); // flags: UP=1
    auth_data.extend_from_slice(&[0u8; 4]); // signCount = 0
    let cdj_hash = sha256_hashv(&[cdj]).to_bytes();
    let mut signed: Vec<u8> = auth_data;
    signed.extend_from_slice(&cdj_hash);

    let precompile_data = build_precompile_data(&[0u8; 64], &pk, &signed);
    let sysvar_bytes = build_sysvar_with_precompile(SECP256R1_PRECOMPILE_ID, &precompile_data);
    let sysvar_acct = instructions_sysvar_account_with(sysvar_bytes);

    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_WEBAUTHN,
            auth_pubkey: pad_pubkey(&pk),
            client_data_json: cdj_padded,
            client_data_json_len: cdj_len,
            auth_signature: empty_auth_sig(),
        }
        .into(),
        &[signer(sponsor), empty_pda(proposal), sysvar_acct],
    )
    .assert_success();
}

#[test]
fn propose_rejects_ed25519_with_wrong_challenge_in_precompile() {
    let mut svm = ikavery_svm();
    let pk = [0x77u8; ED25519_PUBKEY_LEN];
    let (members_packed, member_count) = pack_one(SCHEME_ED25519, &pk);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    // Precompile claims to have signed a *different* challenge — should fail.
    let wrong_challenge = [0xfeu8; 32];
    let precompile_data = build_precompile_data(&[0u8; 64], &pk, &wrong_challenge);
    let sysvar_bytes = build_sysvar_with_precompile(ED25519_PRECOMPILE_ID, &precompile_data);
    let sysvar_acct = instructions_sysvar_account_with(sysvar_bytes);

    let proposal = proposal_pda(recovery, 0);
    let result = svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_ED25519,
            auth_pubkey: pad_pubkey(&pk),
            client_data_json: empty_cdj(),
            client_data_json_len: 0,
            auth_signature: empty_auth_sig(),
        }
        .into(),
        &[signer(sponsor), empty_pda(proposal), sysvar_acct],
    );
    assert!(
        result.is_err(),
        "wrong precompile challenge must be rejected"
    );
    assert_program_error(&result, IkaveryError::NoMatchingPrecompile as u32);
}

/// Canonical browser-emitted clientDataJSON for `webauthn.get`.
fn build_canonical_client_data_json(challenge: &[u8; 32]) -> std::string::String {
    let enc = b64url_encode(challenge);
    std::format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.com\"}}",
        enc
    )
}

fn b64url_encode(bytes: &[u8]) -> std::string::String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = std::string::String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | bytes[i + 2] as u32;
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHA[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        0 => {}
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => unreachable!(),
    }
    out
}

// ---------------------------------------------------------------------------
// Secp256k1 — recovery-syscall path. No precompile sysvar needed; the program
// calls `sol_secp256k1_recover` directly and compares the recovered pubkey to
// the 33-byte compressed pubkey stored in the roster.
// ---------------------------------------------------------------------------

#[test]
fn propose_with_secp256k1_credential_via_recover() {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let mut svm = ikavery_svm();

    // Deterministic k256 keypair → 33-byte compressed pubkey identical to
    // what Sui would derive for the same private key. That's the cross-
    // chain id parity the secp256k1 module pins in its unit tests.
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_encoded_point(true);
    let pk_bytes = compressed.as_bytes();
    assert_eq!(pk_bytes.len(), SECP256K1_PUBKEY_LEN);
    let mut pk33 = [0u8; SECP256K1_PUBKEY_LEN];
    pk33.copy_from_slice(pk_bytes);

    let (members_packed, member_count) = pack_one(SCHEME_SECP256K1, &pk33);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    let bundle = challenges::bundle_hash(&[&msg]).unwrap();
    let challenge = challenges::propose(recovery_id.as_array(), &bundle, 0);

    // Sign the 32-byte challenge directly (no envelope) — same shape any
    // off-the-shelf k1 wallet produces with sign_prehash.
    let (sig, recid): (Signature, RecoveryId) = signing_key.sign_prehash(&challenge).unwrap();
    let mut auth_sig = [0u8; AUTH_SIGNATURE_BYTES];
    auth_sig[..64].copy_from_slice(sig.to_bytes().as_slice());
    auth_sig[64] = recid.to_byte();

    // No precompile sysvar entry needed — recover-and-compare runs purely
    // inside the program. We still pass a well-formed (empty) sysvar.
    let proposal = proposal_pda(recovery, 0);
    svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_SECP256K1,
            auth_pubkey: pad_pubkey(&pk33),
            client_data_json: empty_cdj(),
            client_data_json_len: 0,
            auth_signature: auth_sig,
        }
        .into(),
        &[
            signer(sponsor),
            empty_pda(proposal),
            instructions_sysvar_account(),
        ],
    )
    .assert_success();
}

#[test]
fn propose_rejects_secp256k1_with_wrong_signature() {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};

    let mut svm = ikavery_svm();

    let signing_key = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
    let pk_bytes = signing_key.verifying_key().to_encoded_point(true);
    let mut pk33 = [0u8; SECP256K1_PUBKEY_LEN];
    pk33.copy_from_slice(pk_bytes.as_bytes());

    let (members_packed, member_count) = pack_one(SCHEME_SECP256K1, &pk33);
    let (sponsor, recovery_id, recovery) =
        bootstrap_recovery_packed(&mut svm, 1, members_packed, member_count);

    let to = unique_addr();
    let msg = build_transfer_message(sponsor, to, 1_000);
    let (message_bytes, message_len) = pad_message(&msg);

    // Sign a *different* challenge → recovered pubkey won't match the
    // roster's stored pubkey.
    let wrong_challenge = [0xfeu8; 32];
    let (sig, recid): (Signature, RecoveryId) = signing_key.sign_prehash(&wrong_challenge).unwrap();
    let mut auth_sig = [0u8; AUTH_SIGNATURE_BYTES];
    auth_sig[..64].copy_from_slice(sig.to_bytes().as_slice());
    auth_sig[64] = recid.to_byte();

    let proposal = proposal_pda(recovery, 0);
    let result = svm.process_instruction(
        &ProposeInstruction {
            recovery,
            recovery_id,
            proposal,
            proposer: sponsor,
            instructions_sysvar: instructions_sysvar_addr(),
            rent: rent_sysvar_addr(),
            system_program: system_program_addr(),
            proposal_index: 0,
            message_bytes,
            message_len,
            user_pubkey: [0u8; 32],
            signature_scheme: 0,
            auth_scheme: SCHEME_SECP256K1,
            auth_pubkey: pad_pubkey(&pk33),
            client_data_json: empty_cdj(),
            client_data_json_len: 0,
            auth_signature: auth_sig,
        }
        .into(),
        &[
            signer(sponsor),
            empty_pda(proposal),
            instructions_sysvar_account(),
        ],
    );
    assert!(result.is_err(), "wrong-message k1 sig must be rejected");
}

// ---------------------------------------------------------------------------
// Helpers — error code extraction
// ---------------------------------------------------------------------------

fn assert_program_error(result: &quasar_svm::ExecutionResult, expected: u32) {
    let err = result
        .raw_result
        .as_ref()
        .err()
        .expect("expected error result");
    let msg = format!("{err:?}");
    let code = format!("Custom({expected})");
    assert!(
        msg.contains(&code),
        "expected error code {} ({}) — got {msg}",
        expected,
        std::any::type_name_of_val(&expected),
    );
}
