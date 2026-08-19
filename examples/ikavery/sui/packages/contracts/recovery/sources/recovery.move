/// Passkey-or-zkLogin–gated recovery: import a private key into Ika as a
/// zero-trust `imported-key` dWallet, enroll multiple authentication
/// identities (WebAuthn passkeys and/or zkLogin/Sui addresses), and recover
/// by triggering a t-of-N–approved Sui transaction that signs a multi-tx
/// Solana sweep.
///
/// Every member is a `(scheme, public_key)` pair stored as a single
/// scheme-prefixed byte string; authorization is always a signature over
/// a per-operation challenge, never `ctx.sender()`. This means the Sui
/// transaction sender can be anyone (including a sponsor wallet) and the
/// member's wallet just signs the challenge on the side.
///
/// Schemes are tagged inside `auth::Credential` / `auth::NewMember` —
/// Ed25519, Secp256k1, Secp256r1, WebAuthn (passkey), and SenderAddress
/// (the approver-only path, used for zkLogin / MultiSig / Passkey-as-sender
/// — these members can propose and approve, but cannot execute since they
/// hold no encrypted user share).
module recovery::recovery;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::coordinator::DWalletCoordinator;
use ika_dwallet_2pc_mpc::coordinator_inner::{
    ImportedKeyDWalletCap,
    UnverifiedPresignCap
};
use ika_dwallet_2pc_mpc::sessions_manager::SessionIdentifier;
use recovery::auth::{Self, Credential, NewMember};
use recovery::challenges;
use recovery::registry::{Self, Registry};
use recovery::sweep_intent::{Self, SweepIntent};
use sui::coin::Coin;
use sui::sui::SUI;
use sui::table::{Self, Table};
use sui::vec_set::{Self, VecSet};

// ===== Crypto constants for the imported Solana ed25519 dWallet =====
const SOLANA_CURVE: u32 = 2;     // ED25519
const SOLANA_SIG_ALGO: u32 = 0;  // EdDSA
const SOLANA_HASH: u32 = 0;      // SHA512

// ===== Limits =====
const MAX_BUNDLE_SIZE: u64 = 8;
const MIN_THRESHOLD: u64 = 1;
const MAX_MEMBERS: u64 = 16;

// ===== Error codes =====
const EThresholdInvalid: u64 = 1;
const ENoInitialMembers: u64 = 2;
const ETooManyMembers: u64 = 3;
const EBundleTooLarge: u64 = 4;
const EBundleEmpty: u64 = 5;
const EMessageSigCountMismatch: u64 = 6;
const EAlreadyVoted: u64 = 7;
const EAlreadyExecuted: u64 = 8;
const EThresholdNotReached: u64 = 9;
const EAlreadyMember: u64 = 10;
const EProposalMissing: u64 = 11;
const EEnrollmentMissing: u64 = 12;
const ENotEnoughPresigns: u64 = 13;
const EIntentMismatch: u64 = 14;
/// Caller used a `SenderAddress` (approver-only) credential for an action
/// that needs an encrypted user share — currently only `execute()`.
const EApproverOnly: u64 = 15;
/// Roster-change proposal removed a member that isn't in the set.
const ENotAMember: u64 = 16;
/// Roster change with no removals and no threshold change — would be a noop.
const ERosterChangeEmpty: u64 = 17;
/// Roster-change proposal id missing.
const ERosterChangeMissing: u64 = 18;
/// Removing the proposer from the roster mid-flight is allowed in principle,
/// but removing the *last* member would brick the vault. Aborts when applying
/// the change would leave fewer members than `MIN_THRESHOLD`.
const ERosterUnderflow: u64 = 19;

// ===== Proposals =====
/// A recovery proposal stores the *structural* intent of each sweep tx (not
/// the message bytes). The bundle's recent blockhash, account-key ordering,
/// and other non-fund-redirecting bits are not committed; the executor is
/// expected to rebuild fresh messages at execute time and pass them in
/// alongside per-tx centralized signatures. `execute()` re-derives the
/// intent from each fresh message and aborts unless every fingerprint
/// matches the stored intent at the same index.
///
/// Presigns are reserved out of the global pool at proposal time so the
/// bundle can be signed even if the global pool is later drained or used by
/// another proposal.
public struct RecoveryProposal has store {
    sweep_intents: vector<SweepIntent>,
    intent_hash: vector<u8>,
    proposal_presigns: vector<UnverifiedPresignCap>,
    approvals: u64,
    voters: VecSet<vector<u8>>,
    executed: bool,
}

public struct EnrollmentProposal has store {
    new_member: NewMember,
    new_encryption_key_address: address,
    approvals: u64,
    voters: VecSet<vector<u8>>,
    executed: bool,
}

/// Proposal to mutate the roster — remove some existing members and/or change
/// the threshold. Both fields can be set in a single proposal so the new
/// threshold is evaluated against the post-removal roster atomically.
///
/// `members_to_remove` is a vector of canonical id bytes
/// (`[scheme, ...pubkey/addr]`), the same shape stored in `members`.
public struct RosterChangeProposal has store {
    members_to_remove: vector<vector<u8>>,
    /// `option::some(t)` to also change threshold, `option::none()` to keep current.
    new_threshold: Option<u64>,
    approvals: u64,
    voters: VecSet<vector<u8>>,
    executed: bool,
}

// ===== Main shared object =====
public struct Recovery has key, store {
    id: UID,
    imported_key_cap: ImportedKeyDWalletCap,
    presigns: vector<UnverifiedPresignCap>,
    /// Unified members set: each entry is `[scheme, ...pubkey]` per
    /// `auth::new_member_id_bytes`.
    members: VecSet<vector<u8>>,
    threshold: u64,
    proposals: Table<u64, RecoveryProposal>,
    enrollments: Table<u64, EnrollmentProposal>,
    roster_changes: Table<u64, RosterChangeProposal>,
    next_proposal_id: u64,
    next_enrollment_id: u64,
    next_roster_change_id: u64,
    nonce: u64,
    dwallet_network_encryption_key_id: ID,
}

// ===== Construction =====
/// Create the Recovery shared object. Caller must already have produced the
/// `ImportedKeyDWalletCap` from `coordinator::request_imported_key_dwallet_verification`
/// in this same PTB and pass it in here.
///
/// `initial_members` is a mixed list of passkey + sender identities, each
/// constructed via `auth::new_passkey_member` / `auth::new_sender_member`.
public fun create(
    imported_key_cap: ImportedKeyDWalletCap,
    initial_members: vector<NewMember>,
    threshold: u64,
    dwallet_network_encryption_key_id: ID,
    registry: &mut Registry,
    ctx: &mut TxContext,
): ID {
    let n = initial_members.length();
    assert!(n > 0, ENoInitialMembers);
    assert!(n <= MAX_MEMBERS, ETooManyMembers);
    assert!(threshold >= MIN_THRESHOLD && threshold <= n, EThresholdInvalid);

    let mut members = vec_set::empty<vector<u8>>();
    let mut i = 0;
    while (i < n) {
        let m = *initial_members.borrow(i);
        assert!(!auth::is_already_member(&m, &members), EAlreadyMember);
        auth::insert_member(m, &mut members);
        i = i + 1;
    };

    let recovery = Recovery {
        id: object::new(ctx),
        imported_key_cap,
        presigns: vector::empty(),
        members,
        threshold,
        proposals: table::new(ctx),
        enrollments: table::new(ctx),
        roster_changes: table::new(ctx),
        next_proposal_id: 0,
        next_enrollment_id: 0,
        next_roster_change_id: 0,
        nonce: 0,
        dwallet_network_encryption_key_id,
    };
    let recovery_id = object::id(&recovery);
    let mut j = 0;
    while (j < n) {
        let m = initial_members.borrow(j);
        registry::register(registry, auth::new_member_id_bytes(m), recovery_id);
        j = j + 1;
    };
    transfer::public_share_object(recovery);
    recovery_id
}

// ===== Presign pool =====
public fun replenish_presigns(
    self: &mut Recovery,
    coord: &mut DWalletCoordinator,
    count: u64,
    ika: &mut Coin<IKA>,
    sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    let mut i = 0;
    while (i < count) {
        let session = random_session(coord, ctx);
        let cap = coord.request_global_presign(
            self.dwallet_network_encryption_key_id,
            SOLANA_CURVE,
            SOLANA_SIG_ALGO,
            session,
            ika,
            sui,
            ctx,
        );
        self.presigns.push_back(cap);
        i = i + 1;
    };
}

// ===== Read-only accessors =====
// Package-only: external callers parse the Recovery struct directly via BCS.
public(package) fun presign_count(self: &Recovery): u64 { self.presigns.length() }
public(package) fun threshold(self: &Recovery): u64 { self.threshold }
public(package) fun member_count(self: &Recovery): u64 {
    self.members.length()
}
/// `member_id` is `[scheme, ...pubkey]` — see `auth::new_member_id_bytes`.
public(package) fun is_member(self: &Recovery, member_id: vector<u8>): bool {
    self.members.contains(&member_id)
}
public(package) fun current_nonce(self: &Recovery): u64 { self.nonce }
public(package) fun next_proposal_id(self: &Recovery): u64 { self.next_proposal_id }
public(package) fun next_enrollment_id(self: &Recovery): u64 { self.next_enrollment_id }
public(package) fun next_roster_change_id(self: &Recovery): u64 { self.next_roster_change_id }

// ===== Recovery flow =====
/// Propose a recovery sweep.
///
/// `sweep_messages` is parsed (each message becomes a `SweepIntent`) and
/// only the intents are stored — the bytes themselves are discarded so the
/// proposal isn't tied to a specific recent blockhash. `execute()` will
/// receive freshly-built messages with current blockhash and re-derive
/// intents to match.
///
/// Each tx in the bundle reserves one presign out of the global pool. The
/// reserved caps are owned by the proposal and consumed at `execute()`.
public fun propose(
    self: &mut Recovery,
    sweep_messages: vector<vector<u8>>,
    cred: Credential,
    ctx: &mut TxContext,
): u64 {
    let n = sweep_messages.length();
    assert!(n > 0, EBundleEmpty);
    assert!(n <= MAX_BUNDLE_SIZE, EBundleTooLarge);
    assert!(self.presigns.length() >= n, ENotEnoughPresigns);

    // Parse + extract intents. Aborts on unknown program / instruction /
    // address-table-lookup.
    let mut sweep_intents = vector::empty<SweepIntent>();
    let mut i = 0;
    while (i < n) {
        sweep_intents.push_back(sweep_intent::from_message_bytes(*sweep_messages.borrow(i)));
        i = i + 1;
    };

    let intent_h = sweep_intent::hash_intents(&sweep_intents);
    let challenge = challenges::propose(
        object::uid_to_bytes(&self.id),
        intent_h,
        self.nonce,
    );
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );
    self.nonce = self.nonce + 1;

    // Reserve presigns for this proposal. Pop from the front to preserve
    // the pool's FIFO ordering for the remaining global users.
    let mut proposal_presigns = vector::empty<UnverifiedPresignCap>();
    i = 0;
    while (i < n) {
        proposal_presigns.push_back(self.presigns.remove(0));
        i = i + 1;
    };

    let proposal_id = self.next_proposal_id;
    self.next_proposal_id = proposal_id + 1;

    let mut voters = vec_set::empty<vector<u8>>();
    voters.insert(voter);

    self.proposals.add(proposal_id, RecoveryProposal {
        sweep_intents,
        intent_hash: intent_h,
        proposal_presigns,
        approvals: 1,
        voters,
        executed: false,
    });
    proposal_id
}

public fun approve(
    self: &mut Recovery,
    proposal_id: u64,
    cred: Credential,
    ctx: &mut TxContext,
) {
    assert!(self.proposals.contains(proposal_id), EProposalMissing);
    let challenge = challenges::approve(object::uid_to_bytes(&self.id), proposal_id);
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );

    let proposal = self.proposals.borrow_mut(proposal_id);
    assert!(!proposal.executed, EAlreadyExecuted);
    assert!(!proposal.voters.contains(&voter), EAlreadyVoted);
    proposal.voters.insert(voter);
    proposal.approvals = proposal.approvals + 1;
}

/// Execute an approved recovery proposal.
///
/// Caller passes freshly-built sweep messages (with a current blockhash) and
/// per-tx `message_centralized_signature` blobs produced from the executor's
/// share. For each tx we re-parse the message, project to a `SweepIntent`,
/// and abort unless it matches the stored intent at the same index. Then we
/// approve + sign via the imported-key direct-sign path. The reserved
/// presign for that index is consumed regardless of whether Ika later
/// validates the centralized signature.
///
/// Auth: the executor must be a member. Without this gate, a non-member
/// could submit garbage centralized sigs and burn the reserved presigns.
public fun execute(
    self: &mut Recovery,
    coord: &mut DWalletCoordinator,
    proposal_id: u64,
    sweep_messages: vector<vector<u8>>,
    msg_centralized_sigs: vector<vector<u8>>,
    cred: Credential,
    ika: &mut Coin<IKA>,
    sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): vector<ID> {
    assert!(self.proposals.contains(proposal_id), EProposalMissing);

    // Approver-only members (`auth::SenderAddress`) hold no encrypted user
    // share, so they can't produce the centralized signature this flow needs.
    // Reject before consuming any presigns — the alternative is an opaque
    // failure deep inside Ika's `request_imported_key_sign_and_return_id`.
    assert!(!auth::is_approver_only(&cred), EApproverOnly);

    let challenge = challenges::execute(object::uid_to_bytes(&self.id), proposal_id);
    auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );

    let mut presigns_rev: vector<UnverifiedPresignCap>;
    let n;
    {
        let proposal = self.proposals.borrow_mut(proposal_id);
        assert!(!proposal.executed, EAlreadyExecuted);
        assert!(proposal.approvals >= self.threshold, EThresholdNotReached);
        n = proposal.sweep_intents.length();
        assert!(sweep_messages.length() == n, EMessageSigCountMismatch);
        assert!(msg_centralized_sigs.length() == n, EMessageSigCountMismatch);
        proposal.executed = true;
        // Drain so we can verify each cap and pass by value into Ika. We
        // intentionally leave `sweep_intents` intact for post-execute audit.
        presigns_rev = drain_vec(&mut proposal.proposal_presigns);
    };

    let mut sign_ids = vector::empty<ID>();
    let mut i = 0;
    while (i < n) {
        let msg_bytes = *sweep_messages.borrow(i);
        let centralized_sig = *msg_centralized_sigs.borrow(i);

        // Re-derive the intent from the freshly-built message and require
        // it equals the intent stored at this index. The parser aborts on
        // any unknown program / instruction / data shape, so an executor
        // that smuggled extra instructions would fail here too.
        let fresh_intent = sweep_intent::from_message_bytes(msg_bytes);
        let stored = self.proposals.borrow(proposal_id).sweep_intents.borrow(i);
        assert!(&fresh_intent == stored, EIntentMismatch);

        // presigns_rev was built by drain_vec (pops back-to-front), so
        // pop_back here yields caps in original index order — i==0 first.
        let unverified = presigns_rev.pop_back();
        let verified_presign = coord.verify_presign_cap(unverified, ctx);
        let approval = coord.approve_imported_key_message(
            &self.imported_key_cap,
            SOLANA_SIG_ALGO,
            SOLANA_HASH,
            msg_bytes,
        );
        let session = random_session(coord, ctx);
        let sign_id = coord.request_imported_key_sign_and_return_id(
            verified_presign,
            approval,
            centralized_sig,
            session,
            ika,
            sui,
            ctx,
        );
        sign_ids.push_back(sign_id);
        i = i + 1;
    };
    presigns_rev.destroy_empty();
    sign_ids
}

// ===== Enrollment flow (t-of-N, mixed kinds) =====
public fun propose_enrollment(
    self: &mut Recovery,
    new_member: NewMember,
    new_encryption_key_address: address,
    cred: Credential,
    ctx: &mut TxContext,
): u64 {
    assert!(
        !auth::is_already_member(&new_member, &self.members),
        EAlreadyMember,
    );
    assert!(
        self.members.length() < MAX_MEMBERS,
        ETooManyMembers,
    );

    let challenge = challenges::enroll_propose(
        object::uid_to_bytes(&self.id),
        auth::new_member_id_bytes(&new_member),
        self.nonce,
    );
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );
    self.nonce = self.nonce + 1;

    let enrollment_id = self.next_enrollment_id;
    self.next_enrollment_id = enrollment_id + 1;

    let mut voters = vec_set::empty<vector<u8>>();
    voters.insert(voter);

    self.enrollments.add(enrollment_id, EnrollmentProposal {
        new_member,
        new_encryption_key_address,
        approvals: 1,
        voters,
        executed: false,
    });
    enrollment_id
}

public fun approve_enrollment(
    self: &mut Recovery,
    enrollment_id: u64,
    cred: Credential,
    ctx: &mut TxContext,
) {
    assert!(self.enrollments.contains(enrollment_id), EEnrollmentMissing);
    let challenge = challenges::enroll_approve(
        object::uid_to_bytes(&self.id),
        enrollment_id,
    );
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );

    let e = self.enrollments.borrow_mut(enrollment_id);
    assert!(!e.executed, EAlreadyExecuted);
    assert!(!e.voters.contains(&voter), EAlreadyVoted);
    e.voters.insert(voter);
    e.approvals = e.approvals + 1;
}

/// Execute an enrollment for a *key-holding* new member (Ed25519/Secp256k1/
/// Secp256r1/WebAuthn). Asks Ika to re-encrypt the user share to the new
/// member's encryption key, then adds them to the roster + registry.
///
/// For approver-only (`SenderAddress`) members, use
/// `execute_enrollment_approver_only` instead — it skips the re-encrypt step
/// (and its IKA+SUI cost) since approver-only members don't hold a share.
public fun execute_enrollment(
    self: &mut Recovery,
    coord: &mut DWalletCoordinator,
    enrollment_id: u64,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    source_encrypted_user_secret_key_share_id: ID,
    registry: &mut Registry,
    ika: &mut Coin<IKA>,
    sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    assert!(self.enrollments.contains(enrollment_id), EEnrollmentMissing);
    {
        let e = self.enrollments.borrow(enrollment_id);
        assert!(!e.executed, EAlreadyExecuted);
        assert!(e.approvals >= self.threshold, EThresholdNotReached);
        // Approver-only members must use the dedicated path; this one
        // submits a re-encrypt request that would simply waste gas for them.
        assert!(!auth::is_approver_only_member(&e.new_member), EApproverOnly);
    };

    let recovery_id = object::id(self);
    let enrollment = self.enrollments.borrow_mut(enrollment_id);
    enrollment.executed = true;
    let new_member = enrollment.new_member;
    let dest_addr = enrollment.new_encryption_key_address;

    let session = random_session(coord, ctx);
    coord.request_re_encrypt_user_share_for(
        self.imported_key_cap.imported_key_dwallet_id(),
        dest_addr,
        encrypted_centralized_secret_share_and_proof,
        source_encrypted_user_secret_key_share_id,
        session,
        ika,
        sui,
        ctx,
    );

    let member_id_bytes = auth::new_member_id_bytes(&new_member);
    auth::insert_member(new_member, &mut self.members);
    registry::register(registry, member_id_bytes, recovery_id);
}

/// Execute an enrollment for a `SenderAddress` (approver-only) member. Adds
/// them to the roster + registry without touching the dWallet — they can
/// vote on future proposals but never execute themselves. No IKA/SUI fee
/// since there's no Ika operation.
public fun execute_enrollment_approver_only(
    self: &mut Recovery,
    enrollment_id: u64,
    registry: &mut Registry,
    _ctx: &mut TxContext,
) {
    assert!(self.enrollments.contains(enrollment_id), EEnrollmentMissing);
    {
        let e = self.enrollments.borrow(enrollment_id);
        assert!(!e.executed, EAlreadyExecuted);
        assert!(e.approvals >= self.threshold, EThresholdNotReached);
        // Reverse of `execute_enrollment`'s gate: this path is *only* for
        // approver-only members.
        assert!(auth::is_approver_only_member(&e.new_member), EApproverOnly);
    };

    let recovery_id = object::id(self);
    let enrollment = self.enrollments.borrow_mut(enrollment_id);
    enrollment.executed = true;
    let new_member = enrollment.new_member;

    let member_id_bytes = auth::new_member_id_bytes(&new_member);
    auth::insert_member(new_member, &mut self.members);
    registry::register(registry, member_id_bytes, recovery_id);
}

// ===== Roster-change flow (member removal + threshold change) =====
//
// One unified flow for shrinking the roster and/or changing the threshold.
// The two changes are bundled because evaluating "is the new threshold valid"
// only makes sense against the post-removal member count — splitting them
// across two proposals would risk transient invalid states between executes.
//
// No member is *added* through this flow — adds go through `propose_enrollment`
// because they need to bind the new device's encryption-key registration. To
// fully replace someone (rotate a lost key), do enrollment first to install
// the replacement, then a roster_change to remove the old identity.

/// Propose a roster change. `members_to_remove` lists canonical member-ids to
/// drop; `new_threshold` is `option::some(t)` to also change threshold or
/// `option::none()` to keep the current value. Aborts if every removal isn't
/// already a member, or the proposal would leave the vault under
/// `MIN_THRESHOLD` members, or the resulting threshold is out of range.
public fun propose_roster_change(
    self: &mut Recovery,
    members_to_remove: vector<vector<u8>>,
    new_threshold: Option<u64>,
    cred: Credential,
    ctx: &mut TxContext,
): u64 {
    // Reject empty proposals up front so the wallet prompt isn't spent on a noop.
    let removal_count = members_to_remove.length();
    let has_threshold_change = new_threshold.is_some();
    assert!(removal_count > 0 || has_threshold_change, ERosterChangeEmpty);

    // Validate every removal is currently a member. Without this, a stale
    // proposal could quietly skip removals at execute time.
    let mut i = 0;
    while (i < removal_count) {
        let id = members_to_remove.borrow(i);
        assert!(self.members.contains(id), ENotAMember);
        i = i + 1;
    };

    // Validate post-change shape so an unsatisfiable proposal can't waste
    // approvals: simulate removals (member-count after), then check threshold.
    let post_count = self.members.length() - removal_count;
    assert!(post_count >= MIN_THRESHOLD, ERosterUnderflow);
    let effective_threshold = if (has_threshold_change) {
        let t = *new_threshold.borrow();
        assert!(t >= MIN_THRESHOLD && t <= post_count, EThresholdInvalid);
        t
    } else {
        // Keep the existing threshold; clamp against the new (smaller) member
        // count to surface invalid states instead of silently allowing a
        // current threshold > new member count.
        assert!(self.threshold <= post_count, EThresholdInvalid);
        self.threshold
    };
    let _ = effective_threshold; // referenced via stored fields at execute time

    let payload_hash = challenges::roster_change_payload(
        &members_to_remove,
        if (has_threshold_change) *new_threshold.borrow() else 0,
        has_threshold_change,
    );
    let challenge = challenges::roster_change_propose(
        object::uid_to_bytes(&self.id),
        payload_hash,
        self.nonce,
    );
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );
    self.nonce = self.nonce + 1;

    let id = self.next_roster_change_id;
    self.next_roster_change_id = id + 1;

    let mut voters = vec_set::empty<vector<u8>>();
    voters.insert(voter);

    self.roster_changes.add(id, RosterChangeProposal {
        members_to_remove,
        new_threshold,
        approvals: 1,
        voters,
        executed: false,
    });
    id
}

public fun approve_roster_change(
    self: &mut Recovery,
    roster_change_id: u64,
    cred: Credential,
    ctx: &mut TxContext,
) {
    assert!(self.roster_changes.contains(roster_change_id), ERosterChangeMissing);
    let challenge = challenges::roster_change_approve(
        object::uid_to_bytes(&self.id),
        roster_change_id,
    );
    let voter = auth::verify(
        cred,
        &self.members,
        &challenge,
        ctx,
    );

    let p = self.roster_changes.borrow_mut(roster_change_id);
    assert!(!p.executed, EAlreadyExecuted);
    assert!(!p.voters.contains(&voter), EAlreadyVoted);
    p.voters.insert(voter);
    p.approvals = p.approvals + 1;
}

/// Apply an approved roster change. No Ika ops, no IKA/SUI fee — purely a
/// shared-object mutation. Re-validates removals against the live members set
/// (in case of races with concurrent enrollments) and re-validates the
/// resulting threshold against the post-change roster size.
public fun execute_roster_change(
    self: &mut Recovery,
    roster_change_id: u64,
    _ctx: &mut TxContext,
) {
    assert!(self.roster_changes.contains(roster_change_id), ERosterChangeMissing);
    {
        let p = self.roster_changes.borrow(roster_change_id);
        assert!(!p.executed, EAlreadyExecuted);
        assert!(p.approvals >= self.threshold, EThresholdNotReached);
    };

    // Snapshot proposal fields and mark executed before mutating roster so a
    // mid-loop abort can't leave us partially applied without `executed=true`.
    let removals;
    let maybe_new_threshold;
    {
        let p = self.roster_changes.borrow_mut(roster_change_id);
        p.executed = true;
        removals = p.members_to_remove;
        maybe_new_threshold = p.new_threshold;
    };

    let n = removals.length();
    let mut i = 0;
    while (i < n) {
        let id = *removals.borrow(i);
        // Re-check membership at execute time. If a concurrent
        // `execute_roster_change` already removed this id, abort cleanly
        // rather than panicking inside `VecSet::remove`.
        assert!(self.members.contains(&id), ENotAMember);
        auth::remove_member(id, &mut self.members);
        i = i + 1;
    };

    let post_count = self.members.length();
    assert!(post_count >= MIN_THRESHOLD, ERosterUnderflow);
    if (maybe_new_threshold.is_some()) {
        let t = *maybe_new_threshold.borrow();
        assert!(t >= MIN_THRESHOLD && t <= post_count, EThresholdInvalid);
        self.threshold = t;
    } else {
        // Threshold preserved across removals — clamp if the old value would
        // now exceed the post-change member count.
        assert!(self.threshold <= post_count, EThresholdInvalid);
    };
}

// ===== Internal helpers =====
fun random_session(
    coord: &mut DWalletCoordinator,
    ctx: &mut TxContext,
): SessionIdentifier {
    coord.register_session_identifier(ctx.fresh_object_address().to_bytes(), ctx)
}

fun drain_vec<T>(src: &mut vector<T>): vector<T> {
    let mut out = vector::empty<T>();
    while (!src.is_empty()) {
        out.push_back(src.pop_back());
    };
    out
}
