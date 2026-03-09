# Integration Patterns Reference

Complete patterns for building production contracts with Ika.

## Pattern: Shared dWallet Contract

Contract owns `DWalletCap`, controls signing through business logic. Uses public user share so network can sign without user interaction.

### Full Treasury with Access Control

```rust
module my_protocol::treasury;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{DWalletCap, UnverifiedPresignCap}
};
use sui::{balance::Balance, coin::Coin, sui::SUI};

const SECP256K1: u32 = 0;
const TAPROOT: u32 = 1;
const SHA256: u32 = 0;
const ENotAuthorized: u64 = 1;
const ENoPresigns: u64 = 2;

public struct Treasury has key, store {
    id: UID,
    dwallet_cap: DWalletCap,
    presigns: vector<UnverifiedPresignCap>,
    authorized_signers: vector<address>,
    ika_balance: Balance<IKA>,
    sui_balance: Balance<SUI>,
    dwallet_network_encryption_key_id: ID,
}

// === Initialization ===

public fun create_treasury(
    coordinator: &mut DWalletCoordinator,
    initial_ika: Coin<IKA>,
    initial_sui: Coin<SUI>,
    dwallet_network_encryption_key_id: ID,
    centralized_public_key_share_and_proof: vector<u8>,
    user_public_output: vector<u8>,
    public_user_secret_key_share: vector<u8>,
    session_identifier_bytes: vector<u8>,
    authorized_signers: vector<address>,
    ctx: &mut TxContext,
) {
    let mut ika = initial_ika;
    let mut sui = initial_sui;

    let session = coordinator.register_session_identifier(session_identifier_bytes, ctx);
    let (dwallet_cap, _) = coordinator.request_dwallet_dkg_with_public_user_secret_key_share(
        dwallet_network_encryption_key_id, SECP256K1,
        centralized_public_key_share_and_proof, user_public_output, public_user_secret_key_share,
        option::none(), session, &mut ika, &mut sui, ctx,
    );

    let treasury = Treasury {
        id: object::new(ctx),
        dwallet_cap, presigns: vector::empty(),
        authorized_signers,
        ika_balance: ika.into_balance(),
        sui_balance: sui.into_balance(),
        dwallet_network_encryption_key_id,
    };
    transfer::public_share_object(treasury);
}

// === Access Control ===

fun assert_authorized(self: &Treasury, ctx: &TxContext) {
    assert!(self.authorized_signers.contains(&ctx.sender()), ENotAuthorized);
}

public fun add_signer(self: &mut Treasury, new_signer: address, ctx: &TxContext) {
    assert_authorized(self, ctx);
    if (!self.authorized_signers.contains(&new_signer)) {
        self.authorized_signers.push_back(new_signer);
    };
}

public fun remove_signer(self: &mut Treasury, signer: address, ctx: &TxContext) {
    assert_authorized(self, ctx);
    let (found, idx) = self.authorized_signers.index_of(&signer);
    if (found) { self.authorized_signers.swap_remove(idx); };
}

// === Direct Signing ===

public fun sign_message(
    self: &mut Treasury,
    coordinator: &mut DWalletCoordinator,
    message: vector<u8>,
    message_centralized_signature: vector<u8>,
    ctx: &mut TxContext,
): ID {
    assert_authorized(self, ctx);
    assert!(self.presigns.length() > 0, ENoPresigns);
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);

    let verified = coordinator.verify_presign_cap(self.presigns.swap_remove(0), ctx);
    let approval = coordinator.approve_message(&self.dwallet_cap, TAPROOT, SHA256, message);
    let session = random_session(coordinator, ctx);
    let sign_id = coordinator.request_sign_and_return_id(
        verified, approval, message_centralized_signature, session,
        &mut ika, &mut sui, ctx,
    );

    // Auto-replenish
    let s = random_session(coordinator, ctx);
    self.presigns.push_back(coordinator.request_global_presign(
        self.dwallet_network_encryption_key_id, SECP256K1, TAPROOT, s,
        &mut ika, &mut sui, ctx,
    ));

    return_payment_coins(self, ika, sui);
    sign_id
}

// === Balance Management ===

public fun add_ika_balance(self: &mut Treasury, coin: Coin<IKA>) {
    self.ika_balance.join(coin.into_balance());
}
public fun add_sui_balance(self: &mut Treasury, coin: Coin<SUI>) {
    self.sui_balance.join(coin.into_balance());
}
public fun ika_balance(self: &Treasury): u64 { self.ika_balance.value() }
public fun sui_balance(self: &Treasury): u64 { self.sui_balance.value() }

// === Helpers ===

fun random_session(c: &mut DWalletCoordinator, ctx: &mut TxContext): SessionIdentifier {
    c.register_session_identifier(ctx.fresh_object_address().to_bytes(), ctx)
}
fun withdraw_payment_coins(self: &mut Treasury, ctx: &mut TxContext): (Coin<IKA>, Coin<SUI>) {
    (self.ika_balance.withdraw_all().into_coin(ctx), self.sui_balance.withdraw_all().into_coin(ctx))
}
fun return_payment_coins(self: &mut Treasury, ika: Coin<IKA>, sui: Coin<SUI>) {
    self.ika_balance.join(ika.into_balance());
    self.sui_balance.join(sui.into_balance());
}
```

## Pattern: DAO Governance with Future Signing

Full governance: propose -> vote -> execute. Uses future signing to separate commitment from execution.

```rust
module my_protocol::dao;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{
        DWalletCap, UnverifiedPresignCap,
        UnverifiedPartialUserSignatureCap
    }
};
use sui::{balance::Balance, coin::Coin, sui::SUI, table::{Self, Table}};

const TAPROOT: u32 = 1;
const SHA256: u32 = 0;
const MIN_POOL: u64 = 3;
const ENotMember: u64 = 0;
const EAlreadyVoted: u64 = 1;
const EAlreadyExecuted: u64 = 2;
const EInsufficientVotes: u64 = 3;
const ENoPresigns: u64 = 4;

public struct DAO has key, store {
    id: UID,
    dwallet_cap: DWalletCap,
    presigns: vector<UnverifiedPresignCap>,
    members: vector<address>,
    voting_threshold: u64,
    proposals: Table<u64, Proposal>,
    next_id: u64,
    ika_balance: Balance<IKA>,
    sui_balance: Balance<SUI>,
    dwallet_network_encryption_key_id: ID,
}

public struct Proposal has store {
    message: vector<u8>,
    description: vector<u8>,
    partial_sig_cap: Option<UnverifiedPartialUserSignatureCap>,
    votes_for: u64,
    votes_against: u64,
    voters: Table<address, bool>,
    executed: bool,
}

/// Phase 1: Create proposal with partial signature
public fun create_proposal(
    self: &mut DAO,
    coordinator: &mut DWalletCoordinator,
    message: vector<u8>,
    description: vector<u8>,
    message_centralized_signature: vector<u8>,
    ctx: &mut TxContext,
): u64 {
    assert!(self.members.contains(&ctx.sender()), ENotMember);
    assert!(self.presigns.length() > 0, ENoPresigns);
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);

    // Future sign Phase 1
    let verified = coordinator.verify_presign_cap(self.presigns.swap_remove(0), ctx);
    let session = random_session(coordinator, ctx);
    let partial_cap = coordinator.request_future_sign(
        self.dwallet_cap.dwallet_id(), verified, message, SHA256,
        message_centralized_signature, session, &mut ika, &mut sui, ctx,
    );

    let id = self.next_id;
    self.next_id = id + 1;

    let proposal = Proposal {
        message, description,
        partial_sig_cap: option::some(partial_cap),
        votes_for: 1, votes_against: 0,  // Proposer auto-votes yes
        voters: table::new(ctx),
        executed: false,
    };
    proposal.voters.add(ctx.sender(), true);
    self.proposals.add(id, proposal);

    // Replenish if low
    if (self.presigns.length() < MIN_POOL) {
        let s = random_session(coordinator, ctx);
        self.presigns.push_back(coordinator.request_global_presign(
            self.dwallet_network_encryption_key_id, 0, TAPROOT, s,
            &mut ika, &mut sui, ctx,
        ));
    };

    return_payment_coins(self, ika, sui);
    id
}

/// Vote on proposal
public fun vote(
    self: &mut DAO, proposal_id: u64, approve: bool, ctx: &TxContext,
) {
    assert!(self.members.contains(&ctx.sender()), ENotMember);
    let p = self.proposals.borrow_mut(proposal_id);
    assert!(!p.voters.contains(ctx.sender()), EAlreadyVoted);
    assert!(!p.executed, EAlreadyExecuted);
    p.voters.add(ctx.sender(), approve);
    if (approve) { p.votes_for = p.votes_for + 1; }
    else { p.votes_against = p.votes_against + 1; };
}

/// Phase 2: Execute after approval
public fun execute(
    self: &mut DAO,
    coordinator: &mut DWalletCoordinator,
    proposal_id: u64,
    ctx: &mut TxContext,
): ID {
    let p = self.proposals.borrow_mut(proposal_id);
    assert!(p.votes_for >= self.voting_threshold, EInsufficientVotes);
    assert!(!p.executed, EAlreadyExecuted);
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);

    let verified = coordinator.verify_partial_user_signature_cap(p.partial_sig_cap.extract(), ctx);
    let approval = coordinator.approve_message(&self.dwallet_cap, TAPROOT, SHA256, p.message);
    let session = random_session(coordinator, ctx);
    let sign_id = coordinator.request_sign_with_partial_user_signature_and_return_id(
        verified, approval, session, &mut ika, &mut sui, ctx,
    );

    p.executed = true;
    return_payment_coins(self, ika, sui);
    sign_id
}

// Helpers (same pattern as treasury)
fun random_session(c: &mut DWalletCoordinator, ctx: &mut TxContext): SessionIdentifier {
    c.register_session_identifier(ctx.fresh_object_address().to_bytes(), ctx)
}
fun withdraw_payment_coins(self: &mut DAO, ctx: &mut TxContext): (Coin<IKA>, Coin<SUI>) {
    (self.ika_balance.withdraw_all().into_coin(ctx), self.sui_balance.withdraw_all().into_coin(ctx))
}
fun return_payment_coins(self: &mut DAO, ika: Coin<IKA>, sui: Coin<SUI>) {
    self.ika_balance.join(ika.into_balance());
    self.sui_balance.join(sui.into_balance());
}
```

## Pattern: Presign Pool Management

### Batch Replenishment

```rust
const TARGET_POOL: u64 = 10;
const BATCH_SIZE: u64 = 5;

public fun batch_replenish(
    self: &mut MyContract,
    coordinator: &mut DWalletCoordinator,
    ctx: &mut TxContext,
) {
    let current = self.presigns.length();
    if (current >= TARGET_POOL) { return };
    let needed = TARGET_POOL - current;
    let to_add = if (needed > BATCH_SIZE) { BATCH_SIZE } else { needed };
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);
    let mut i = 0;
    while (i < to_add) {
        let s = random_session(coordinator, ctx);
        self.presigns.push_back(coordinator.request_global_presign(
            self.dwallet_network_encryption_key_id, 0, 1, s,
            &mut ika, &mut sui, ctx,
        ));
        i = i + 1;
    };
    return_payment_coins(self, ika, sui);
}
```

### Pool Monitoring Events

```rust
use sui::event;

public struct PresignPoolLow has copy, drop {
    contract_id: ID,
    current_size: u64,
    min_size: u64,
}

public struct PresignAdded has copy, drop {
    contract_id: ID,
    new_size: u64,
}

fun emit_pool_warning(self: &MyContract, min_size: u64) {
    if (self.presigns.length() < min_size) {
        event::emit(PresignPoolLow {
            contract_id: self.id.to_inner(),
            current_size: self.presigns.length(),
            min_size,
        });
    };
}
```

## Pattern: Imported Key Wallet

Complete flow for importing existing private key and signing.

```rust
module my_protocol::imported_wallet;

use ika::ika::IKA;
use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{ImportedKeyDWalletCap, UnverifiedPresignCap}
};
use sui::{balance::Balance, coin::Coin, sui::SUI};

public struct ImportedWallet has key, store {
    id: UID,
    imported_dwallet_cap: ImportedKeyDWalletCap,
    presigns: vector<UnverifiedPresignCap>,
    ika_balance: Balance<IKA>,
    sui_balance: Balance<SUI>,
    dwallet_network_encryption_key_id: ID,
}

// Create wallet by importing existing key
public fun import_wallet(
    coordinator: &mut DWalletCoordinator,
    initial_ika: Coin<IKA>, initial_sui: Coin<SUI>,
    enc_key_id: ID,
    centralized_party_message: vector<u8>,
    encrypted_share_and_proof: vector<u8>,
    encryption_key_address: address,
    user_public_output: vector<u8>,
    signer_public_key: vector<u8>,
    session_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    let mut ika = initial_ika;
    let mut sui = initial_sui;
    let session = coordinator.register_session_identifier(session_bytes, ctx);
    let imported_cap = coordinator.request_imported_key_dwallet_verification(
        enc_key_id, 0, centralized_party_message,
        encrypted_share_and_proof, encryption_key_address,
        user_public_output, signer_public_key,
        session, &mut ika, &mut sui, ctx,
    );
    let wallet = ImportedWallet {
        id: object::new(ctx), imported_dwallet_cap: imported_cap,
        presigns: vector::empty(),
        ika_balance: ika.into_balance(), sui_balance: sui.into_balance(),
        dwallet_network_encryption_key_id: enc_key_id,
    };
    transfer::public_share_object(wallet);
}

// IMPORTANT: Use request_presign (dWallet-specific), NOT request_global_presign
public fun add_presign(
    self: &mut ImportedWallet,
    coordinator: &mut DWalletCoordinator,
    ctx: &mut TxContext,
) {
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);
    let session = random_session(coordinator, ctx);
    let cap = coordinator.request_presign(
        self.imported_dwallet_cap.imported_key_dwallet_id(),
        0,  // ECDSA
        session, &mut ika, &mut sui, ctx,
    );
    self.presigns.push_back(cap);
    return_payment_coins(self, ika, sui);
}

// IMPORTANT: Use approve_imported_key_message and request_imported_key_sign
public fun sign(
    self: &mut ImportedWallet,
    coordinator: &mut DWalletCoordinator,
    message: vector<u8>,
    msg_sig: vector<u8>,
    ctx: &mut TxContext,
): ID {
    let (mut ika, mut sui) = withdraw_payment_coins(self, ctx);
    let verified = coordinator.verify_presign_cap(self.presigns.swap_remove(0), ctx);
    let approval = coordinator.approve_imported_key_message(
        &self.imported_dwallet_cap, 0, 0, message,
    );
    let session = random_session(coordinator, ctx);
    let sign_id = coordinator.request_imported_key_sign_and_return_id(
        verified, approval, msg_sig, session, &mut ika, &mut sui, ctx,
    );
    return_payment_coins(self, ika, sui);
    sign_id
}

fun random_session(c: &mut DWalletCoordinator, ctx: &mut TxContext): SessionIdentifier {
    c.register_session_identifier(ctx.fresh_object_address().to_bytes(), ctx)
}
fun withdraw_payment_coins(self: &mut ImportedWallet, ctx: &mut TxContext): (Coin<IKA>, Coin<SUI>) {
    (self.ika_balance.withdraw_all().into_coin(ctx), self.sui_balance.withdraw_all().into_coin(ctx))
}
fun return_payment_coins(self: &mut ImportedWallet, ika: Coin<IKA>, sui: Coin<SUI>) {
    self.ika_balance.join(ika.into_balance());
    self.sui_balance.join(sui.into_balance());
}
```

## Pattern: Request Types with Enum (Multisig)

For contracts that handle multiple request types:

```rust
public enum RequestType has copy, drop, store {
    Transaction(vector<u8>, vector<u8>, vector<u8>),  // preimage, sig, psbt
    AddMember(address),
    RemoveMember(address),
    ChangeApprovalThreshold(u64),
    ChangeRejectionThreshold(u64),
    ChangeExpirationDuration(u64),
}

public enum RequestStatus has copy, drop, store {
    Pending,
    Approved(RequestResult),
    Rejected,
}

public enum RequestResult has copy, drop, store {
    TransactionResult(ID),  // sign session ID
    GovernanceResult,
}

public struct Request has store {
    id: u64,
    request_type: RequestType,
    status: RequestStatus,
    partial_sig_cap: Option<UnverifiedPartialUserSignatureCap>,
    approvers_count: u64,
    rejecters_count: u64,
    votes: Table<address, bool>,
    created_at: u64,
}
```

## Pattern: Expiration and Rejection

```rust
use sui::clock::Clock;

const EXPIRATION_MS: u64 = 86400000; // 24 hours

public fun vote_request(
    self: &mut Multisig,
    request_id: u64,
    vote: bool,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let request = self.requests.borrow_mut(request_id);

    // Check expiration first
    if (clock.timestamp_ms() > request.created_at + self.expiration_duration) {
        reject_request(self, request_id);
        return
    };

    // Check voting eligibility
    assert!(self.members.contains(&ctx.sender()), ENotMember);
    assert!(!request.votes.contains(ctx.sender()), EAlreadyVoted);

    // Irrevocable vote
    request.votes.add(ctx.sender(), vote);
    if (vote) { request.approvers_count = request.approvers_count + 1; }
    else { request.rejecters_count = request.rejecters_count + 1; };

    // Auto-reject if rejection threshold met
    if (request.rejecters_count >= self.rejection_threshold) {
        reject_request(self, request_id);
    };
}
```

## Pattern: Constants Module

Isolate chain-specific constants for cleanliness:

```rust
module my_protocol::constants;

/// Bitcoin secp256k1
public macro fun curve(): u32 { 0 }
/// Taproot
public macro fun signature_algorithm(): u32 { 1 }
/// SHA256
public macro fun hash_scheme(): u32 { 0 }
```

Usage: `constants::curve!()`, `constants::signature_algorithm!()`, `constants::hash_scheme!()`.

## Pattern: Events

```rust
module my_protocol::events;

use sui::event;

public struct WalletCreated has copy, drop { wallet_id: ID }
public struct RequestCreated has copy, drop { wallet_id: ID, request_id: u64 }
public struct VoteCast has copy, drop { wallet_id: ID, request_id: u64, voter: address, approve: bool }
public struct RequestExecuted has copy, drop { wallet_id: ID, request_id: u64, sign_id: ID }
public struct PresignAdded has copy, drop { wallet_id: ID }
public struct BalanceAdded has copy, drop { wallet_id: ID, amount: u64, token: vector<u8> }

public fun wallet_created(id: ID) { event::emit(WalletCreated { wallet_id: id }); }
public fun request_created(wallet_id: ID, request_id: u64) {
    event::emit(RequestCreated { wallet_id, request_id });
}
// ... etc
```

## Pattern: Member Deduplication

```rust
use sui::vec_set;

// In initialization:
let members = vec_set::from_keys(members).into_keys();
// Removes duplicates, produces sorted vector
```
