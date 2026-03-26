# Protocol Complete Reference

All coordinator function signatures and detailed flows.

## DKG Functions

### Shared dWallet (public user share)
```rust
public fun request_dwallet_dkg_with_public_user_secret_key_share(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    centralized_public_key_share_and_proof: vector<u8>,
    user_public_output: vector<u8>,
    public_user_secret_key_share: vector<u8>,
    sign_during_dkg_request: Option<SignDuringDKGRequest>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): (DWalletCap, Option<ID>)
```
Returns: `DWalletCap` for signing auth + optional sign session ID if sign-during-DKG was requested.

### Zero-Trust dWallet (encrypted user share)
```rust
public fun request_dwallet_dkg(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    centralized_public_key_share_and_proof: vector<u8>,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    encryption_key_address: address,
    user_public_output: vector<u8>,
    signer_public_key: vector<u8>,
    sign_during_dkg_request: Option<SignDuringDKGRequest>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): (DWalletCap, Option<ID>)
```
Additional params vs shared: `encrypted_centralized_secret_share_and_proof`, `encryption_key_address`, `signer_public_key`.

### Sign During DKG
```rust
public fun sign_during_dkg_request(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    hash_scheme: u32,
    message: vector<u8>,
    message_centralized_signature: vector<u8>,
): SignDuringDKGRequest
```
Requires an existing verified presign. Pass result as `option::some(req)` to DKG call. The returned `Option<ID>` from DKG will contain the sign session ID.

## Presign Functions

### Global Presign (Taproot, EdDSA, Schnorr, ECDSA with DKG wallets)
```rust
public fun request_global_presign(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    signature_algorithm: u32,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPresignCap
```

### dWallet-Specific Presign (ECDSA with imported keys only)
```rust
public fun request_presign(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    signature_algorithm: u32,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPresignCap
```

### Presign Verification
```rust
public fun verify_presign_cap(
    self: &mut DWalletCoordinator,
    cap: UnverifiedPresignCap,
    ctx: &mut TxContext,
): VerifiedPresignCap

public fun is_presign_valid(
    self: &DWalletCoordinator,
    presign_cap: &UnverifiedPresignCap,
): bool
```
`verify_presign_cap` fails if network hasn't completed presign. Check with `is_presign_valid` first or ensure sufficient time.

## Message Approval Functions

### Standard dWallet
```rust
public fun approve_message(
    self: &mut DWalletCoordinator,
    dwallet_cap: &DWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
): MessageApproval
```

### Imported Key dWallet
```rust
public fun approve_imported_key_message(
    self: &mut DWalletCoordinator,
    imported_dwallet_cap: &ImportedKeyDWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
): ImportedKeyMessageApproval
```

## Signing Functions

### Direct Sign (no return)
```rust
public fun request_sign(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    message_approval: MessageApproval,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
)
```

### Direct Sign (returns sign session ID)
```rust
public fun request_sign_and_return_id(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    message_approval: MessageApproval,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ID
```

### Imported Key Sign
```rust
public fun request_imported_key_sign_and_return_id(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    message_approval: ImportedKeyMessageApproval,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ID
```

## Future Signing Functions

### Phase 1: Request Future Sign
```rust
public fun request_future_sign(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    presign_cap: VerifiedPresignCap,
    message: vector<u8>,
    hash_scheme: u32,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPartialUserSignatureCap
```
Note: takes `dwallet_id` directly (not `DWalletCap`). Get via `dwallet_cap.dwallet_id()`.

### Partial Signature Verification
```rust
public fun verify_partial_user_signature_cap(
    self: &mut DWalletCoordinator,
    cap: UnverifiedPartialUserSignatureCap,
    ctx: &mut TxContext,
): VerifiedPartialUserSignatureCap

public fun is_partial_user_signature_valid(
    self: &DWalletCoordinator,
    cap: &UnverifiedPartialUserSignatureCap,
): bool
```

### Phase 2: Complete with Partial Signature
```rust
public fun request_sign_with_partial_user_signature_and_return_id(
    self: &mut DWalletCoordinator,
    partial_user_signature_cap: VerifiedPartialUserSignatureCap,
    message_approval: MessageApproval,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ID
```
Note: no `message_centralized_signature` param - the partial sig already contains it.

### Imported Key Phase 2
```rust
public fun request_imported_key_sign_with_partial_user_signature_and_return_id(
    self: &mut DWalletCoordinator,
    partial_user_signature_cap: VerifiedPartialUserSignatureCap,
    message_approval: ImportedKeyMessageApproval,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ID
```

### Matching Partial Signatures
```rust
public fun match_partial_user_signature_with_message_approval(
    self: &DWalletCoordinator,
    cap: &VerifiedPartialUserSignatureCap,
    approval: &MessageApproval,
): bool

public fun match_partial_user_signature_with_imported_key_message_approval(
    self: &DWalletCoordinator,
    cap: &VerifiedPartialUserSignatureCap,
    approval: &ImportedKeyMessageApproval,
): bool
```
Use to verify partial sig matches intended message before completing.

## Key Import Functions

```rust
public fun request_imported_key_dwallet_verification(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    centralized_party_message: vector<u8>,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    encryption_key_address: address,
    user_public_output: vector<u8>,
    signer_public_key: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ImportedKeyDWalletCap
```

## Convert to Shared

```rust
public fun request_make_dwallet_user_secret_key_shares_public(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    public_user_secret_key_shares: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
)
```
Irreversible. The `public_user_secret_key_shares` must be the original user secret key share from DKG.

## Query Functions

```rust
public fun has_dwallet(self: &DWalletCoordinator, dwallet_id: ID): bool
public fun get_dwallet(self: &DWalletCoordinator, dwallet_id: ID): &DWallet
public fun current_pricing(self: &DWalletCoordinator): PricingInfo
```

## Session Management

```rust
public fun register_session_identifier(
    self: &mut DWalletCoordinator,
    bytes: vector<u8>,
    ctx: &mut TxContext,
): SessionIdentifier
```
Bytes must be globally unique. Recommended: `ctx.fresh_object_address().to_bytes()`.

## Capability Accessors

```rust
// DWalletCap
public fun dwallet_id(cap: &DWalletCap): ID

// ImportedKeyDWalletCap
public fun imported_key_dwallet_id(cap: &ImportedKeyDWalletCap): ID
```
