use quasar_lang::prelude::*;

#[error_code]
pub enum IkaveryError {
    InvalidThreshold = 6000,
    NoMembers,
    TooManyMembers,
    NotAMember,
    DuplicateMember,
    UnknownScheme,
    BadMemberLength,
    ProposalNotActive,
    ArithmeticOverflow,
    /// The credential's declared address didn't match the Signer's address.
    /// Mirrors Sui's `EWrongSender`.
    WrongSigner,
    /// Solana ships a Secp256k1 precompile, but only the ETH-flavoured one
    /// (recovers a 20-byte address rather than the 33-byte compressed pubkey
    /// our roster stores). Wiring it up needs an on-chain pubkey-to-address
    /// mapper we haven't built yet — see task #112.
    SchemeNotYetSupported,
    /// `auth_pubkey_len` didn't match the scheme's required pubkey length.
    BadPubkeyLength,
    /// The Instructions-sysvar account address wasn't `Sysvar1nstructions…`.
    BadInstructionsSysvar,
    /// No precompile invocation in the tx covered the credential's pubkey
    /// + the operation challenge.
    NoMatchingPrecompile,
    /// `client_data_json` parse / hash / challenge check failed for a
    /// WebAuthn credential.
    BadWebAuthnAssertion,
    /// The roster change would leave fewer members than the threshold.
    ThresholdAboveRoster,
    /// Adding the proposed members would exceed `MAX_MEMBERS`.
    RosterFull,
    /// `message_len` exceeded `MAX_MESSAGE_BYTES`.
    BadMessageLength,
    /// `sweep_intent::from_message_bytes` rejected the proposed bundle.
    IntentExtractionFailed,
    /// At execute, the freshly-rebuilt intent digest didn't match the
    /// proposal's stored `intent_digest`.
    IntentDigestMismatch,
    /// At execute, the proposal hadn't reached threshold.
    NotApproved,
    /// The caller-supplied index didn't match the on-account counter for
    /// the next slot. Indexes are passed as ix args (so the seed expression
    /// references a clean ident the IDL codegen can lower); the runtime
    /// check keeps the on-chain counter monotonic.
    WrongIndex,
    /// `digest_count` was 0 — a proposal must commit to at least one tx.
    BundleEmpty,
    /// `digest_count` exceeded `MAX_BUNDLE_PER_PROPOSAL`.
    BundleTooLarge,
    /// `tx_index` was >= the proposal's bundle length.
    TxIndexOutOfBounds,
    /// The given `tx_index` already had its `approve_message` CPI fired —
    /// per-tx execution is one-shot per proposal.
    TxAlreadyExecuted,
}
