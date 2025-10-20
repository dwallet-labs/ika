/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * # dWallet 2PC-MPC Coordinator Inner Module
 * 
 * This module implements the core logic for creating and managing dWallets using
 * Multi-Party Computation (MPC) protocols. It provides a trustless and
 * decentralized approach to wallet creation and key management through distributed
 * key generation (DKG) and threshold signing protocols.
 * 
 * ## Key Features
 * 
 * - Distributed Key Generation (DKG) for secure key creation
 * - Threshold signing with presign optimization
 * - Network encryption key management and reconfiguration
 * - User encryption key registration and management
 * - Session-based MPC protocol coordination
 * - Epoch-based validator committee transitions
 * - Comprehensive pricing and fee management
 * - Support for multiple cryptographic curves and algorithms
 * 
 * ## Architecture
 * 
 * The module is organized around the `DWalletCoordinatorInner` struct which
 * manages:
 * 
 * - dWallet lifecycle and state transitions
 * - MPC session coordination and scheduling
 * - Validator committee management
 * - Cryptographic algorithm support and emergency controls
 * - Economic incentives through pricing and fee collection
 */

import { MoveStruct, MoveEnum, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as sessions_manager from './sessions_manager.js';
import * as object_table from './deps/sui/object_table.js';
import * as pricing_and_fee_manager from './pricing_and_fee_manager.js';
import * as bls_committee from './deps/ika_common/bls_committee.js';
import * as support_config from './support_config.js';
import * as bag from './deps/sui/bag.js';
import * as object from './deps/sui/object.js';
import * as table_vec from './deps/sui/table_vec.js';
import * as table from './deps/sui/table.js';
const $moduleName = '@local-pkg/2pc-mpc::coordinator_inner';
export const DWalletCoordinatorWitness = new MoveStruct({ name: `${$moduleName}::DWalletCoordinatorWitness`, fields: {
        dummy_field: bcs.bool()
    } });
export const DWalletCoordinatorInner = new MoveStruct({ name: `${$moduleName}::DWalletCoordinatorInner`, fields: {
        /** Current epoch number */
        current_epoch: bcs.u64(),
        /** Session management and coordination */
        sessions_manager: sessions_manager.SessionsManager,
        /** All dWallet instances (DWallet ID -> DWallet) */
        dwallets: object_table.ObjectTable,
        /**
         * Network encryption keys (Network encryption key ID ->
         * DWalletNetworkEncryptionKey)
         */
        dwallet_network_encryption_keys: object_table.ObjectTable,
        /**
         * Number of network encryption keys reconfiguration have been completed for the
         * current epoch
         */
        epoch_dwallet_network_encryption_keys_reconfiguration_completed: bcs.u64(),
        /** User encryption keys (User encryption key address -> EncryptionKey) */
        encryption_keys: object_table.ObjectTable,
        /**
         * Presign sessions for signature optimization (Presign session ID ->
         * PresignSession)
         */
        presign_sessions: object_table.ObjectTable,
        /**
         * Partial user signatures for future signing (Partial user signature ID ->
         * PartialUserSignature)
         */
        partial_centralized_signed_messages: object_table.ObjectTable,
        /** Pricing and fee management */
        pricing_and_fee_manager: pricing_and_fee_manager.PricingAndFeeManager,
        /** Current active validator committee */
        active_committee: bls_committee.BlsCommittee,
        /** Next epoch active validator committee */
        next_epoch_active_committee: bcs.option(bls_committee.BlsCommittee),
        /** Total number of messages processed */
        total_messages_processed: bcs.u64(),
        /** Last processed checkpoint sequence number */
        last_processed_checkpoint_sequence_number: bcs.u64(),
        /** Last checkpoint sequence number from previous epoch */
        previous_epoch_last_checkpoint_sequence_number: bcs.u64(),
        /** Cryptographic algorithm support configuration */
        support_config: support_config.SupportConfig,
        received_end_of_publish: bcs.bool(),
        /** Any extra fields that's not defined statically */
        extra_fields: bag.Bag
    } });
export const DWalletCap = new MoveStruct({ name: `${$moduleName}::DWalletCap`, fields: {
        id: object.UID,
        /** ID of the controlled dWallet */
        dwallet_id: bcs.Address
    } });
export const ImportedKeyDWalletCap = new MoveStruct({ name: `${$moduleName}::ImportedKeyDWalletCap`, fields: {
        id: object.UID,
        /** ID of the controlled imported key dWallet */
        dwallet_id: bcs.Address
    } });
/** State of a dWallet network encryption key throughout its lifecycle */
export const DWalletNetworkEncryptionKeyState = new MoveEnum({ name: `${$moduleName}::DWalletNetworkEncryptionKeyState`, fields: {
        /** DKG request was sent to the network, but didn't finish yet. */
        AwaitingNetworkDKG: null,
        /** Network DKG has completed successfully */
        NetworkDKGCompleted: null,
        /** Reconfiguration request was sent to the network, but didn't finish yet. */
        AwaitingNetworkReconfiguration: null,
        /** Network reconfiguration has completed successfully */
        NetworkReconfigurationCompleted: null
    } });
export const DWalletNetworkEncryptionKey = new MoveStruct({ name: `${$moduleName}::DWalletNetworkEncryptionKey`, fields: {
        id: object.UID,
        /** Epoch when the network DKG was initiated */
        dkg_at_epoch: bcs.u64(),
        /** Initial network DKG output (chunked for storage efficiency) */
        network_dkg_public_output: table_vec.TableVec,
        /** Reconfiguration outputs indexed by epoch (Epoch -> Chunked Output) */
        reconfiguration_public_outputs: table.Table,
        /** Parameters for network dkg */
        dkg_params_for_network: bcs.vector(bcs.u8()),
        /** Curves supported by this network encryption key */
        supported_curves: bcs.vector(bcs.u32()),
        /** Current operational state */
        state: DWalletNetworkEncryptionKeyState
    } });
export const EncryptionKey = new MoveStruct({ name: `${$moduleName}::EncryptionKey`, fields: {
        /** Unique identifier for this encryption key */
        id: object.UID,
        /** Epoch when this key was created */
        created_at_epoch: bcs.u64(),
        /** Cryptographic curve this key supports */
        curve: bcs.u32(),
        /** Serialized encryption key data */
        encryption_key: bcs.vector(bcs.u8()),
        /**
         * Ed25519 signature proving encryption key authenticity, signed by the
         * `signer_public_key`. Used to verify the data originated from the
         * `signer_address`.
         */
        encryption_key_signature: bcs.vector(bcs.u8()),
        /** Ed25519 public key used to create the signature */
        signer_public_key: bcs.vector(bcs.u8()),
        /** Address of the encryption key owner */
        signer_address: bcs.Address
    } });
/**
 * State of an encrypted user secret key share throughout verification and
 * acceptance
 */
export const EncryptedUserSecretKeyShareState = new MoveEnum({ name: `${$moduleName}::EncryptedUserSecretKeyShareState`, fields: {
        /** Waiting for network to verify the encryption proof */
        AwaitingNetworkVerification: null,
        /** Network has successfully verified the encryption */
        NetworkVerificationCompleted: null,
        /** Network has rejected the encryption verification */
        NetworkVerificationRejected: null,
        /** Key holder has signed and accepted the share */
        KeyHolderSigned: new MoveStruct({ name: `EncryptedUserSecretKeyShareState.KeyHolderSigned`, fields: {
                user_output_signature: bcs.vector(bcs.u8())
            } })
    } });
export const EncryptedUserSecretKeyShare = new MoveStruct({ name: `${$moduleName}::EncryptedUserSecretKeyShare`, fields: {
        /** Unique identifier for this encrypted share */
        id: object.UID,
        /** Epoch when this share was created */
        created_at_epoch: bcs.u64(),
        /** ID of the dWallet this share belongs to */
        dwallet_id: bcs.Address,
        /**
         * Encrypted secret share with zero-knowledge proof of correctness for the
         * dWallet's secret key share (of `dwallet_id`).
         */
        encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
        /** ID of the encryption key used for encryption */
        encryption_key_id: bcs.Address,
        /** Address of the encryption key owner */
        encryption_key_address: bcs.Address,
        /** Source share ID if this was created via re-encryption (None for DKG-created) */
        source_encrypted_user_secret_key_share_id: bcs.option(bcs.Address),
        /** Current verification and acceptance state */
        state: EncryptedUserSecretKeyShareState
    } });
export const UnverifiedPartialUserSignatureCap = new MoveStruct({ name: `${$moduleName}::UnverifiedPartialUserSignatureCap`, fields: {
        /** Unique identifier for this capability */
        id: object.UID,
        /** ID of the associated partial user signature */
        partial_centralized_signed_message_id: bcs.Address
    } });
export const VerifiedPartialUserSignatureCap = new MoveStruct({ name: `${$moduleName}::VerifiedPartialUserSignatureCap`, fields: {
        /** Unique identifier for this capability */
        id: object.UID,
        /** ID of the associated verified partial user signature */
        partial_centralized_signed_message_id: bcs.Address
    } });
export const VerifiedPresignCap = new MoveStruct({ name: `${$moduleName}::VerifiedPresignCap`, fields: {
        id: object.UID,
        /**
         * Target dWallet ID for dWallet-specific presigns
         *
         * - `Some(id)`: Can only be used with the specified dWallet (e.g. ECDSA
         *   requirement)
         * - `None`: Global presign, can be used with any compatible dWallet (e.g. Schnorr
         *   and EdDSA)
         */
        dwallet_id: bcs.option(bcs.Address),
        /** ID of the associated presign session */
        presign_id: bcs.Address
    } });
export const PartialUserSignatureState = new MoveEnum({ name: `${$moduleName}::PartialUserSignatureState`, fields: {
        AwaitingNetworkVerification: null,
        NetworkVerificationCompleted: null,
        NetworkVerificationRejected: null
    } });
export const PartialUserSignature = new MoveStruct({ name: `${$moduleName}::PartialUserSignature`, fields: {
        /** Unique identifier for this partial signature */
        id: object.UID,
        /** Epoch when this partial signature was created */
        created_at_epoch: bcs.u64(),
        /** Presign capability (consumed to prevent reuse) */
        presign_cap: VerifiedPresignCap,
        /** ID of the dWallet that will complete the signature */
        dwallet_id: bcs.Address,
        /** ID of the capability that controls completion */
        cap_id: bcs.Address,
        /** Cryptographic curve for the signature */
        curve: bcs.u32(),
        /** Signature algorithm to be used */
        signature_algorithm: bcs.u32(),
        /** Hash scheme to apply to the message */
        hash_scheme: bcs.u32(),
        /** Raw message bytes to be signed */
        message: bcs.vector(bcs.u8()),
        /** User's partial signature on the message */
        message_centralized_signature: bcs.vector(bcs.u8()),
        /** Current verification state */
        state: PartialUserSignatureState
    } });
/**
 * State of a dWallet throughout its creation and operational lifecycle.
 *
 * dWallets can be created through two paths:
 *
 * 1.  **DKG Path**: Distributed Key Generation with validator participation
 * 2.  **Import Path**: Importing existing private keys with network verification
 *
 * Both paths converge to the `Active` state where signing operations can be
 * performed.
 */
export const DWalletState = new MoveEnum({ name: `${$moduleName}::DWalletState`, fields: {
        /** DKG first round has been requested from the network */
        DKGRequested: null,
        /** Network rejected the DKG first round request */
        NetworkRejectedDKGRequest: null,
        /** DKG first round completed, waiting for user to initiate second round */
        AwaitingUserDKGVerificationInitiation: new MoveStruct({ name: `DWalletState.AwaitingUserDKGVerificationInitiation`, fields: {
                first_round_output: bcs.vector(bcs.u8())
            } }),
        /** DKG second round has been requested, waiting for network verification */
        AwaitingNetworkDKGVerification: null,
        /** Network rejected the DKG second round verification */
        NetworkRejectedDKGVerification: null,
        /** Imported key verification requested, waiting for network verification */
        AwaitingNetworkImportedKeyVerification: null,
        /** Network rejected the imported key verification */
        NetworkRejectedImportedKeyVerification: null,
        /** DKG/Import completed, waiting for key holder to sign and accept */
        AwaitingKeyHolderSignature: new MoveStruct({ name: `DWalletState.AwaitingKeyHolderSignature`, fields: {
                public_output: bcs.vector(bcs.u8())
            } }),
        /** dWallet is fully operational and ready for signing */
        Active: new MoveStruct({ name: `DWalletState.Active`, fields: {
                public_output: bcs.vector(bcs.u8())
            } })
    } });
export const DWallet = new MoveStruct({ name: `${$moduleName}::DWallet`, fields: {
        /** Unique identifier for the dWallet */
        id: object.UID,
        /** Epoch when this dWallet was created */
        created_at_epoch: bcs.u64(),
        /** Elliptic curve used for cryptographic operations */
        curve: bcs.u32(),
        /**
         * Public user secret key share (if trust-minimized mode is enabled)
         *
         * - `None`: Zero-trust mode - user participation required for signing
         * - `Some(share)`: Trust-minimized mode - network can sign independently
         */
        public_user_secret_key_share: bcs.option(bcs.vector(bcs.u8())),
        /** ID of the capability that controls this dWallet */
        dwallet_cap_id: bcs.Address,
        /** Network encryption key used for securing this dWallet's network share */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Whether this dWallet was created from an imported key */
        is_imported_key_dwallet: bcs.bool(),
        /**
         * Encrypted user secret key shares (Encryption user secret key share ID ->
         * EncryptedUserSecretKeyShare)
         */
        encrypted_user_secret_key_shares: object_table.ObjectTable,
        /** Signing sessions (Sign ID -> SignSession) */
        sign_sessions: object_table.ObjectTable,
        /** Current state of the dWallet */
        state: DWalletState
    } });
export const UnverifiedPresignCap = new MoveStruct({ name: `${$moduleName}::UnverifiedPresignCap`, fields: {
        id: object.UID,
        /**
         * Target dWallet ID for dWallet-specific presigns
         *
         * - `Some(id)`: Can only be used with the specified dWallet (e.g. ECDSA
         *   requirement)
         * - `None`: Global presign, can be used with any compatible dWallet (e.g. Schnorr
         *   and EdDSA)
         */
        dwallet_id: bcs.option(bcs.Address),
        /** ID of the associated presign session */
        presign_id: bcs.Address
    } });
/**
 * State progression of a presign session through its lifecycle.
 *
 * Presign sessions follow a linear progression from request to completion, with
 * potential rejection at the network validation stage.
 */
export const PresignState = new MoveEnum({ name: `${$moduleName}::PresignState`, fields: {
        /** Presign has been requested and is awaiting network processing */
        Requested: null,
        /**
         * Network rejected the presign request (invalid parameters, insufficient
         * resources, etc.)
         */
        NetworkRejected: null,
        /** Presign completed successfully with cryptographic material ready for use */
        Completed: new MoveStruct({ name: `PresignState.Completed`, fields: {
                presign: bcs.vector(bcs.u8())
            } })
    } });
export const PresignSession = new MoveStruct({ name: `${$moduleName}::PresignSession`, fields: {
        /** Unique identifier for this presign session */
        id: object.UID,
        /** Epoch when this presign was created */
        created_at_epoch: bcs.u64(),
        /** Elliptic curve used for the presign */
        curve: bcs.u32(),
        /** Signature algorithm this presign supports */
        signature_algorithm: bcs.u32(),
        /**
         * Target dWallet ID (None for global presigns)
         *
         * - `Some(id)`: dWallet-specific presign (e.g. required for ECDSA)
         * - `None`: Global presign (e.g. available for Schnorr, EdDSA)
         */
        dwallet_id: bcs.option(bcs.Address),
        /** ID of the capability that controls this presign */
        cap_id: bcs.Address,
        /** Current state of the presign computation */
        state: PresignState
    } });
/**
 * State progression of a signing session through its lifecycle.
 *
 * Signing sessions combine user authorization with network cryptographic
 * operations to produce final signatures.
 */
export const SignState = new MoveEnum({ name: `${$moduleName}::SignState`, fields: {
        /** Signature has been requested and is awaiting network processing */
        Requested: null,
        /**
         * Network rejected the signature request (invalid presign, unauthorized message,
         * etc.)
         */
        NetworkRejected: null,
        /** Signature completed successfully and ready for use */
        Completed: new MoveStruct({ name: `SignState.Completed`, fields: {
                signature: bcs.vector(bcs.u8())
            } })
    } });
export const SignSession = new MoveStruct({ name: `${$moduleName}::SignSession`, fields: {
        id: object.UID,
        /** Epoch when this signing session was initiated */
        created_at_epoch: bcs.u64(),
        /** ID of the dWallet performing the signature */
        dwallet_id: bcs.Address,
        /** Current state of the signing process */
        state: SignState
    } });
export const MessageApproval = new MoveStruct({ name: `${$moduleName}::MessageApproval`, fields: {
        /** ID of the dWallet authorized to sign this message */
        dwallet_id: bcs.Address,
        /** Cryptographic signature algorithm to use */
        signature_algorithm: bcs.u32(),
        /** Hash scheme to apply to the message before signing */
        hash_scheme: bcs.u32(),
        /** Raw message bytes to be signed */
        message: bcs.vector(bcs.u8())
    } });
export const ImportedKeyMessageApproval = new MoveStruct({ name: `${$moduleName}::ImportedKeyMessageApproval`, fields: {
        /** ID of the imported key dWallet authorized to sign this message */
        dwallet_id: bcs.Address,
        /** Cryptographic signature algorithm to use */
        signature_algorithm: bcs.u32(),
        /** Hash scheme to apply to the message before signing */
        hash_scheme: bcs.u32(),
        /** Raw message bytes to be signed */
        message: bcs.vector(bcs.u8())
    } });
export const DWalletNetworkDKGEncryptionKeyRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletNetworkDKGEncryptionKeyRequestEvent`, fields: {
        /** ID of the network encryption key to be generated */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Parameters for the network */
        params_for_network: bcs.vector(bcs.u8())
    } });
export const CompletedDWalletNetworkDKGEncryptionKeyEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletNetworkDKGEncryptionKeyEvent`, fields: {
        /** ID of the successfully generated network encryption key */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const RejectedDWalletNetworkDKGEncryptionKeyEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletNetworkDKGEncryptionKeyEvent`, fields: {
        /** ID of the rejected network encryption key */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const DWalletEncryptionKeyReconfigurationRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletEncryptionKeyReconfigurationRequestEvent`, fields: {
        /** ID of the network encryption key to be reconfigured */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const CompletedDWalletEncryptionKeyReconfigurationEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletEncryptionKeyReconfigurationEvent`, fields: {
        /** ID of the successfully reconfigured network encryption key */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const RejectedDWalletEncryptionKeyReconfigurationEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletEncryptionKeyReconfigurationEvent`, fields: {
        /** ID of the network encryption key that failed reconfiguration */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const DWalletDKGFirstRoundRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletDKGFirstRoundRequestEvent`, fields: {
        /** ID of the dWallet being created */
        dwallet_id: bcs.Address,
        /** ID of the capability that controls the dWallet */
        dwallet_cap_id: bcs.Address,
        /** Network encryption key for securing the dWallet's network share */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the dWallet's cryptographic operations */
        curve: bcs.u32()
    } });
export const CompletedDWalletDKGFirstRoundEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletDKGFirstRoundEvent`, fields: {
        /** ID of the dWallet being created */
        dwallet_id: bcs.Address,
        /** Public output from the first round of DKG */
        first_round_output: bcs.vector(bcs.u8())
    } });
export const RejectedDWalletDKGFirstRoundEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletDKGFirstRoundEvent`, fields: {
        /** ID of the dWallet whose DKG first round was rejected */
        dwallet_id: bcs.Address
    } });
export const DWalletDKGSecondRoundRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletDKGSecondRoundRequestEvent`, fields: {
        /** ID of the encrypted user secret key share being created */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the dWallet being created through DKG */
        dwallet_id: bcs.Address,
        /** Cryptographic output from the network's first round of DKG */
        first_round_output: bcs.vector(bcs.u8()),
        /** User's public key share with cryptographic proof of correctness */
        centralized_public_key_share_and_proof: bcs.vector(bcs.u8()),
        /** ID of the dWallet capability that authorizes this operation */
        dwallet_cap_id: bcs.Address,
        /** User's encrypted secret key share with zero-knowledge proof */
        encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
        /** Serialized encryption key used to encrypt the user's secret share */
        encryption_key: bcs.vector(bcs.u8()),
        /** ID of the encryption key object */
        encryption_key_id: bcs.Address,
        /** Address of the encryption key owner */
        encryption_key_address: bcs.Address,
        /** User's contribution to the DKG public output */
        user_public_output: bcs.vector(bcs.u8()),
        /** Ed25519 public key for verifying the user's signature */
        signer_public_key: bcs.vector(bcs.u8()),
        /** ID of the network encryption key for securing network shares */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the dWallet's cryptographic operations */
        curve: bcs.u32()
    } });
export const CompletedDWalletDKGSecondRoundEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletDKGSecondRoundEvent`, fields: {
        /** ID of the successfully created dWallet */
        dwallet_id: bcs.Address,
        /** Complete public output from the DKG process (public key and metadata) */
        public_output: bcs.vector(bcs.u8()),
        /** ID of the user's encrypted secret key share */
        encrypted_user_secret_key_share_id: bcs.Address
    } });
export const RejectedDWalletDKGSecondRoundEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletDKGSecondRoundEvent`, fields: {
        /** ID of the dWallet whose DKG second round was rejected */
        dwallet_id: bcs.Address,
        /** Public output that was being processed when rejection occurred */
        public_output: bcs.vector(bcs.u8())
    } });
export const DWalletDKGRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletDKGRequestEvent`, fields: {
        /** ID of the encrypted user secret key share being created */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the dWallet being created through DKG */
        dwallet_id: bcs.Address,
        /** User's public key share with cryptographic proof of correctness */
        centralized_public_key_share_and_proof: bcs.vector(bcs.u8()),
        /** ID of the dWallet capability that authorizes this operation */
        dwallet_cap_id: bcs.Address,
        /** User's encrypted secret key share with zero-knowledge proof */
        encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
        /** Serialized encryption key used to encrypt the user's secret share */
        encryption_key: bcs.vector(bcs.u8()),
        /** ID of the encryption key object */
        encryption_key_id: bcs.Address,
        /** Address of the encryption key owner */
        encryption_key_address: bcs.Address,
        /** User's contribution to the DKG public output */
        user_public_output: bcs.vector(bcs.u8()),
        /** Ed25519 public key for verifying the user's signature */
        signer_public_key: bcs.vector(bcs.u8()),
        /** ID of the network encryption key for securing network shares */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the dWallet's cryptographic operations */
        curve: bcs.u32()
    } });
export const CompletedDWalletDKGEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletDKGEvent`, fields: {
        /** ID of the successfully created dWallet */
        dwallet_id: bcs.Address,
        /** Complete public output from the DKG process (public key and metadata) */
        public_output: bcs.vector(bcs.u8()),
        /** ID of the user's encrypted secret key share */
        encrypted_user_secret_key_share_id: bcs.Address
    } });
export const RejectedDWalletDKGEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletDKGEvent`, fields: {
        /** ID of the dWallet whose DKG second round was rejected */
        dwallet_id: bcs.Address,
        /** Public output that was being processed when rejection occurred */
        public_output: bcs.vector(bcs.u8())
    } });
export const DWalletImportedKeyVerificationRequestEvent = new MoveStruct({ name: `${$moduleName}::DWalletImportedKeyVerificationRequestEvent`, fields: {
        /** ID of the imported key dWallet being verified */
        dwallet_id: bcs.Address,
        /** ID of the encrypted user secret key share being created */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** User's cryptographic message for importing computation */
        centralized_party_message: bcs.vector(bcs.u8()),
        /** ID of the imported key dWallet capability */
        dwallet_cap_id: bcs.Address,
        /** User's encrypted secret key share with proof of correctness */
        encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
        /** Serialized encryption key used for user share encryption */
        encryption_key: bcs.vector(bcs.u8()),
        /** ID of the encryption key object */
        encryption_key_id: bcs.Address,
        /** Address of the encryption key owner */
        encryption_key_address: bcs.Address,
        /** User's public key contribution and verification data */
        user_public_output: bcs.vector(bcs.u8()),
        /**
         * Ed25519 public key for signature verification, used to verify the user's
         * signature on the public output
         */
        signer_public_key: bcs.vector(bcs.u8()),
        /** ID of the network encryption key for securing network shares */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the imported key dWallet */
        curve: bcs.u32()
    } });
export const CompletedDWalletImportedKeyVerificationEvent = new MoveStruct({ name: `${$moduleName}::CompletedDWalletImportedKeyVerificationEvent`, fields: {
        /** ID of the successfully verified imported key dWallet */
        dwallet_id: bcs.Address,
        /** Public output from the verification process */
        public_output: bcs.vector(bcs.u8()),
        /** ID of the user's encrypted secret key share */
        encrypted_user_secret_key_share_id: bcs.Address
    } });
export const RejectedDWalletImportedKeyVerificationEvent = new MoveStruct({ name: `${$moduleName}::RejectedDWalletImportedKeyVerificationEvent`, fields: {
        /** ID of the imported key dWallet that failed verification */
        dwallet_id: bcs.Address
    } });
export const CreatedEncryptionKeyEvent = new MoveStruct({ name: `${$moduleName}::CreatedEncryptionKeyEvent`, fields: {
        /** ID of the newly created encryption key */
        encryption_key_id: bcs.Address,
        /** Address of the encryption key owner */
        signer_address: bcs.Address
    } });
export const EncryptedShareVerificationRequestEvent = new MoveStruct({ name: `${$moduleName}::EncryptedShareVerificationRequestEvent`, fields: {
        /** User's encrypted secret key share with zero-knowledge proof of correctness */
        encrypted_centralized_secret_share_and_proof: bcs.vector(bcs.u8()),
        /**
         * Public output of the dWallet (used for verification), this is the public output
         * of the dWallet that the user's share is being encrypted to. This value is taken
         * from the the dWallet object during event creation, and we cannot get it from the
         * user's side.
         */
        public_output: bcs.vector(bcs.u8()),
        /** ID of the dWallet this encrypted share belongs to */
        dwallet_id: bcs.Address,
        /** Serialized encryption key used for the re-encryption */
        encryption_key: bcs.vector(bcs.u8()),
        /** ID of the encryption key object */
        encryption_key_id: bcs.Address,
        /** ID of the new encrypted user secret key share being created */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the source encrypted share (if this is a re-encryption) */
        source_encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the network encryption key securing network shares */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the dWallet */
        curve: bcs.u32()
    } });
export const CompletedEncryptedShareVerificationEvent = new MoveStruct({ name: `${$moduleName}::CompletedEncryptedShareVerificationEvent`, fields: {
        /** ID of the successfully verified encrypted user secret key share */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the dWallet associated with this encrypted share */
        dwallet_id: bcs.Address
    } });
export const RejectedEncryptedShareVerificationEvent = new MoveStruct({ name: `${$moduleName}::RejectedEncryptedShareVerificationEvent`, fields: {
        /** ID of the encrypted user secret key share that failed verification */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the dWallet associated with the failed share */
        dwallet_id: bcs.Address
    } });
export const AcceptEncryptedUserShareEvent = new MoveStruct({ name: `${$moduleName}::AcceptEncryptedUserShareEvent`, fields: {
        /** ID of the accepted encrypted user secret key share */
        encrypted_user_secret_key_share_id: bcs.Address,
        /** ID of the dWallet associated with this share */
        dwallet_id: bcs.Address,
        /** User's signature on the public output proving acceptance */
        user_output_signature: bcs.vector(bcs.u8()),
        /** ID of the encryption key used for this share */
        encryption_key_id: bcs.Address,
        /** Address of the user who accepted the share */
        encryption_key_address: bcs.Address
    } });
export const MakeDWalletUserSecretKeySharePublicRequestEvent = new MoveStruct({ name: `${$moduleName}::MakeDWalletUserSecretKeySharePublicRequestEvent`, fields: {
        /** The user's secret key share to be made public */
        public_user_secret_key_share: bcs.vector(bcs.u8()),
        /** dWallet's public output for verification */
        public_output: bcs.vector(bcs.u8()),
        /** Elliptic curve for the dWallet */
        curve: bcs.u32(),
        /** ID of the dWallet being transitioned to trust-minimized mode */
        dwallet_id: bcs.Address,
        /** ID of the network encryption key */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const CompletedMakeDWalletUserSecretKeySharePublicEvent = new MoveStruct({ name: `${$moduleName}::CompletedMakeDWalletUserSecretKeySharePublicEvent`, fields: {
        /** ID of the dWallet that successfully transitioned to trust-minimized mode */
        dwallet_id: bcs.Address,
        /** The user's secret key share that was made public */
        public_user_secret_key_share: bcs.vector(bcs.u8())
    } });
export const RejectedMakeDWalletUserSecretKeySharePublicEvent = new MoveStruct({ name: `${$moduleName}::RejectedMakeDWalletUserSecretKeySharePublicEvent`, fields: {
        /** ID of the dWallet that failed to transition to trust-minimized mode */
        dwallet_id: bcs.Address
    } });
export const PresignRequestEvent = new MoveStruct({ name: `${$moduleName}::PresignRequestEvent`, fields: {
        /**
           * Target dWallet ID for dWallet-specific presigns
           *
           * - `Some(id)`: dWallet-specific presign (required for ECDSA)
           * - `None`: Global presign (available for Schnorr, EdDSA)
           */
        dwallet_id: bcs.option(bcs.Address),
        /** Unique identifier for this presign session */
        presign_id: bcs.Address,
        /** dWallet's public output for verification (None for global presigns) */
        dwallet_public_output: bcs.option(bcs.vector(bcs.u8())),
        /** ID of the network encryption key securing the presign */
        dwallet_network_encryption_key_id: bcs.Address,
        /** Elliptic curve for the presign computation */
        curve: bcs.u32(),
        /** Signature algorithm for the presign (determines presign type) */
        signature_algorithm: bcs.u32()
    } });
export const CompletedPresignEvent = new MoveStruct({ name: `${$moduleName}::CompletedPresignEvent`, fields: {
        /** Target dWallet ID (None for global presigns) */
        dwallet_id: bcs.option(bcs.Address),
        /** Unique identifier for the completed presign */
        presign_id: bcs.Address,
        /** Precomputed cryptographic material for signature acceleration */
        presign: bcs.vector(bcs.u8())
    } });
export const RejectedPresignEvent = new MoveStruct({ name: `${$moduleName}::RejectedPresignEvent`, fields: {
        /** Target dWallet ID (None for global presigns) */
        dwallet_id: bcs.option(bcs.Address),
        /** ID of the presign that failed generation */
        presign_id: bcs.Address
    } });
export const SignRequestEvent = new MoveStruct({ name: `${$moduleName}::SignRequestEvent`, fields: {
        /** Unique identifier for this signing session */
        sign_id: bcs.Address,
        /** ID of the dWallet performing the signature */
        dwallet_id: bcs.Address,
        /** dWallet's public output for signature verification */
        dwallet_public_output: bcs.vector(bcs.u8()),
        /** Elliptic curve for the signature */
        curve: bcs.u32(),
        /** Cryptographic signature algorithm */
        signature_algorithm: bcs.u32(),
        /** Hash scheme applied to the message */
        hash_scheme: bcs.u32(),
        /** Raw message bytes to be signed */
        message: bcs.vector(bcs.u8()),
        /** ID of the network encryption key securing network shares */
        dwallet_network_encryption_key_id: bcs.Address,
        /** ID of the presign used for acceleration */
        presign_id: bcs.Address,
        /** Precomputed cryptographic material for fast signing */
        presign: bcs.vector(bcs.u8()),
        /** User's partial signature on the message */
        message_centralized_signature: bcs.vector(bcs.u8()),
        /** Whether this uses future sign capabilities */
        is_future_sign: bcs.bool()
    } });
export const CompletedSignEvent = new MoveStruct({ name: `${$moduleName}::CompletedSignEvent`, fields: {
        /** Unique identifier for the completed signing session */
        sign_id: bcs.Address,
        /** Complete cryptographic signature ready for use */
        signature: bcs.vector(bcs.u8()),
        /** Whether this signature used future sign capabilities */
        is_future_sign: bcs.bool()
    } });
export const RejectedSignEvent = new MoveStruct({ name: `${$moduleName}::RejectedSignEvent`, fields: {
        /** ID of the signing session that failed */
        sign_id: bcs.Address,
        /** Whether this rejection involved future sign capabilities */
        is_future_sign: bcs.bool()
    } });
export const FutureSignRequestEvent = new MoveStruct({ name: `${$moduleName}::FutureSignRequestEvent`, fields: {
        /** ID of the dWallet that will complete the future signature */
        dwallet_id: bcs.Address,
        /** ID of the partial user signature being validated */
        partial_centralized_signed_message_id: bcs.Address,
        /** Message that will be signed when conditions are met */
        message: bcs.vector(bcs.u8()),
        /** Precomputed cryptographic material for the future signature */
        presign: bcs.vector(bcs.u8()),
        /** dWallet's public output for verification */
        dwallet_public_output: bcs.vector(bcs.u8()),
        /** Elliptic curve for the signature */
        curve: bcs.u32(),
        /** Signature algorithm for the future signature */
        signature_algorithm: bcs.u32(),
        /** Hash scheme to be applied to the message */
        hash_scheme: bcs.u32(),
        /** User's partial signature proving authorization */
        message_centralized_signature: bcs.vector(bcs.u8()),
        /** ID of the network encryption key */
        dwallet_network_encryption_key_id: bcs.Address
    } });
export const CompletedFutureSignEvent = new MoveStruct({ name: `${$moduleName}::CompletedFutureSignEvent`, fields: {
        /** ID of the dWallet associated with the future signature */
        dwallet_id: bcs.Address,
        /** ID of the validated partial user signature */
        partial_centralized_signed_message_id: bcs.Address
    } });
export const RejectedFutureSignEvent = new MoveStruct({ name: `${$moduleName}::RejectedFutureSignEvent`, fields: {
        /** ID of the dWallet associated with the failed request */
        dwallet_id: bcs.Address,
        /** ID of the partial user signature that failed validation */
        partial_centralized_signed_message_id: bcs.Address
    } });
export const DWalletCheckpointInfoEvent = new MoveStruct({ name: `${$moduleName}::DWalletCheckpointInfoEvent`, fields: {
        epoch: bcs.u64(),
        sequence_number: bcs.u64()
    } });
export const SetMaxActiveSessionsBufferEvent = new MoveStruct({ name: `${$moduleName}::SetMaxActiveSessionsBufferEvent`, fields: {
        max_active_sessions_buffer: bcs.u64()
    } });
export const SetGasFeeReimbursementSuiSystemCallValueEvent = new MoveStruct({ name: `${$moduleName}::SetGasFeeReimbursementSuiSystemCallValueEvent`, fields: {
        gas_fee_reimbursement_sui_system_call_value: bcs.u64()
    } });
export const EndOfEpochEvent = new MoveStruct({ name: `${$moduleName}::EndOfEpochEvent`, fields: {
        epoch: bcs.u64()
    } });
export interface DwalletIdArguments {
    self: RawTransactionArgument<string>;
}
export interface DwalletIdOptions {
    package?: string;
    arguments: DwalletIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * === Public Functions === Returns the ID of the dWallet.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet Cap
 *
 * ### Returns
 *
 * The ID of the dWallet
 */
export function dwalletId(options: DwalletIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWalletCap`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'dwallet_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ImportedKeyDwalletIdArguments {
    self: RawTransactionArgument<string>;
}
export interface ImportedKeyDwalletIdOptions {
    package?: string;
    arguments: ImportedKeyDwalletIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns the ID of the imported key dWallet.
 *
 * ### Parameters
 *
 * - `self`: Reference to the imported key dWallet Cap
 *
 * ### Returns
 *
 * The ID of the imported key dWallet
 */
export function importedKeyDwalletId(options: ImportedKeyDwalletIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::ImportedKeyDWalletCap`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'imported_key_dwallet_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsImportedKeyDwalletArguments {
    self: RawTransactionArgument<string>;
}
export interface IsImportedKeyDwalletOptions {
    package?: string;
    arguments: IsImportedKeyDwalletArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns true if the dWallet is an imported key dWallet.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 *
 * ### Returns
 *
 * True if the dWallet is an imported key dWallet, false otherwise
 */
export function isImportedKeyDwallet(options: IsImportedKeyDwalletOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'is_imported_key_dwallet',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsDwalletActiveArguments {
    self: RawTransactionArgument<string>;
}
export interface IsDwalletActiveOptions {
    package?: string;
    arguments: IsDwalletActiveArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns true if the dWallet is active.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 *
 * ### Returns
 *
 * True if the dWallet is active, false otherwise
 */
export function isDwalletActive(options: IsDwalletActiveOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'is_dwallet_active',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface DwalletNetworkEncryptionKeyIdArguments {
    self: RawTransactionArgument<string>;
}
export interface DwalletNetworkEncryptionKeyIdOptions {
    package?: string;
    arguments: DwalletNetworkEncryptionKeyIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns the network encryption key ID of the dWallet.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 *
 * ### Returns
 *
 * The network encryption key ID of the dWallet
 */
export function dwalletNetworkEncryptionKeyId(options: DwalletNetworkEncryptionKeyIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'dwallet_network_encryption_key_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CurveArguments {
    self: RawTransactionArgument<string>;
}
export interface CurveOptions {
    package?: string;
    arguments: CurveArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns the curve of the dWallet.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 *
 * ### Returns
 *
 * The curve of the dWallet
 */
export function curve(options: CurveOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'curve',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidateActiveAndGetPublicOutputArguments {
    self: RawTransactionArgument<string>;
}
export interface ValidateActiveAndGetPublicOutputOptions {
    package?: string;
    arguments: ValidateActiveAndGetPublicOutputArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Validates that a dWallet is in active state and returns its public output.
 *
 * This function ensures that a dWallet has completed its creation process (either
 * DKG or imported key verification) and is ready for cryptographic operations like
 * signing.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet to validate
 *
 * ### Returns
 *
 * Reference to the dWallet's public output
 *
 * ### Aborts
 *
 * - `EDWalletInactive`: If the dWallet is not in the `Active` state
 *
 * ### Active State Requirements
 *
 * A dWallet is considered active when:
 *
 * - DKG process has completed successfully, OR
 * - Imported key verification has completed successfully
 * - User has accepted their encrypted key share
 * - Public output is available for cryptographic operations
 */
export function validateActiveAndGetPublicOutput(options: ValidateActiveAndGetPublicOutputOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'validate_active_and_get_public_output',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface HasSignSessionArguments {
    self: RawTransactionArgument<string>;
    signId: RawTransactionArgument<string>;
}
export interface HasSignSessionOptions {
    package?: string;
    arguments: HasSignSessionArguments | [
        self: RawTransactionArgument<string>,
        signId: RawTransactionArgument<string>
    ];
}
/**
 * Returns true if the `SignSession` object exists for the given `sign_id`.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 * - `sign_id`: ID of the sign session
 *
 * ### Returns
 *
 * True if the `SignSession` object exists, false otherwise
 */
export function hasSignSession(options: HasSignSessionOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "signId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'has_sign_session',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GetSignSessionArguments {
    self: RawTransactionArgument<string>;
    signId: RawTransactionArgument<string>;
}
export interface GetSignSessionOptions {
    package?: string;
    arguments: GetSignSessionArguments | [
        self: RawTransactionArgument<string>,
        signId: RawTransactionArgument<string>
    ];
}
/**
 * Returns a reference to the `SignSession` object for the given `sign_id`.
 *
 * ### Parameters
 *
 * - `self`: Reference to the dWallet
 * - `sign_id`: ID of the sign session
 *
 * ### Returns
 *
 * Reference to the `SignSession` object
 */
export function getSignSession(options: GetSignSessionOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::DWallet`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "signId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'get_sign_session',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GetSignSignatureArguments {
    self: RawTransactionArgument<string>;
}
export interface GetSignSignatureOptions {
    package?: string;
    arguments: GetSignSignatureArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Returns the signature of the `SignSession` object for the given `sign_id`.
 *
 * ### Parameters
 *
 * - `self`: Reference to the sign session
 *
 * ### Returns
 *
 * Option of the signature of the `SignSession` object
 */
export function getSignSignature(options: GetSignSignatureOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator_inner::SignSession`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator_inner',
        function: 'get_sign_signature',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}