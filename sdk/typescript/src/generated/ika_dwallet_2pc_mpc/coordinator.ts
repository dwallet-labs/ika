/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
const $moduleName = '@local-pkg/2pc-mpc::coordinator';
export const DWalletCoordinator = new MoveStruct({ name: `${$moduleName}::DWalletCoordinator`, fields: {
        id: object.UID,
        version: bcs.u64(),
        package_id: bcs.Address,
        new_package_id: bcs.option(bcs.Address),
        migration_epoch: bcs.option(bcs.u64())
    } });
export interface ProcessCheckpointMessageByQuorumArguments {
    dwallet_2pcMpcCoordinator: RawTransactionArgument<string>;
    signature: RawTransactionArgument<number[]>;
    signersBitmap: RawTransactionArgument<number[]>;
    message: RawTransactionArgument<number[]>;
}
export interface ProcessCheckpointMessageByQuorumOptions {
    package?: string;
    arguments: ProcessCheckpointMessageByQuorumArguments | [
        dwallet_2pcMpcCoordinator: RawTransactionArgument<string>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
        message: RawTransactionArgument<number[]>
    ];
}
/**
 * Being called by the Ika network to store outputs of completed MPC sessions to
 * Sui.
 */
export function processCheckpointMessageByQuorum(options: ProcessCheckpointMessageByQuorumOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'vector<u8>',
        'vector<u8>',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["dwallet_2pcMpcCoordinator", "signature", "signersBitmap", "message"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'process_checkpoint_message_by_quorum',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface InitiateMidEpochReconfigurationArguments {
    self: RawTransactionArgument<string>;
    systemCurrentStatusInfo: RawTransactionArgument<string>;
}
export interface InitiateMidEpochReconfigurationOptions {
    package?: string;
    arguments: InitiateMidEpochReconfigurationArguments | [
        self: RawTransactionArgument<string>,
        systemCurrentStatusInfo: RawTransactionArgument<string>
    ];
}
export function initiateMidEpochReconfiguration(options: InitiateMidEpochReconfigurationOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self", "systemCurrentStatusInfo"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'initiate_mid_epoch_reconfiguration',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestNetworkEncryptionKeyMidEpochReconfigurationArguments {
    self: RawTransactionArgument<string>;
    dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>;
}
export interface RequestNetworkEncryptionKeyMidEpochReconfigurationOptions {
    package?: string;
    arguments: RequestNetworkEncryptionKeyMidEpochReconfigurationArguments | [
        self: RawTransactionArgument<string>,
        dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>
    ];
}
export function requestNetworkEncryptionKeyMidEpochReconfiguration(options: RequestNetworkEncryptionKeyMidEpochReconfigurationOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletNetworkEncryptionKeyId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_network_encryption_key_mid_epoch_reconfiguration',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AdvanceEpochArguments {
    self: RawTransactionArgument<string>;
    advanceEpochApprover: RawTransactionArgument<string>;
}
export interface AdvanceEpochOptions {
    package?: string;
    arguments: AdvanceEpochArguments | [
        self: RawTransactionArgument<string>,
        advanceEpochApprover: RawTransactionArgument<string>
    ];
}
export function advanceEpoch(options: AdvanceEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::advance_epoch_approver::AdvanceEpochApprover`
    ] satisfies string[];
    const parameterNames = ["self", "advanceEpochApprover"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'advance_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestDwalletNetworkEncryptionKeyDkgByCapArguments {
    self: RawTransactionArgument<string>;
    paramsForNetwork: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface RequestDwalletNetworkEncryptionKeyDkgByCapOptions {
    package?: string;
    arguments: RequestDwalletNetworkEncryptionKeyDkgByCapArguments | [
        self: RawTransactionArgument<string>,
        paramsForNetwork: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
export function requestDwalletNetworkEncryptionKeyDkgByCap(options: RequestDwalletNetworkEncryptionKeyDkgByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'vector<u8>',
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "paramsForNetwork", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_dwallet_network_encryption_key_dkg_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProcessCheckpointMessageByCapArguments {
    self: RawTransactionArgument<string>;
    message: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface ProcessCheckpointMessageByCapOptions {
    package?: string;
    arguments: ProcessCheckpointMessageByCapArguments | [
        self: RawTransactionArgument<string>,
        message: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
export function processCheckpointMessageByCap(options: ProcessCheckpointMessageByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'vector<u8>',
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "message", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'process_checkpoint_message_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetGasFeeReimbursementSuiSystemCallValueByCapArguments {
    self: RawTransactionArgument<string>;
    gasFeeReimbursementSuiSystemCallValue: RawTransactionArgument<number | bigint>;
    cap: RawTransactionArgument<string>;
}
export interface SetGasFeeReimbursementSuiSystemCallValueByCapOptions {
    package?: string;
    arguments: SetGasFeeReimbursementSuiSystemCallValueByCapArguments | [
        self: RawTransactionArgument<string>,
        gasFeeReimbursementSuiSystemCallValue: RawTransactionArgument<number | bigint>,
        cap: RawTransactionArgument<string>
    ];
}
export function setGasFeeReimbursementSuiSystemCallValueByCap(options: SetGasFeeReimbursementSuiSystemCallValueByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'u64',
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "gasFeeReimbursementSuiSystemCallValue", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'set_gas_fee_reimbursement_sui_system_call_value_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetSupportedAndPricingArguments {
    self: RawTransactionArgument<string>;
    defaultPricing: RawTransactionArgument<string>;
    supportedCurvesToSignatureAlgorithmsToHashSchemes: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetSupportedAndPricingOptions {
    package?: string;
    arguments: SetSupportedAndPricingArguments | [
        self: RawTransactionArgument<string>,
        defaultPricing: RawTransactionArgument<string>,
        supportedCurvesToSignatureAlgorithmsToHashSchemes: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function setSupportedAndPricing(options: SetSupportedAndPricingOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::pricing::PricingInfo`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::vec_map::VecMap<u32, 0x0000000000000000000000000000000000000000000000000000000000000002::vec_map::VecMap<u32, vector<u32>>>',
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "defaultPricing", "supportedCurvesToSignatureAlgorithmsToHashSchemes", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'set_supported_and_pricing',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetPausedCurvesAndSignatureAlgorithmsArguments {
    self: RawTransactionArgument<string>;
    pausedCurves: RawTransactionArgument<number[]>;
    pausedSignatureAlgorithms: RawTransactionArgument<number[]>;
    pausedHashSchemes: RawTransactionArgument<number[]>;
    cap: RawTransactionArgument<string>;
}
export interface SetPausedCurvesAndSignatureAlgorithmsOptions {
    package?: string;
    arguments: SetPausedCurvesAndSignatureAlgorithmsArguments | [
        self: RawTransactionArgument<string>,
        pausedCurves: RawTransactionArgument<number[]>,
        pausedSignatureAlgorithms: RawTransactionArgument<number[]>,
        pausedHashSchemes: RawTransactionArgument<number[]>,
        cap: RawTransactionArgument<string>
    ];
}
export function setPausedCurvesAndSignatureAlgorithms(options: SetPausedCurvesAndSignatureAlgorithmsOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'vector<u32>',
        'vector<u32>',
        'vector<u32>',
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "pausedCurves", "pausedSignatureAlgorithms", "pausedHashSchemes", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'set_paused_curves_and_signature_algorithms',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestLockEpochSessionsArguments {
    self: RawTransactionArgument<string>;
    systemCurrentStatusInfo: RawTransactionArgument<string>;
}
export interface RequestLockEpochSessionsOptions {
    package?: string;
    arguments: RequestLockEpochSessionsArguments | [
        self: RawTransactionArgument<string>,
        systemCurrentStatusInfo: RawTransactionArgument<string>
    ];
}
export function requestLockEpochSessions(options: RequestLockEpochSessionsOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::system_current_status_info::SystemCurrentStatusInfo`
    ] satisfies string[];
    const parameterNames = ["self", "systemCurrentStatusInfo"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_lock_epoch_sessions',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetPricingVoteArguments {
    self: RawTransactionArgument<string>;
    pricing: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface SetPricingVoteOptions {
    package?: string;
    arguments: SetPricingVoteArguments | [
        self: RawTransactionArgument<string>,
        pricing: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function setPricingVote(options: SetPricingVoteOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::pricing::PricingInfo`,
        `${packageAddress}::validator_cap::VerifiedValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["self", "pricing", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'set_pricing_vote',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RegisterSessionIdentifierArguments {
    self: RawTransactionArgument<string>;
    identifier: RawTransactionArgument<number[]>;
}
export interface RegisterSessionIdentifierOptions {
    package?: string;
    arguments: RegisterSessionIdentifierArguments | [
        self: RawTransactionArgument<string>,
        identifier: RawTransactionArgument<number[]>
    ];
}
export function registerSessionIdentifier(options: RegisterSessionIdentifierOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "identifier"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'register_session_identifier',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GetActiveEncryptionKeyArguments {
    self: RawTransactionArgument<string>;
    address: RawTransactionArgument<string>;
}
export interface GetActiveEncryptionKeyOptions {
    package?: string;
    arguments: GetActiveEncryptionKeyArguments | [
        self: RawTransactionArgument<string>,
        address: RawTransactionArgument<string>
    ];
}
export function getActiveEncryptionKey(options: GetActiveEncryptionKeyOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'address'
    ] satisfies string[];
    const parameterNames = ["self", "address"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'get_active_encryption_key',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RegisterEncryptionKeyArguments {
    self: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    encryptionKey: RawTransactionArgument<number[]>;
    encryptionKeySignature: RawTransactionArgument<number[]>;
    signerPublicKey: RawTransactionArgument<number[]>;
}
export interface RegisterEncryptionKeyOptions {
    package?: string;
    arguments: RegisterEncryptionKeyArguments | [
        self: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        encryptionKey: RawTransactionArgument<number[]>,
        encryptionKeySignature: RawTransactionArgument<number[]>,
        signerPublicKey: RawTransactionArgument<number[]>
    ];
}
export function registerEncryptionKey(options: RegisterEncryptionKeyOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'u32',
        'vector<u8>',
        'vector<u8>',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "curve", "encryptionKey", "encryptionKeySignature", "signerPublicKey"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'register_encryption_key',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ApproveMessageArguments {
    self: RawTransactionArgument<string>;
    dwalletCap: RawTransactionArgument<string>;
    signatureAlgorithm: RawTransactionArgument<number>;
    hashScheme: RawTransactionArgument<number>;
    message: RawTransactionArgument<number[]>;
}
export interface ApproveMessageOptions {
    package?: string;
    arguments: ApproveMessageArguments | [
        self: RawTransactionArgument<string>,
        dwalletCap: RawTransactionArgument<string>,
        signatureAlgorithm: RawTransactionArgument<number>,
        hashScheme: RawTransactionArgument<number>,
        message: RawTransactionArgument<number[]>
    ];
}
export function approveMessage(options: ApproveMessageOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::DWalletCap`,
        'u32',
        'u32',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletCap", "signatureAlgorithm", "hashScheme", "message"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'approve_message',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ApproveImportedKeyMessageArguments {
    self: RawTransactionArgument<string>;
    importedKeyDwalletCap: RawTransactionArgument<string>;
    signatureAlgorithm: RawTransactionArgument<number>;
    hashScheme: RawTransactionArgument<number>;
    message: RawTransactionArgument<number[]>;
}
export interface ApproveImportedKeyMessageOptions {
    package?: string;
    arguments: ApproveImportedKeyMessageArguments | [
        self: RawTransactionArgument<string>,
        importedKeyDwalletCap: RawTransactionArgument<string>,
        signatureAlgorithm: RawTransactionArgument<number>,
        hashScheme: RawTransactionArgument<number>,
        message: RawTransactionArgument<number[]>
    ];
}
export function approveImportedKeyMessage(options: ApproveImportedKeyMessageOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::ImportedKeyDWalletCap`,
        'u32',
        'u32',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "importedKeyDwalletCap", "signatureAlgorithm", "hashScheme", "message"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'approve_imported_key_message',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestDwalletDkgFirstRoundArguments {
    Self: RawTransactionArgument<string>;
    DwalletNetworkEncryptionKeyId: RawTransactionArgument<string>;
    Curve: RawTransactionArgument<number>;
    SessionIdentifier: RawTransactionArgument<string>;
    PaymentIka: RawTransactionArgument<string>;
    PaymentSui: RawTransactionArgument<string>;
}
export interface RequestDwalletDkgFirstRoundOptions {
    package?: string;
    arguments: RequestDwalletDkgFirstRoundArguments | [
        Self: RawTransactionArgument<string>,
        DwalletNetworkEncryptionKeyId: RawTransactionArgument<string>,
        Curve: RawTransactionArgument<number>,
        SessionIdentifier: RawTransactionArgument<string>,
        PaymentIka: RawTransactionArgument<string>,
        PaymentSui: RawTransactionArgument<string>
    ];
}
export function requestDwalletDkgFirstRound(options: RequestDwalletDkgFirstRoundOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u32',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["Self", "DwalletNetworkEncryptionKeyId", "Curve", "SessionIdentifier", "PaymentIka", "PaymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_dwallet_dkg_first_round',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestDwalletDkgSecondRoundArguments {
    Self: RawTransactionArgument<string>;
    DwalletCap: RawTransactionArgument<string>;
    CentralizedPublicKeyShareAndProof: RawTransactionArgument<number[]>;
    EncryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>;
    EncryptionKeyAddress: RawTransactionArgument<string>;
    UserPublicOutput: RawTransactionArgument<number[]>;
    SingerPublicKey: RawTransactionArgument<number[]>;
    SessionIdentifier: RawTransactionArgument<string>;
    PaymentIka: RawTransactionArgument<string>;
    PaymentSui: RawTransactionArgument<string>;
}
export interface RequestDwalletDkgSecondRoundOptions {
    package?: string;
    arguments: RequestDwalletDkgSecondRoundArguments | [
        Self: RawTransactionArgument<string>,
        DwalletCap: RawTransactionArgument<string>,
        CentralizedPublicKeyShareAndProof: RawTransactionArgument<number[]>,
        EncryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>,
        EncryptionKeyAddress: RawTransactionArgument<string>,
        UserPublicOutput: RawTransactionArgument<number[]>,
        SingerPublicKey: RawTransactionArgument<number[]>,
        SessionIdentifier: RawTransactionArgument<string>,
        PaymentIka: RawTransactionArgument<string>,
        PaymentSui: RawTransactionArgument<string>
    ];
}
export function requestDwalletDkgSecondRound(options: RequestDwalletDkgSecondRoundOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::DWalletCap`,
        'vector<u8>',
        'vector<u8>',
        'address',
        'vector<u8>',
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["Self", "DwalletCap", "CentralizedPublicKeyShareAndProof", "EncryptedCentralizedSecretShareAndProof", "EncryptionKeyAddress", "UserPublicOutput", "SingerPublicKey", "SessionIdentifier", "PaymentIka", "PaymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_dwallet_dkg_second_round',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestDwalletDkgArguments {
    self: RawTransactionArgument<string>;
    dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    centralizedPublicKeyShareAndProof: RawTransactionArgument<number[]>;
    encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>;
    encryptionKeyAddress: RawTransactionArgument<string>;
    userPublicOutput: RawTransactionArgument<number[]>;
    singerPublicKey: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestDwalletDkgOptions {
    package?: string;
    arguments: RequestDwalletDkgArguments | [
        self: RawTransactionArgument<string>,
        dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        centralizedPublicKeyShareAndProof: RawTransactionArgument<number[]>,
        encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>,
        encryptionKeyAddress: RawTransactionArgument<string>,
        userPublicOutput: RawTransactionArgument<number[]>,
        singerPublicKey: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestDwalletDkg(options: RequestDwalletDkgOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u32',
        'vector<u8>',
        'vector<u8>',
        'address',
        'vector<u8>',
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletNetworkEncryptionKeyId", "curve", "centralizedPublicKeyShareAndProof", "encryptedCentralizedSecretShareAndProof", "encryptionKeyAddress", "userPublicOutput", "singerPublicKey", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_dwallet_dkg',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CalculatePricingVotesArguments {
    self: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    signatureAlgorithm: RawTransactionArgument<number | null>;
    protocol: RawTransactionArgument<number>;
}
export interface CalculatePricingVotesOptions {
    package?: string;
    arguments: CalculatePricingVotesArguments | [
        self: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        signatureAlgorithm: RawTransactionArgument<number | null>,
        protocol: RawTransactionArgument<number>
    ];
}
export function calculatePricingVotes(options: CalculatePricingVotesOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        'u32',
        '0x0000000000000000000000000000000000000000000000000000000000000001::option::Option<u32>',
        'u32'
    ] satisfies string[];
    const parameterNames = ["self", "curve", "signatureAlgorithm", "protocol"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'calculate_pricing_votes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestImportedKeyDwalletVerificationArguments {
    self: RawTransactionArgument<string>;
    dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    centralizedPartyMessage: RawTransactionArgument<number[]>;
    encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>;
    encryptionKeyAddress: RawTransactionArgument<string>;
    userPublicOutput: RawTransactionArgument<number[]>;
    signerPublicKey: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestImportedKeyDwalletVerificationOptions {
    package?: string;
    arguments: RequestImportedKeyDwalletVerificationArguments | [
        self: RawTransactionArgument<string>,
        dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        centralizedPartyMessage: RawTransactionArgument<number[]>,
        encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>,
        encryptionKeyAddress: RawTransactionArgument<string>,
        userPublicOutput: RawTransactionArgument<number[]>,
        signerPublicKey: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestImportedKeyDwalletVerification(options: RequestImportedKeyDwalletVerificationOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u32',
        'vector<u8>',
        'vector<u8>',
        'address',
        'vector<u8>',
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletNetworkEncryptionKeyId", "curve", "centralizedPartyMessage", "encryptedCentralizedSecretShareAndProof", "encryptionKeyAddress", "userPublicOutput", "signerPublicKey", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_imported_key_dwallet_verification',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestMakeDwalletUserSecretKeySharesPublicArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
    publicUserSecretKeyShares: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestMakeDwalletUserSecretKeySharesPublicOptions {
    package?: string;
    arguments: RequestMakeDwalletUserSecretKeySharesPublicArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>,
        publicUserSecretKeyShares: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestMakeDwalletUserSecretKeySharesPublic(options: RequestMakeDwalletUserSecretKeySharesPublicOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId", "publicUserSecretKeyShares", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_make_dwallet_user_secret_key_shares_public',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestReEncryptUserShareForArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
    destinationEncryptionKeyAddress: RawTransactionArgument<string>;
    encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>;
    sourceEncryptedUserSecretKeyShareId: RawTransactionArgument<string>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestReEncryptUserShareForOptions {
    package?: string;
    arguments: RequestReEncryptUserShareForArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>,
        destinationEncryptionKeyAddress: RawTransactionArgument<string>,
        encryptedCentralizedSecretShareAndProof: RawTransactionArgument<number[]>,
        sourceEncryptedUserSecretKeyShareId: RawTransactionArgument<string>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestReEncryptUserShareFor(options: RequestReEncryptUserShareForOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'address',
        'vector<u8>',
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId", "destinationEncryptionKeyAddress", "encryptedCentralizedSecretShareAndProof", "sourceEncryptedUserSecretKeyShareId", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_re_encrypt_user_share_for',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AcceptEncryptedUserShareArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
    encryptedUserSecretKeyShareId: RawTransactionArgument<string>;
    userOutputSignature: RawTransactionArgument<number[]>;
}
export interface AcceptEncryptedUserShareOptions {
    package?: string;
    arguments: AcceptEncryptedUserShareArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>,
        encryptedUserSecretKeyShareId: RawTransactionArgument<string>,
        userOutputSignature: RawTransactionArgument<number[]>
    ];
}
export function acceptEncryptedUserShare(options: AcceptEncryptedUserShareOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId", "encryptedUserSecretKeyShareId", "userOutputSignature"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'accept_encrypted_user_share',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestPresignArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
    signatureAlgorithm: RawTransactionArgument<number>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestPresignOptions {
    package?: string;
    arguments: RequestPresignArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>,
        signatureAlgorithm: RawTransactionArgument<number>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestPresign(options: RequestPresignOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u32',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId", "signatureAlgorithm", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_presign',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestGlobalPresignArguments {
    self: RawTransactionArgument<string>;
    dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>;
    curve: RawTransactionArgument<number>;
    signatureAlgorithm: RawTransactionArgument<number>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestGlobalPresignOptions {
    package?: string;
    arguments: RequestGlobalPresignArguments | [
        self: RawTransactionArgument<string>,
        dwalletNetworkEncryptionKeyId: RawTransactionArgument<string>,
        curve: RawTransactionArgument<number>,
        signatureAlgorithm: RawTransactionArgument<number>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestGlobalPresign(options: RequestGlobalPresignOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u32',
        'u32',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletNetworkEncryptionKeyId", "curve", "signatureAlgorithm", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_global_presign',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsPresignValidArguments {
    self: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
}
export interface IsPresignValidOptions {
    package?: string;
    arguments: IsPresignValidArguments | [
        self: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>
    ];
}
export function isPresignValid(options: IsPresignValidOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::UnverifiedPresignCap`
    ] satisfies string[];
    const parameterNames = ["self", "presignCap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'is_presign_valid',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyPresignCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyPresignCapOptions {
    package?: string;
    arguments: VerifyPresignCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyPresignCap(options: VerifyPresignCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::UnverifiedPresignCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'verify_presign_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestSignArguments {
    self: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    messageCentralizedSignature: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestSignOptions {
    package?: string;
    arguments: RequestSignArguments | [
        self: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        messageCentralizedSignature: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestSign(options: RequestSignOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPresignCap`,
        `${packageAddress}::coordinator_inner::MessageApproval`,
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "presignCap", "messageApproval", "messageCentralizedSignature", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_sign',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestSignAndReturnIdArguments {
    self: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    messageCentralizedSignature: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestSignAndReturnIdOptions {
    package?: string;
    arguments: RequestSignAndReturnIdArguments | [
        self: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        messageCentralizedSignature: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestSignAndReturnId(options: RequestSignAndReturnIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPresignCap`,
        `${packageAddress}::coordinator_inner::MessageApproval`,
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "presignCap", "messageApproval", "messageCentralizedSignature", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_sign_and_return_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestImportedKeySignArguments {
    self: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    messageCentralizedSignature: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestImportedKeySignOptions {
    package?: string;
    arguments: RequestImportedKeySignArguments | [
        self: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        messageCentralizedSignature: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestImportedKeySign(options: RequestImportedKeySignOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPresignCap`,
        `${packageAddress}::coordinator_inner::ImportedKeyMessageApproval`,
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "presignCap", "messageApproval", "messageCentralizedSignature", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_imported_key_sign',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestImportedKeySignAndReturnIdArguments {
    self: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    messageCentralizedSignature: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestImportedKeySignAndReturnIdOptions {
    package?: string;
    arguments: RequestImportedKeySignAndReturnIdArguments | [
        self: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        messageCentralizedSignature: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestImportedKeySignAndReturnId(options: RequestImportedKeySignAndReturnIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPresignCap`,
        `${packageAddress}::coordinator_inner::ImportedKeyMessageApproval`,
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "presignCap", "messageApproval", "messageCentralizedSignature", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_imported_key_sign_and_return_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestFutureSignArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
    presignCap: RawTransactionArgument<string>;
    message: RawTransactionArgument<number[]>;
    hashScheme: RawTransactionArgument<number>;
    messageCentralizedSignature: RawTransactionArgument<number[]>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestFutureSignOptions {
    package?: string;
    arguments: RequestFutureSignArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>,
        presignCap: RawTransactionArgument<string>,
        message: RawTransactionArgument<number[]>,
        hashScheme: RawTransactionArgument<number>,
        messageCentralizedSignature: RawTransactionArgument<number[]>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestFutureSign(options: RequestFutureSignOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        `${packageAddress}::coordinator_inner::VerifiedPresignCap`,
        'vector<u8>',
        'u32',
        'vector<u8>',
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId", "presignCap", "message", "hashScheme", "messageCentralizedSignature", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_future_sign',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsPartialUserSignatureValidArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface IsPartialUserSignatureValidOptions {
    package?: string;
    arguments: IsPartialUserSignatureValidArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function isPartialUserSignatureValid(options: IsPartialUserSignatureValidOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::UnverifiedPartialUserSignatureCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'is_partial_user_signature_valid',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyPartialUserSignatureCapArguments {
    self: RawTransactionArgument<string>;
    cap: RawTransactionArgument<string>;
}
export interface VerifyPartialUserSignatureCapOptions {
    package?: string;
    arguments: VerifyPartialUserSignatureCapArguments | [
        self: RawTransactionArgument<string>,
        cap: RawTransactionArgument<string>
    ];
}
export function verifyPartialUserSignatureCap(options: VerifyPartialUserSignatureCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::UnverifiedPartialUserSignatureCap`
    ] satisfies string[];
    const parameterNames = ["self", "cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'verify_partial_user_signature_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestSignWithPartialUserSignatureArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestSignWithPartialUserSignatureOptions {
    package?: string;
    arguments: RequestSignWithPartialUserSignatureArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestSignWithPartialUserSignature(options: RequestSignWithPartialUserSignatureOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::MessageApproval`,
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_sign_with_partial_user_signature',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestSignWithPartialUserSignatureAndReturnIdArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestSignWithPartialUserSignatureAndReturnIdOptions {
    package?: string;
    arguments: RequestSignWithPartialUserSignatureAndReturnIdArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestSignWithPartialUserSignatureAndReturnId(options: RequestSignWithPartialUserSignatureAndReturnIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::MessageApproval`,
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_sign_with_partial_user_signature_and_return_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestImportedKeySignWithPartialUserSignatureArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestImportedKeySignWithPartialUserSignatureOptions {
    package?: string;
    arguments: RequestImportedKeySignWithPartialUserSignatureArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestImportedKeySignWithPartialUserSignature(options: RequestImportedKeySignWithPartialUserSignatureOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::ImportedKeyMessageApproval`,
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_imported_key_sign_with_partial_user_signature',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface RequestImportedKeySignWithPartialUserSignatureAndReturnIdArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
    sessionIdentifier: RawTransactionArgument<string>;
    paymentIka: RawTransactionArgument<string>;
    paymentSui: RawTransactionArgument<string>;
}
export interface RequestImportedKeySignWithPartialUserSignatureAndReturnIdOptions {
    package?: string;
    arguments: RequestImportedKeySignWithPartialUserSignatureAndReturnIdArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>,
        sessionIdentifier: RawTransactionArgument<string>,
        paymentIka: RawTransactionArgument<string>,
        paymentSui: RawTransactionArgument<string>
    ];
}
export function requestImportedKeySignWithPartialUserSignatureAndReturnId(options: RequestImportedKeySignWithPartialUserSignatureAndReturnIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::ImportedKeyMessageApproval`,
        `${packageAddress}::sessions_manager::SessionIdentifier`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval", "sessionIdentifier", "paymentIka", "paymentSui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'request_imported_key_sign_with_partial_user_signature_and_return_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface MatchPartialUserSignatureWithMessageApprovalArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
}
export interface MatchPartialUserSignatureWithMessageApprovalOptions {
    package?: string;
    arguments: MatchPartialUserSignatureWithMessageApprovalArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>
    ];
}
export function matchPartialUserSignatureWithMessageApproval(options: MatchPartialUserSignatureWithMessageApprovalOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::MessageApproval`
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'match_partial_user_signature_with_message_approval',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface MatchPartialUserSignatureWithImportedKeyMessageApprovalArguments {
    self: RawTransactionArgument<string>;
    partialUserSignatureCap: RawTransactionArgument<string>;
    messageApproval: RawTransactionArgument<string>;
}
export interface MatchPartialUserSignatureWithImportedKeyMessageApprovalOptions {
    package?: string;
    arguments: MatchPartialUserSignatureWithImportedKeyMessageApprovalArguments | [
        self: RawTransactionArgument<string>,
        partialUserSignatureCap: RawTransactionArgument<string>,
        messageApproval: RawTransactionArgument<string>
    ];
}
export function matchPartialUserSignatureWithImportedKeyMessageApproval(options: MatchPartialUserSignatureWithImportedKeyMessageApprovalOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::coordinator_inner::VerifiedPartialUserSignatureCap`,
        `${packageAddress}::coordinator_inner::ImportedKeyMessageApproval`
    ] satisfies string[];
    const parameterNames = ["self", "partialUserSignatureCap", "messageApproval"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'match_partial_user_signature_with_imported_key_message_approval',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface HasDwalletArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
}
export interface HasDwalletOptions {
    package?: string;
    arguments: HasDwalletArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>
    ];
}
export function hasDwallet(options: HasDwalletOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'has_dwallet',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface GetDwalletArguments {
    self: RawTransactionArgument<string>;
    dwalletId: RawTransactionArgument<string>;
}
export interface GetDwalletOptions {
    package?: string;
    arguments: GetDwalletArguments | [
        self: RawTransactionArgument<string>,
        dwalletId: RawTransactionArgument<string>
    ];
}
export function getDwallet(options: GetDwalletOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "dwalletId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'get_dwallet',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CurrentPricingArguments {
    self: RawTransactionArgument<string>;
}
export interface CurrentPricingOptions {
    package?: string;
    arguments: CurrentPricingArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function currentPricing(options: CurrentPricingOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'current_pricing',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SubsidizeCoordinatorWithSuiArguments {
    self: RawTransactionArgument<string>;
    sui: RawTransactionArgument<string>;
}
export interface SubsidizeCoordinatorWithSuiOptions {
    package?: string;
    arguments: SubsidizeCoordinatorWithSuiArguments | [
        self: RawTransactionArgument<string>,
        sui: RawTransactionArgument<string>
    ];
}
/**
 * Fund the coordinator with SUI - this let you subsidize the protocol. IMPORTANT:
 * YOU WON'T BE ABLE TO WITHDRAW THE FUNDS OR GET ANYTHING IN RETURN.
 */
export function subsidizeCoordinatorWithSui(options: SubsidizeCoordinatorWithSuiOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>'
    ] satisfies string[];
    const parameterNames = ["self", "sui"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'subsidize_coordinator_with_sui',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SubsidizeCoordinatorWithIkaArguments {
    self: RawTransactionArgument<string>;
    ika: RawTransactionArgument<string>;
}
export interface SubsidizeCoordinatorWithIkaOptions {
    package?: string;
    arguments: SubsidizeCoordinatorWithIkaArguments | [
        self: RawTransactionArgument<string>,
        ika: RawTransactionArgument<string>
    ];
}
/**
 * Fund the coordinator with IKA - this let you subsidize the protocol. IMPORTANT:
 * YOU WON'T BE ABLE TO WITHDRAW THE FUNDS OR GET ANYTHING IN RETURN.
 */
export function subsidizeCoordinatorWithIka(options: SubsidizeCoordinatorWithIkaOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<${packageAddress}::ika::IKA>`
    ] satisfies string[];
    const parameterNames = ["self", "ika"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'subsidize_coordinator_with_ika',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CommitUpgradeArguments {
    self: RawTransactionArgument<string>;
    upgradePackageApprover: RawTransactionArgument<string>;
}
export interface CommitUpgradeOptions {
    package?: string;
    arguments: CommitUpgradeArguments | [
        self: RawTransactionArgument<string>,
        upgradePackageApprover: RawTransactionArgument<string>
    ];
}
export function commitUpgrade(options: CommitUpgradeOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self", "upgradePackageApprover"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'commit_upgrade',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface TryMigrateByCapArguments {
    self: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface TryMigrateByCapOptions {
    package?: string;
    arguments: TryMigrateByCapArguments | [
        self: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
/**
 * Try to migrate the coordinator object to the new package id using a cap.
 *
 * This function sets the new package id and version and can be modified in future
 * versions to migrate changes in the `coordinator_inner` object if needed. This
 * function can be called immediately after the upgrade is committed.
 */
export function tryMigrateByCap(options: TryMigrateByCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`,
        `${packageAddress}::protocol_cap::VerifiedProtocolCap`
    ] satisfies string[];
    const parameterNames = ["self", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'try_migrate_by_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface TryMigrateArguments {
    self: RawTransactionArgument<string>;
}
export interface TryMigrateOptions {
    package?: string;
    arguments: TryMigrateArguments | [
        self: RawTransactionArgument<string>
    ];
}
/**
 * Try to migrate the coordinator object to the new package id.
 *
 * This function sets the new package id and version and can be modified in future
 * versions to migrate changes in the `coordinator_inner` object if needed. Call
 * this function after the migration epoch is reached.
 */
export function tryMigrate(options: TryMigrateOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'try_migrate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VersionArguments {
    self: RawTransactionArgument<string>;
}
export interface VersionOptions {
    package?: string;
    arguments: VersionArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function version(options: VersionOptions) {
    const packageAddress = options.package ?? '@local-pkg/2pc-mpc';
    const argumentsTypes = [
        `${packageAddress}::coordinator::DWalletCoordinator`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'coordinator',
        function: 'version',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}