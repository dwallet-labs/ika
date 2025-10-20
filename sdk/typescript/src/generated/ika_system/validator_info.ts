/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as group_ops from './deps/sui/group_ops.js';
import * as table_vec from './deps/sui/table_vec.js';
import * as extended_field from './deps/ika_common/extended_field.js';
const $moduleName = '@local-pkg/system::validator_info';
export const ValidatorInfo = new MoveStruct({ name: `${$moduleName}::ValidatorInfo`, fields: {
        /** Human-readable name of the validator */
        name: bcs.string(),
        /** Unique identifier for this validator */
        validator_id: bcs.Address,
        /**
         * The network address of the validator (could also contain extra info such as
         * port, DNS and etc.)
         */
        network_address: bcs.string(),
        /**
         * The address of the validator used for p2p activities such as state sync (could
         * also contain extra info such as port, DNS and etc.)
         */
        p2p_address: bcs.string(),
        /** The address of the consensus */
        consensus_address: bcs.string(),
        /**
         * Current epoch public keys The public key bytes corresponding to the private key
         * that the validator holds to sign checkpoint messages
         */
        protocol_pubkey_bytes: bcs.vector(bcs.u8()),
        /** The protocol public key element for cryptographic operations */
        protocol_pubkey: group_ops.Element,
        /**
         * The public key bytes corresponding to the private key that the validator uses to
         * establish TLS connections
         */
        network_pubkey_bytes: bcs.vector(bcs.u8()),
        /** The public key bytes corresponding to the consensus */
        consensus_pubkey_bytes: bcs.vector(bcs.u8()),
        /**
         * The validator's MPC public data. This key is used for the network DKG process
         * and for resharing the network MPC key Must always contain value
         */
        mpc_data_bytes: bcs.option(table_vec.TableVec),
        /**
         * Next epoch configurations - only take effect in the next epoch If none, current
         * value will stay unchanged.
         */
        next_epoch_protocol_pubkey_bytes: bcs.option(bcs.vector(bcs.u8())),
        next_epoch_network_pubkey_bytes: bcs.option(bcs.vector(bcs.u8())),
        next_epoch_consensus_pubkey_bytes: bcs.option(bcs.vector(bcs.u8())),
        next_epoch_mpc_data_bytes: bcs.option(table_vec.TableVec),
        next_epoch_network_address: bcs.option(bcs.string()),
        next_epoch_p2p_address: bcs.option(bcs.string()),
        next_epoch_consensus_address: bcs.option(bcs.string()),
        previous_mpc_data_bytes: bcs.option(table_vec.TableVec),
        /** Extended metadata field for additional validator information */
        metadata: extended_field.ExtendedField
    } });
export interface ValidatorIdArguments {
    self: RawTransactionArgument<string>;
}
export interface ValidatorIdOptions {
    package?: string;
    arguments: ValidatorIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the validator ID */
export function validatorId(options: ValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NetworkAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface NetworkAddressOptions {
    package?: string;
    arguments: NetworkAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the network address */
export function networkAddress(options: NetworkAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'network_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface P2pAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface P2pAddressOptions {
    package?: string;
    arguments: P2pAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the P2P address */
export function p2pAddress(options: P2pAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'p2p_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ConsensusAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface ConsensusAddressOptions {
    package?: string;
    arguments: ConsensusAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the consensus address */
export function consensusAddress(options: ConsensusAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'consensus_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProtocolPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface ProtocolPubkeyBytesOptions {
    package?: string;
    arguments: ProtocolPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the protocol public key bytes */
export function protocolPubkeyBytes(options: ProtocolPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'protocol_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProtocolPubkeyArguments {
    self: RawTransactionArgument<string>;
}
export interface ProtocolPubkeyOptions {
    package?: string;
    arguments: ProtocolPubkeyArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the protocol public key element */
export function protocolPubkey(options: ProtocolPubkeyOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'protocol_pubkey',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NetworkPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface NetworkPubkeyBytesOptions {
    package?: string;
    arguments: NetworkPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the network public key bytes */
export function networkPubkeyBytes(options: NetworkPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'network_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ConsensusPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface ConsensusPubkeyBytesOptions {
    package?: string;
    arguments: ConsensusPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the consensus public key bytes */
export function consensusPubkeyBytes(options: ConsensusPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'consensus_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface MpcDataBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface MpcDataBytesOptions {
    package?: string;
    arguments: MpcDataBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the MPC public data bytes */
export function mpcDataBytes(options: MpcDataBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'mpc_data_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochNetworkAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochNetworkAddressOptions {
    package?: string;
    arguments: NextEpochNetworkAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch network address */
export function nextEpochNetworkAddress(options: NextEpochNetworkAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_network_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochP2pAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochP2pAddressOptions {
    package?: string;
    arguments: NextEpochP2pAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch P2P address */
export function nextEpochP2pAddress(options: NextEpochP2pAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_p2p_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochConsensusAddressArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochConsensusAddressOptions {
    package?: string;
    arguments: NextEpochConsensusAddressArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch consensus address */
export function nextEpochConsensusAddress(options: NextEpochConsensusAddressOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_consensus_address',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochProtocolPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochProtocolPubkeyBytesOptions {
    package?: string;
    arguments: NextEpochProtocolPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch protocol public key bytes */
export function nextEpochProtocolPubkeyBytes(options: NextEpochProtocolPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_protocol_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochNetworkPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochNetworkPubkeyBytesOptions {
    package?: string;
    arguments: NextEpochNetworkPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch network public key bytes */
export function nextEpochNetworkPubkeyBytes(options: NextEpochNetworkPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_network_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochConsensusPubkeyBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochConsensusPubkeyBytesOptions {
    package?: string;
    arguments: NextEpochConsensusPubkeyBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch consensus public key bytes */
export function nextEpochConsensusPubkeyBytes(options: NextEpochConsensusPubkeyBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_consensus_pubkey_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NextEpochMpcDataBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface NextEpochMpcDataBytesOptions {
    package?: string;
    arguments: NextEpochMpcDataBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the next epoch MPC public data */
export function nextEpochMpcDataBytes(options: NextEpochMpcDataBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'next_epoch_mpc_data_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface PreviousMpcDataBytesArguments {
    self: RawTransactionArgument<string>;
}
export interface PreviousMpcDataBytesOptions {
    package?: string;
    arguments: PreviousMpcDataBytesArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the previous MPC public data */
export function previousMpcDataBytes(options: PreviousMpcDataBytesOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_info::ValidatorInfo`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_info',
        function: 'previous_mpc_data_bytes',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}