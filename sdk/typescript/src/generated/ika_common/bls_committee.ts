/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as group_ops from './deps/sui/group_ops.js';
const $moduleName = '@local-pkg/common::bls_committee';
export const BlsCommitteeMember = new MoveStruct({ name: `${$moduleName}::BlsCommitteeMember`, fields: {
        validator_id: bcs.Address,
        protocol_pubkey: group_ops.Element
    } });
export const BlsCommittee = new MoveStruct({ name: `${$moduleName}::BlsCommittee`, fields: {
        members: bcs.vector(BlsCommitteeMember),
        /** The aggregation of public keys for all members of the committee */
        aggregated_protocol_pubkey: group_ops.Element,
        /** Minimum signatures required for quorum (2n/3 + 1) */
        quorum_threshold: bcs.u64(),
        /** Minimum signatures required for validity (n/3 + 1) */
        validity_threshold: bcs.u64()
    } });
export const CommitteeQuorumVerifiedEvent = new MoveStruct({ name: `${$moduleName}::CommitteeQuorumVerifiedEvent`, fields: {
        epoch: bcs.u64(),
        signer_count: bcs.u64()
    } });
export interface TotalVotingPowerArguments {
    self: RawTransactionArgument<string>;
}
export interface TotalVotingPowerOptions {
    package?: string;
    arguments: TotalVotingPowerArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the total voting power (number of members in the committee) */
export function totalVotingPower(options: TotalVotingPowerOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'total_voting_power',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface QuorumThresholdArguments {
    self: RawTransactionArgument<string>;
}
export interface QuorumThresholdOptions {
    package?: string;
    arguments: QuorumThresholdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the quorum threshold (2n/3 + 1) for the committee */
export function quorumThreshold(options: QuorumThresholdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'quorum_threshold',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidityThresholdArguments {
    self: RawTransactionArgument<string>;
}
export interface ValidityThresholdOptions {
    package?: string;
    arguments: ValidityThresholdArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns the validity threshold (n/3 + 1) for the committee */
export function validityThreshold(options: ValidityThresholdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'validity_threshold',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewBlsCommitteeMemberArguments {
    validatorId: RawTransactionArgument<string>;
    protocolPubkey: RawTransactionArgument<string>;
}
export interface NewBlsCommitteeMemberOptions {
    package?: string;
    arguments: NewBlsCommitteeMemberArguments | [
        validatorId: RawTransactionArgument<string>,
        protocolPubkey: RawTransactionArgument<string>
    ];
}
/**
 * Creates a new BLS committee member with the given validator ID and protocol
 * public key
 */
export function newBlsCommitteeMember(options: NewBlsCommitteeMemberOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        '0x0000000000000000000000000000000000000000000000000000000000000002::group_ops::Element<0x0000000000000000000000000000000000000000000000000000000000000002::bls12381::UncompressedG1>'
    ] satisfies string[];
    const parameterNames = ["validatorId", "protocolPubkey"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'new_bls_committee_member',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorIdArguments {
    member: RawTransactionArgument<string>;
}
export interface ValidatorIdOptions {
    package?: string;
    arguments: ValidatorIdArguments | [
        member: RawTransactionArgument<string>
    ];
}
/** Returns the validator ID of the committee member */
export function validatorId(options: ValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommitteeMember`
    ] satisfies string[];
    const parameterNames = ["member"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewBlsCommitteeArguments {
    members: RawTransactionArgument<string[]>;
}
export interface NewBlsCommitteeOptions {
    package?: string;
    arguments: NewBlsCommitteeArguments | [
        members: RawTransactionArgument<string[]>
    ];
}
/**
 * Creates a new BLS committee from a vector of members Each member has equal
 * voting power of 1, total voting power equals number of members Calculates quorum
 * threshold (2n/3 + 1) and validity threshold (n/3 + 1)
 */
export function newBlsCommittee(options: NewBlsCommitteeOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `vector<${packageAddress}::bls_committee::BlsCommitteeMember>`
    ] satisfies string[];
    const parameterNames = ["members"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'new_bls_committee',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface EmptyOptions {
    package?: string;
    arguments?: [
    ];
}
/**
 * Creates an empty committee with zero thresholds Only relevant for initialization
 * phase
 */
export function empty(options: EmptyOptions = {}) {
    const packageAddress = options.package ?? '@local-pkg/common';
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'empty',
    });
}
export interface MembersArguments {
    self: RawTransactionArgument<string>;
}
export interface MembersOptions {
    package?: string;
    arguments: MembersArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns an immutable reference to committee members */
export function members(options: MembersOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'members',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorIdsArguments {
    self: RawTransactionArgument<string>;
}
export interface ValidatorIdsOptions {
    package?: string;
    arguments: ValidatorIdsArguments | [
        self: RawTransactionArgument<string>
    ];
}
/** Returns a vector of all validator IDs in the committee */
export function validatorIds(options: ValidatorIdsOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'validator_ids',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ContainsArguments {
    self: RawTransactionArgument<string>;
    validatorId: RawTransactionArgument<string>;
}
export interface ContainsOptions {
    package?: string;
    arguments: ContainsArguments | [
        self: RawTransactionArgument<string>,
        validatorId: RawTransactionArgument<string>
    ];
}
/** Checks if the committee contains a specific validator ID */
export function contains(options: ContainsOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID'
    ] satisfies string[];
    const parameterNames = ["self", "validatorId"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'contains',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifyCertificateArguments {
    self: RawTransactionArgument<string>;
    epoch: RawTransactionArgument<number | bigint>;
    signature: RawTransactionArgument<number[]>;
    signersBitmap: RawTransactionArgument<number[]>;
    intentBytes: RawTransactionArgument<number[]>;
}
export interface VerifyCertificateOptions {
    package?: string;
    arguments: VerifyCertificateArguments | [
        self: RawTransactionArgument<string>,
        epoch: RawTransactionArgument<number | bigint>,
        signature: RawTransactionArgument<number[]>,
        signersBitmap: RawTransactionArgument<number[]>,
        intentBytes: RawTransactionArgument<number[]>
    ];
}
/**
 * Verifies an aggregate BLS signature is a certificate in the epoch The
 * `signers_bitmap` represents which validators signed the certificate Returns
 * successfully if signature is valid and meets quorum threshold, otherwise aborts
 */
export function verifyCertificate(options: VerifyCertificateOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`,
        'u64',
        'vector<u8>',
        'vector<u8>',
        'vector<u8>'
    ] satisfies string[];
    const parameterNames = ["self", "epoch", "signature", "signersBitmap", "intentBytes"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'verify_certificate',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsQuorumThresholdArguments {
    self: RawTransactionArgument<string>;
    signerCount: RawTransactionArgument<number | bigint>;
}
export interface IsQuorumThresholdOptions {
    package?: string;
    arguments: IsQuorumThresholdArguments | [
        self: RawTransactionArgument<string>,
        signerCount: RawTransactionArgument<number | bigint>
    ];
}
/** Returns true if the voting power meets or exceeds the quorum threshold */
export function isQuorumThreshold(options: IsQuorumThresholdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`,
        'u64'
    ] satisfies string[];
    const parameterNames = ["self", "signerCount"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'is_quorum_threshold',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface IsValidityThresholdArguments {
    self: RawTransactionArgument<string>;
    signerCount: RawTransactionArgument<number | bigint>;
}
export interface IsValidityThresholdOptions {
    package?: string;
    arguments: IsValidityThresholdArguments | [
        self: RawTransactionArgument<string>,
        signerCount: RawTransactionArgument<number | bigint>
    ];
}
/** Returns true if the voting power meets or exceeds the validity threshold */
export function isValidityThreshold(options: IsValidityThresholdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::bls_committee::BlsCommittee`,
        'u64'
    ] satisfies string[];
    const parameterNames = ["self", "signerCount"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'bls_committee',
        function: 'is_validity_threshold',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}