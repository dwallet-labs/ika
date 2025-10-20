/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs, type BcsType } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
const $moduleName = '@local-pkg/common::upgrade_package_approver';
export const UpgradePackageApprover = new MoveStruct({ name: `${$moduleName}::UpgradePackageApprover`, fields: {
        upgrade_cap_id: bcs.Address,
        remaining_witnesses_to_approve: bcs.vector(bcs.string()),
        old_package_id: bcs.Address,
        new_package_id: bcs.option(bcs.Address),
        migration_epoch: bcs.u64()
    } });
export interface CreateArguments {
    upgradeCapId: RawTransactionArgument<string>;
    remainingWitnessesToApprove: RawTransactionArgument<string[]>;
    oldPackageId: RawTransactionArgument<string>;
    migrationEpoch: RawTransactionArgument<number | bigint>;
    _: RawTransactionArgument<string>;
}
export interface CreateOptions {
    package?: string;
    arguments: CreateArguments | [
        upgradeCapId: RawTransactionArgument<string>,
        remainingWitnessesToApprove: RawTransactionArgument<string[]>,
        oldPackageId: RawTransactionArgument<string>,
        migrationEpoch: RawTransactionArgument<number | bigint>,
        _: RawTransactionArgument<string>
    ];
}
export function create(options: CreateOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'vector<0x0000000000000000000000000000000000000000000000000000000000000001::string::String>',
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        'u64',
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["upgradeCapId", "remainingWitnessesToApprove", "oldPackageId", "migrationEpoch", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'create',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface AssertAllWitnessesApprovedArguments {
    self: RawTransactionArgument<string>;
}
export interface AssertAllWitnessesApprovedOptions {
    package?: string;
    arguments: AssertAllWitnessesApprovedArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function assertAllWitnessesApproved(options: AssertAllWitnessesApprovedOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'assert_all_witnesses_approved',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewPackageIdArguments {
    self: RawTransactionArgument<string>;
}
export interface NewPackageIdOptions {
    package?: string;
    arguments: NewPackageIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function newPackageId(options: NewPackageIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'new_package_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface OldPackageIdArguments {
    self: RawTransactionArgument<string>;
}
export interface OldPackageIdOptions {
    package?: string;
    arguments: OldPackageIdArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function oldPackageId(options: OldPackageIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'old_package_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface MigrationEpochArguments {
    self: RawTransactionArgument<string>;
}
export interface MigrationEpochOptions {
    package?: string;
    arguments: MigrationEpochArguments | [
        self: RawTransactionArgument<string>
    ];
}
export function migrationEpoch(options: MigrationEpochOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`
    ] satisfies string[];
    const parameterNames = ["self"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'migration_epoch',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface DestroyArguments {
    self: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface DestroyOptions {
    package?: string;
    arguments: DestroyArguments | [
        self: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function destroy(options: DestroyOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["self", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'destroy',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CommitArguments {
    self: RawTransactionArgument<string>;
    receipt: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface CommitOptions {
    package?: string;
    arguments: CommitArguments | [
        self: RawTransactionArgument<string>,
        receipt: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function commit(options: CommitOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::package::UpgradeReceipt',
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["self", "receipt", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'commit',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ApproveUpgradePackageByWitnessArguments<Witness extends BcsType<any>> {
    upgradePackageApprover: RawTransactionArgument<string>;
    _: RawTransactionArgument<Witness>;
}
export interface ApproveUpgradePackageByWitnessOptions<Witness extends BcsType<any>> {
    package?: string;
    arguments: ApproveUpgradePackageByWitnessArguments<Witness> | [
        upgradePackageApprover: RawTransactionArgument<string>,
        _: RawTransactionArgument<Witness>
    ];
    typeArguments: [
        string
    ];
}
export function approveUpgradePackageByWitness<Witness extends BcsType<any>>(options: ApproveUpgradePackageByWitnessOptions<Witness>) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::upgrade_package_approver::UpgradePackageApprover`,
        `${options.typeArguments[0]}`
    ] satisfies string[];
    const parameterNames = ["upgradePackageApprover", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'upgrade_package_approver',
        function: 'approve_upgrade_package_by_witness',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
        typeArguments: options.typeArguments
    });
}