/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as object from './deps/sui/object.js';
const $moduleName = '@local-pkg/common::validator_cap';
export const ValidatorCap = new MoveStruct({ name: `${$moduleName}::ValidatorCap`, fields: {
        id: object.UID,
        validator_id: bcs.Address
    } });
export const ValidatorOperationCap = new MoveStruct({ name: `${$moduleName}::ValidatorOperationCap`, fields: {
        id: object.UID,
        validator_id: bcs.Address
    } });
export const ValidatorCommissionCap = new MoveStruct({ name: `${$moduleName}::ValidatorCommissionCap`, fields: {
        id: object.UID,
        validator_id: bcs.Address
    } });
export const VerifiedValidatorCap = new MoveStruct({ name: `${$moduleName}::VerifiedValidatorCap`, fields: {
        validator_id: bcs.Address
    } });
export const VerifiedValidatorOperationCap = new MoveStruct({ name: `${$moduleName}::VerifiedValidatorOperationCap`, fields: {
        validator_id: bcs.Address
    } });
export const VerifiedValidatorCommissionCap = new MoveStruct({ name: `${$moduleName}::VerifiedValidatorCommissionCap`, fields: {
        validator_id: bcs.Address
    } });
export interface NewValidatorCapArguments {
    validatorId: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface NewValidatorCapOptions {
    package?: string;
    arguments: NewValidatorCapArguments | [
        validatorId: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function newValidatorCap(options: NewValidatorCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["validatorId", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'new_validator_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewValidatorOperationCapArguments {
    validatorId: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface NewValidatorOperationCapOptions {
    package?: string;
    arguments: NewValidatorOperationCapArguments | [
        validatorId: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
/**
 * Should be only called by the friend modules when adding a `Validator` or
 * rotating an existing validator's `operation_cap_id`.
 */
export function newValidatorOperationCap(options: NewValidatorOperationCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["validatorId", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'new_validator_operation_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface NewValidatorCommissionCapArguments {
    validatorId: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface NewValidatorCommissionCapOptions {
    package?: string;
    arguments: NewValidatorCommissionCapArguments | [
        validatorId: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
/**
 * Should be only called by the friend modules when adding a `Validator` or
 * rotating an existing validator's `commission_cap_id`.
 */
export function newValidatorCommissionCap(options: NewValidatorCommissionCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000002::object::ID',
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["validatorId", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'new_validator_commission_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CreateVerifiedValidatorCapArguments {
    cap: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface CreateVerifiedValidatorCapOptions {
    package?: string;
    arguments: CreateVerifiedValidatorCapArguments | [
        cap: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function createVerifiedValidatorCap(options: CreateVerifiedValidatorCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorCap`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["cap", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'create_verified_validator_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CreateVerifiedValidatorOperationCapArguments {
    cap: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface CreateVerifiedValidatorOperationCapOptions {
    package?: string;
    arguments: CreateVerifiedValidatorOperationCapArguments | [
        cap: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function createVerifiedValidatorOperationCap(options: CreateVerifiedValidatorOperationCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorOperationCap`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["cap", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'create_verified_validator_operation_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface CreateVerifiedValidatorCommissionCapArguments {
    cap: RawTransactionArgument<string>;
    _: RawTransactionArgument<string>;
}
export interface CreateVerifiedValidatorCommissionCapOptions {
    package?: string;
    arguments: CreateVerifiedValidatorCommissionCapArguments | [
        cap: RawTransactionArgument<string>,
        _: RawTransactionArgument<string>
    ];
}
export function createVerifiedValidatorCommissionCap(options: CreateVerifiedValidatorCommissionCapOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorCommissionCap`,
        `${packageAddress}::system_object_cap::SystemObjectCap`
    ] satisfies string[];
    const parameterNames = ["cap", "_"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'create_verified_validator_commission_cap',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface ValidatorIdOptions {
    package?: string;
    arguments: ValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function validatorId(options: ValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorOperationCapValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface ValidatorOperationCapValidatorIdOptions {
    package?: string;
    arguments: ValidatorOperationCapValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function validatorOperationCapValidatorId(options: ValidatorOperationCapValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'validator_operation_cap_validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidatorCommissionCapValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface ValidatorCommissionCapValidatorIdOptions {
    package?: string;
    arguments: ValidatorCommissionCapValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function validatorCommissionCapValidatorId(options: ValidatorCommissionCapValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::ValidatorCommissionCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'validator_commission_cap_validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifiedValidatorCapValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface VerifiedValidatorCapValidatorIdOptions {
    package?: string;
    arguments: VerifiedValidatorCapValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function verifiedValidatorCapValidatorId(options: VerifiedValidatorCapValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::VerifiedValidatorCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'verified_validator_cap_validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifiedValidatorOperationCapValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface VerifiedValidatorOperationCapValidatorIdOptions {
    package?: string;
    arguments: VerifiedValidatorOperationCapValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function verifiedValidatorOperationCapValidatorId(options: VerifiedValidatorOperationCapValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::VerifiedValidatorOperationCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'verified_validator_operation_cap_validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface VerifiedValidatorCommissionCapValidatorIdArguments {
    cap: RawTransactionArgument<string>;
}
export interface VerifiedValidatorCommissionCapValidatorIdOptions {
    package?: string;
    arguments: VerifiedValidatorCommissionCapValidatorIdArguments | [
        cap: RawTransactionArgument<string>
    ];
}
export function verifiedValidatorCommissionCapValidatorId(options: VerifiedValidatorCommissionCapValidatorIdOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        `${packageAddress}::validator_cap::VerifiedValidatorCommissionCap`
    ] satisfies string[];
    const parameterNames = ["cap"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_cap',
        function: 'verified_validator_commission_cap_validator_id',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}