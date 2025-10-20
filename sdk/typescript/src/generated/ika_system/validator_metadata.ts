/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/** Metadata that describes a validator. Attached to the `StakingPool` */

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';
import * as vec_map from './deps/sui/vec_map.js';
const $moduleName = '@local-pkg/system::validator_metadata';
export const ValidatorMetadata = new MoveStruct({ name: `${$moduleName}::ValidatorMetadata`, fields: {
        image_url: bcs.string(),
        project_url: bcs.string(),
        description: bcs.string(),
        extra_fields: vec_map.VecMap(bcs.string(), bcs.string())
    } });
export interface NewArguments {
    imageUrl: RawTransactionArgument<string>;
    projectUrl: RawTransactionArgument<string>;
    description: RawTransactionArgument<string>;
}
export interface NewOptions {
    package?: string;
    arguments: NewArguments | [
        imageUrl: RawTransactionArgument<string>,
        projectUrl: RawTransactionArgument<string>,
        description: RawTransactionArgument<string>
    ];
}
/** Create a new `ValidatorMetadata` instance */
export function _new(options: NewOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String',
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["imageUrl", "projectUrl", "description"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'new',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetImageUrlArguments {
    metadata: RawTransactionArgument<string>;
    imageUrl: RawTransactionArgument<string>;
}
export interface SetImageUrlOptions {
    package?: string;
    arguments: SetImageUrlArguments | [
        metadata: RawTransactionArgument<string>,
        imageUrl: RawTransactionArgument<string>
    ];
}
/** Set the image URL of the Validator. */
export function setImageUrl(options: SetImageUrlOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["metadata", "imageUrl"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'set_image_url',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetProjectUrlArguments {
    metadata: RawTransactionArgument<string>;
    projectUrl: RawTransactionArgument<string>;
}
export interface SetProjectUrlOptions {
    package?: string;
    arguments: SetProjectUrlArguments | [
        metadata: RawTransactionArgument<string>,
        projectUrl: RawTransactionArgument<string>
    ];
}
/** Set the project URL of the Validator. */
export function setProjectUrl(options: SetProjectUrlOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["metadata", "projectUrl"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'set_project_url',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetDescriptionArguments {
    metadata: RawTransactionArgument<string>;
    description: RawTransactionArgument<string>;
}
export interface SetDescriptionOptions {
    package?: string;
    arguments: SetDescriptionArguments | [
        metadata: RawTransactionArgument<string>,
        description: RawTransactionArgument<string>
    ];
}
/** Set the description of the Validator. */
export function setDescription(options: SetDescriptionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`,
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["metadata", "description"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'set_description',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface SetExtraFieldsArguments {
    metadata: RawTransactionArgument<string>;
    extraFields: RawTransactionArgument<string>;
}
export interface SetExtraFieldsOptions {
    package?: string;
    arguments: SetExtraFieldsArguments | [
        metadata: RawTransactionArgument<string>,
        extraFields: RawTransactionArgument<string>
    ];
}
/** Set an extra field of the Validator. */
export function setExtraFields(options: SetExtraFieldsOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`,
        '0x0000000000000000000000000000000000000000000000000000000000000002::vec_map::VecMap<0x0000000000000000000000000000000000000000000000000000000000000001::string::String, 0x0000000000000000000000000000000000000000000000000000000000000001::string::String>'
    ] satisfies string[];
    const parameterNames = ["metadata", "extraFields"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'set_extra_fields',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ImageUrlArguments {
    metadata: RawTransactionArgument<string>;
}
export interface ImageUrlOptions {
    package?: string;
    arguments: ImageUrlArguments | [
        metadata: RawTransactionArgument<string>
    ];
}
/** Returns the image URL of the Validator. */
export function imageUrl(options: ImageUrlOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`
    ] satisfies string[];
    const parameterNames = ["metadata"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'image_url',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ProjectUrlArguments {
    metadata: RawTransactionArgument<string>;
}
export interface ProjectUrlOptions {
    package?: string;
    arguments: ProjectUrlArguments | [
        metadata: RawTransactionArgument<string>
    ];
}
/** Returns the project URL of the Validator. */
export function projectUrl(options: ProjectUrlOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`
    ] satisfies string[];
    const parameterNames = ["metadata"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'project_url',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface DescriptionArguments {
    metadata: RawTransactionArgument<string>;
}
export interface DescriptionOptions {
    package?: string;
    arguments: DescriptionArguments | [
        metadata: RawTransactionArgument<string>
    ];
}
/** Returns the description of the Validator. */
export function description(options: DescriptionOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`
    ] satisfies string[];
    const parameterNames = ["metadata"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'description',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ExtraFieldsArguments {
    metadata: RawTransactionArgument<string>;
}
export interface ExtraFieldsOptions {
    package?: string;
    arguments: ExtraFieldsArguments | [
        metadata: RawTransactionArgument<string>
    ];
}
/** Returns the extra fields of the Validator. */
export function extraFields(options: ExtraFieldsOptions) {
    const packageAddress = options.package ?? '@local-pkg/system';
    const argumentsTypes = [
        `${packageAddress}::validator_metadata::ValidatorMetadata`
    ] satisfies string[];
    const parameterNames = ["metadata"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'validator_metadata',
        function: 'extra_fields',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}