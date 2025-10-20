/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/


/**
 * This module provides utilities for validating multiaddr strings in Sui Move.
 * Multiaddr is a format for encoding addresses from various well-established
 * network protocols. This implementation supports validation for:
 * 
 * - IPv4 addresses with TCP/UDP
 * - IPv6 addresses with TCP/UDP
 * - DNS hostnames with TCP/UDP
 * - HTTP protocol
 */

import { type Transaction } from '@mysten/sui/transactions';
import { normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
export interface ValidateTcpArguments {
    addr: RawTransactionArgument<string>;
}
export interface ValidateTcpOptions {
    package?: string;
    arguments: ValidateTcpArguments | [
        addr: RawTransactionArgument<string>
    ];
}
/**
 * Validates a multiaddr string for TCP with any of IPv4/IPv6/DNS.
 *
 * # Arguments
 *
 * - `addr` - The multiaddr string to validate
 *
 * # Returns
 *
 * - `true` if the multiaddr is valid for TCP, `false` otherwise
 *
 * # Examples
 *
 * ```
 * let valid_addr = string::utf8(b"/ip4/192.168.1.1/tcp/8080");
 * assert!(validate_tcp(&valid_addr));
 * ```
 */
export function validateTcp(options: ValidateTcpOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["addr"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'multiaddr',
        function: 'validate_tcp',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}
export interface ValidateUdpArguments {
    addr: RawTransactionArgument<string>;
}
export interface ValidateUdpOptions {
    package?: string;
    arguments: ValidateUdpArguments | [
        addr: RawTransactionArgument<string>
    ];
}
/**
 * Validates a multiaddr string for UDP with any of IPv4/IPv6/DNS.
 *
 * # Arguments
 *
 * - `addr` - The multiaddr string to validate
 *
 * # Returns
 *
 * - `true` if the multiaddr is valid for UDP, `false` otherwise
 *
 * # Examples
 *
 * ```
 * let valid_addr = string::utf8(b"/ip4/192.168.1.1/udp/8080");
 * assert!(validate_udp(&valid_addr));
 * ```
 */
export function validateUdp(options: ValidateUdpOptions) {
    const packageAddress = options.package ?? '@local-pkg/common';
    const argumentsTypes = [
        '0x0000000000000000000000000000000000000000000000000000000000000001::string::String'
    ] satisfies string[];
    const parameterNames = ["addr"];
    return (tx: Transaction) => tx.moveCall({
        package: packageAddress,
        module: 'multiaddr',
        function: 'validate_udp',
        arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
    });
}