// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// This module provides utilities for validating multiaddr strings in Sui Move.
/// Multiaddr is a format for encoding addresses from various well-established network protocols.
/// This implementation supports validation for:
/// - IPv4 addresses with TCP/UDP
/// - IPv6 addresses with TCP/UDP
/// - DNS hostnames with TCP/UDP
/// - HTTP protocol
module ika_common::multiaddr;

use std::string::{Self, String};

// === Public Functions ===

/// Validates a multiaddr string for TCP with any of IPv4/IPv6/DNS.
///
/// # Arguments
/// * `addr` - The multiaddr string to validate
///
/// # Returns
/// * `true` if the multiaddr is valid for TCP, `false` otherwise
///
/// # Examples
/// ```
/// let valid_addr = string::utf8(b"/ip4/192.168.1.1/tcp/8080");
/// assert!(validate_tcp(&valid_addr));
/// ```
public fun validate_tcp(addr: &String): bool {
    validate_with_transport(addr, string::utf8(b"tcp"))
}

/// Validates a multiaddr string for UDP with any of IPv4/IPv6/DNS.
///
/// # Arguments
/// * `addr` - The multiaddr string to validate
///
/// # Returns
/// * `true` if the multiaddr is valid for UDP, `false` otherwise
///
/// # Examples
/// ```
/// let valid_addr = string::utf8(b"/ip4/192.168.1.1/udp/8080");
/// assert!(validate_udp(&valid_addr));
/// ```
public fun validate_udp(addr: &String): bool {
    validate_with_transport(addr, string::utf8(b"udp"))
}

// === Private Functions ===

/// Internal helper function to validate multiaddr with a specific transport protocol.
///
/// # Arguments
/// * `addr` - The multiaddr string to validate
/// * `transport` - The expected transport protocol (tcp, udp, or quic)
///
/// # Returns
/// * `true` if the multiaddr is valid for the given transport, `false` otherwise
fun validate_with_transport(addr: &String, transport: String): bool {
    let bytes = string::as_bytes(addr);
    let len = vector::length(bytes);
    if (len < 1) return false;

    // Check if it starts with a slash
    if (*vector::borrow(bytes, 0) != 47) return false; // ASCII '/' is 47

    // Find the parts by iterating through the string once
    let mut part_start = 1; // Skip first slash
    let mut part_num = 0u16;
    let mut protocol = string::utf8(b"");
    let mut address = string::utf8(b"");
    let mut actual_transport = string::utf8(b"");
    let mut port = string::utf8(b"");

    let mut i = 1;
    while (i < len) {
        if (*vector::borrow(bytes, i) == 47 || i == len - 1) {
            let end = if (i == len - 1) i + 1 else i;
            let part = string::substring(addr, part_start, end);

            if (part_num == 0) {
                protocol = part;
            } else if (part_num == 1) {
                address = part;
            } else if (part_num == 2) {
                actual_transport = part;
            } else if (part_num == 3) {
                port = part;
            } else {
                // For additional segments, we only validate if they are HTTP/HTTPS resources
                // or if they are valid protocol names (http, https, quic)
                let http = string::utf8(b"http");
                let https = string::utf8(b"https");
                let quic = string::utf8(b"quic");

                // If this is a protocol name, validate it
                if (!(part == http || part == https || part == quic)) {
                    // This is either a resource path or an unknown protocol
                    // If it's a resource path, it can contain any valid URL characters
                    // If it's an unknown protocol, we should reject it
                    if (part_num == 4) {
                        // First additional segment must be a known protocol
                        return false
                    };
                    // For subsequent segments, assume they are resource paths
                    break
                };
            };

            part_start = i + 1;
            part_num = part_num + 1;
        };
        i = i + 1;
    };

    if (part_num < 4) return false; // Need at least protocol/address/transport/port

    // Validate protocol
    let ip4 = string::utf8(b"ip4");
    let ip6 = string::utf8(b"ip6");
    let dns4 = string::utf8(b"dns4");
    let dns6 = string::utf8(b"dns6");
    let dns = string::utf8(b"dns");

    if (
        protocol != ip4 && 
        protocol != ip6 && 
        protocol != dns4 && 
        protocol != dns6 &&
        protocol != dns
    ) return false;

    // Validate address based on protocol
    if (protocol == ip4) {
        if (!is_valid_ipv4(&address)) return false;
    } else if (protocol == ip6) {
        if (!is_valid_ipv6(&address)) return false;
    } else if (protocol == dns4 || protocol == dns6 || protocol == dns) {
        if (!is_valid_dns(&address)) return false;
    };

    // Validate transport
    if (actual_transport != transport) return false;

    // Validate port - must be a string of digits
    if (string::length(&port) == 0) return false;

    let port_bytes = string::as_bytes(&port);
    let port_len = vector::length(port_bytes);
    let mut j = 0;
    let mut is_valid_port = true;

    while (j < port_len) {
        let byte = *vector::borrow(port_bytes, j);
        if (byte < 48 || byte > 57) {
            is_valid_port = false;
            break
        };
        j = j + 1;
    };

    is_valid_port
}

/// Validates an IPv4 address format.
///
/// # Arguments
/// * `ip` - The IPv4 address string to validate
///
/// # Returns
/// * `true` if the IPv4 address is valid, `false` otherwise
fun is_valid_ipv4(ip: &String): bool {
    let len = ip.length();
    let mut parts: vector<String> = vector::empty();
    let mut start = 0;
    let mut i = 0;

    while (i < len) {
        let current = ip.substring(i, i + 1);
        if (current == string::utf8(b".")) {
            let part = ip.substring(start, i);
            parts.push_back(part);
            start = i + 1;
        };
        i = i + 1;
    };

    // Add last part
    let last_part = ip.substring(start, len);
    parts.push_back(last_part);

    if (parts.length() != 4) return false;

    let mut i = 0;
    while (i < 4) {
        let octet = parts.borrow(i);
        let octet_bytes = octet.as_bytes();
        let octet_len = octet_bytes.length();

        // Check if octet is empty or too long
        if (octet_len == 0 || octet_len > 3) return false;

        // Check if all characters are digits
        let mut j = 0;
        while (j < octet_len) {
            let byte = *octet_bytes.borrow(j);
            if (byte < 48 || byte > 57) return false; // Not a digit
            j = j + 1;
        };

        // Check if number is too large
        if (octet_len == 3) {
            let first = *octet_bytes.borrow(0);
            let second = *octet_bytes.borrow(1);
            let third = *octet_bytes.borrow(2);
            if (first > 50) return false; // First digit > 2
            if (first == 50) {
                // First digit is 2
                if (second > 53) return false; // Second digit > 5
                if (second == 53 && third > 53) return false; // Second digit is 5 and third > 5
            };
        } else if (octet_len == 2) {
            let first = *octet_bytes.borrow(0);
            let second = *octet_bytes.borrow(1);
            if (first > 50) return false; // First digit > 2
            if (first == 50 && second > 53) return false; // First digit is 2 and second > 5
        };

        i = i + 1;
    };
    true
}

/// Validates an IPv6 address format.
///
/// # Arguments
/// * `ip` - The IPv6 address string to validate
///
/// # Returns
/// * `true` if the IPv6 address is valid, `false` otherwise
fun is_valid_ipv6(ip: &String): bool {
    let len = ip.length();
    let mut parts: vector<String> = vector::empty();
    let mut start = 0;
    let mut i = 0;
    let mut consecutive_colons = false;
    let mut has_double_colon = false;

    while (i < len) {
        let current = ip.substring(i, i + 1);
        if (current == string::utf8(b":")) {
            if (i > 0 && ip.substring(i - 1, i) == string::utf8(b":")) {
                if (has_double_colon) return false; // Only one :: allowed
                has_double_colon = true;
                consecutive_colons = true;
            } else {
                if (!consecutive_colons) {
                    let part = ip.substring(start, i);
                    if (part.length() > 0) {
                        parts.push_back(part);
                    };
                };
                consecutive_colons = false;
            };
            start = i + 1;
        };
        i = i + 1;
    };

    // Add last part if not empty
    let last_part = ip.substring(start, len);
    if (last_part.length() > 0) {
        parts.push_back(last_part);
    };

    let num_parts = parts.length();
    if (!has_double_colon && num_parts != 8) return false;
    if (has_double_colon && num_parts >= 8) return false;

    let mut i = 0;
    while (i < num_parts) {
        let segment = parts.borrow(i);
        let segment_len = segment.length();
        if (segment_len == 0 || segment_len > 4) return false;

        // Validate hex characters
        let segment_bytes = segment.as_bytes();
        let mut j = 0;
        while (j < segment_len) {
            let byte = *segment_bytes.borrow(j);
            let is_digit = byte >= 48 && byte <= 57; // 0-9
            let is_hex_lower = byte >= 97 && byte <= 102; // a-f
            let is_hex_upper = byte >= 65 && byte <= 70; // A-F
            if (!is_digit && !is_hex_lower && !is_hex_upper) return false;
            j = j + 1;
        };
        i = i + 1;
    };
    true
}

/// Validates a DNS hostname format.
///
/// # Arguments
/// * `hostname` - The DNS hostname string to validate
///
/// # Returns
/// * `true` if the DNS hostname is valid, `false` otherwise
fun is_valid_dns(hostname: &String): bool {
    let len = hostname.length();
    if (len < 1 || len > 253) return false;

    let mut parts: vector<String> = vector::empty();
    let mut start = 0;
    let mut i = 0;

    while (i < len) {
        let current = hostname.substring(i, i + 1);
        if (current == string::utf8(b".")) {
            let part = hostname.substring(start, i);
            if (part.length() == 0) return false; // Empty label not allowed
            parts.push_back(part);
            start = i + 1;
        };
        i = i + 1;
    };

    // Add last part
    let last_part = hostname.substring(start, len);
    if (last_part.length() == 0) return false; // Empty label not allowed
    parts.push_back(last_part);

    let num_parts = parts.length();
    if (num_parts < 1) return false;

    let mut i = 0;
    while (i < num_parts) {
        let label = parts.borrow(i);
        let label_len = label.length();
        if (label_len < 1 || label_len > 63) return false;

        // Validate label characters
        let label_bytes = label.as_bytes();
        let mut j = 0;
        while (j < label_len) {
            let byte = *label_bytes.borrow(j);
            let is_letter = (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122); // A-Z or a-z
            let is_digit = byte >= 48 && byte <= 57; // 0-9
            let is_hyphen = byte == 45; // -

            if (!is_letter && !is_digit && !is_hyphen) return false;

            // First and last characters must be alphanumeric
            if (is_hyphen) {
                if (j == 0 || j == label_len - 1) return false;
            };

            j = j + 1;
        };
        i = i + 1;
    };
    true
}

#[test]
/// Test suite for multiaddr validation
fun test_multiaddr() {
    // Test valid IPv4 with TCP
    let valid_ipv4_tcp = string::utf8(b"/ip4/192.168.1.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_tcp), 0);

    // Test valid IPv4 with UDP
    let valid_ipv4_udp = string::utf8(b"/ip4/192.168.1.1/udp/8080");
    assert!(validate_udp(&valid_ipv4_udp), 1);

    // Test valid IPv6 with TCP
    let valid_ipv6_tcp = string::utf8(b"/ip6/2001:0db8:85a3:0000:0000:8a2e:0370:7334/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_tcp), 2);

    // Test valid DNS with TCP
    let valid_dns_tcp = string::utf8(b"/dns/example.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_tcp), 3);

    // Test invalid cases
    let invalid_ipv4 = string::utf8(b"/ip4/256.168.1.1/tcp/8080");
    assert!(!validate_tcp(&invalid_ipv4), 4);

    let invalid_ipv6 = string::utf8(b"/ip6/2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234/tcp/8080");
    assert!(!validate_tcp(&invalid_ipv6), 5);

    let invalid_dns = string::utf8(b"/dns/example@.com/tcp/8080");
    assert!(!validate_tcp(&invalid_dns), 6);

    let invalid_transport = string::utf8(b"/ip4/192.168.1.1/http/8080");
    assert!(!validate_tcp(&invalid_transport), 7);
    assert!(!validate_udp(&invalid_transport), 8);

    // Additional IPv4 test cases
    let valid_ipv4_min = string::utf8(b"/ip4/0.0.0.0/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_min), 9);

    let valid_ipv4_max = string::utf8(b"/ip4/255.255.255.255/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_max), 10);

    let valid_ipv4_leading_zero = string::utf8(b"/ip4/01.168.1.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_leading_zero), 11);

    let invalid_ipv4_empty = string::utf8(b"/ip4/192.168..1/tcp/8080");
    assert!(!validate_tcp(&invalid_ipv4_empty), 12);

    // Additional IPv6 test cases
    let valid_ipv6_compressed = string::utf8(b"/ip6/2001:db8::8a2e:370:7334/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_compressed), 13);

    let valid_ipv6_loopback = string::utf8(b"/ip6/::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_loopback), 14);

    let valid_ipv6_unspecified = string::utf8(b"/ip6/::/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_unspecified), 15);

    let invalid_ipv6_double_colon = string::utf8(b"/ip6/2001::db8::1/tcp/8080");
    assert!(!validate_tcp(&invalid_ipv6_double_colon), 16);

    let invalid_ipv6_invalid_char = string::utf8(b"/ip6/2001:db8:g::1/tcp/8080");
    assert!(!validate_tcp(&invalid_ipv6_invalid_char), 17);

    // Additional DNS test cases
    let valid_dns_hyphen = string::utf8(b"/dns/my-domain.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_hyphen), 18);

    let valid_dns_numbers = string::utf8(b"/dns/123.example.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_numbers), 19);

    let valid_dns_long = string::utf8(
        b"/dns/this.is.a.very.long.domain.name.that.is.still.valid.com/tcp/8080",
    );
    assert!(validate_tcp(&valid_dns_long), 20);

    let invalid_dns_leading_hyphen = string::utf8(b"/dns/-example.com/tcp/8080");
    assert!(!validate_tcp(&invalid_dns_leading_hyphen), 21);

    let invalid_dns_trailing_hyphen = string::utf8(b"/dns/example-.com/tcp/8080");
    assert!(!validate_tcp(&invalid_dns_trailing_hyphen), 22);

    let invalid_dns_empty_label = string::utf8(b"/dns/example..com/tcp/8080");
    assert!(!validate_tcp(&invalid_dns_empty_label), 23);

    // Additional port test cases
    let valid_port_min = string::utf8(b"/ip4/192.168.1.1/tcp/0");
    assert!(validate_tcp(&valid_port_min), 24);

    let valid_port_max = string::utf8(b"/ip4/192.168.1.1/tcp/65535");
    assert!(validate_tcp(&valid_port_max), 25);

    let invalid_port_empty = string::utf8(b"/ip4/192.168.1.1/tcp/");
    assert!(!validate_tcp(&invalid_port_empty), 26);

    let invalid_port_non_digit = string::utf8(b"/ip4/192.168.1.1/tcp/80a");
    assert!(!validate_tcp(&invalid_port_non_digit), 27);

    // Additional format test cases
    let invalid_format_no_slash = string::utf8(b"ip4/192.168.1.1/tcp/8080");
    assert!(!validate_tcp(&invalid_format_no_slash), 28);

    let invalid_format_missing_protocol = string::utf8(b"//192.168.1.1/tcp/8080");
    assert!(!validate_tcp(&invalid_format_missing_protocol), 29);

    let invalid_format_missing_address = string::utf8(b"/ip4//tcp/8080");
    assert!(!validate_tcp(&invalid_format_missing_address), 30);

    let invalid_format_missing_transport = string::utf8(b"/ip4/192.168.1.1//8080");
    assert!(!validate_tcp(&invalid_format_missing_transport), 31);

    // Real-world IPv4 test cases
    let valid_ipv4_localhost = string::utf8(b"/ip4/127.0.0.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_localhost), 32);

    let valid_ipv4_private = string::utf8(b"/ip4/10.0.0.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_private), 33);

    let valid_ipv4_private_2 = string::utf8(b"/ip4/172.16.0.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_private_2), 34);

    let valid_ipv4_private_3 = string::utf8(b"/ip4/192.168.0.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_private_3), 35);

    let valid_ipv4_public = string::utf8(b"/ip4/8.8.8.8/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_public), 36);

    let valid_ipv4_public_2 = string::utf8(b"/ip4/1.1.1.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_public_2), 37);

    let valid_ipv4_multicast = string::utf8(b"/ip4/224.0.0.1/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_multicast), 38);

    let valid_ipv4_broadcast = string::utf8(b"/ip4/255.255.255.255/tcp/8080");
    assert!(validate_tcp(&valid_ipv4_broadcast), 39);

    // Real-world IPv6 test cases
    let valid_ipv6_localhost = string::utf8(b"/ip6/::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_localhost), 40);

    let valid_ipv6_private = string::utf8(b"/ip6/fd00::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_private), 41);

    let valid_ipv6_public = string::utf8(b"/ip6/2001:4860:4860::8888/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_public), 42);

    let valid_ipv6_public_2 = string::utf8(b"/ip6/2606:4700:4700::1111/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_public_2), 43);

    let valid_ipv6_multicast = string::utf8(b"/ip6/ff02::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_multicast), 44);

    let valid_ipv6_link_local = string::utf8(b"/ip6/fe80::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_link_local), 45);

    let valid_ipv6_compressed_2 = string::utf8(b"/ip6/2001:db8::1:0:0:1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_compressed_2), 46);

    let valid_ipv6_compressed_3 = string::utf8(b"/ip6/2001:db8:0:0:1::1/tcp/8080");
    assert!(validate_tcp(&valid_ipv6_compressed_3), 47);

    // Real-world DNS test cases
    let valid_dns_common = string::utf8(b"/dns/google.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_common), 48);

    let valid_dns_subdomain = string::utf8(b"/dns/mail.google.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_subdomain), 49);

    let valid_dns_numbers_2 = string::utf8(b"/dns/1.1.1.1.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_numbers_2), 50);

    let valid_dns_hyphen_2 = string::utf8(b"/dns/my-service-1.example.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_hyphen_2), 51);

    let valid_dns_mixed = string::utf8(b"/dns/api-v1.prod-1.example.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_mixed), 52);

    let valid_dns_tld = string::utf8(b"/dns/example.io/tcp/8080");
    assert!(validate_tcp(&valid_dns_tld), 53);

    let valid_dns_long_tld = string::utf8(b"/dns/example.technology/tcp/8080");
    assert!(validate_tcp(&valid_dns_long_tld), 54);

    let valid_dns_idn = string::utf8(b"/dns/xn--example-9ja.com/tcp/8080");
    assert!(validate_tcp(&valid_dns_idn), 55);

    // Real-world port test cases
    let valid_port_http = string::utf8(b"/ip4/192.168.1.1/tcp/80");
    assert!(validate_tcp(&valid_port_http), 56);

    let valid_port_https = string::utf8(b"/ip4/192.168.1.1/tcp/443");
    assert!(validate_tcp(&valid_port_https), 57);

    let valid_port_ssh = string::utf8(b"/ip4/192.168.1.1/tcp/22");
    assert!(validate_tcp(&valid_port_ssh), 58);

    let valid_port_ftp = string::utf8(b"/ip4/192.168.1.1/tcp/21");
    assert!(validate_tcp(&valid_port_ftp), 59);

    let valid_port_smtp = string::utf8(b"/ip4/192.168.1.1/tcp/25");
    assert!(validate_tcp(&valid_port_smtp), 60);

    let valid_port_dns = string::utf8(b"/ip4/192.168.1.1/udp/53");
    assert!(validate_udp(&valid_port_dns), 61);

    let valid_port_dhcp = string::utf8(b"/ip4/192.168.1.1/udp/67");
    assert!(validate_udp(&valid_port_dhcp), 62);

    let valid_port_ntp = string::utf8(b"/ip4/192.168.1.1/udp/123");
    assert!(validate_udp(&valid_port_ntp), 63);

    // HTTP/HTTPS endpoint test cases (using TCP)
    let http_standard = string::utf8(b"/ip4/192.168.1.1/tcp/80");
    assert!(validate_tcp(&http_standard), 64);

    let https_standard = string::utf8(b"/ip4/192.168.1.1/tcp/443");
    assert!(validate_tcp(&https_standard), 65);

    let http_ipv6 = string::utf8(b"/ip6/2001:db8::1/tcp/80");
    assert!(validate_tcp(&http_ipv6), 66);

    let https_ipv6 = string::utf8(b"/ip6/2001:db8::1/tcp/443");
    assert!(validate_tcp(&https_ipv6), 67);

    let http_dns = string::utf8(b"/dns/example.com/tcp/80");
    assert!(validate_tcp(&http_dns), 68);

    let https_dns = string::utf8(b"/dns/example.com/tcp/443");
    assert!(validate_tcp(&https_dns), 69);

    let http_alt_port = string::utf8(b"/ip4/192.168.1.1/tcp/8080");
    assert!(validate_tcp(&http_alt_port), 70);

    let https_alt_port = string::utf8(b"/ip4/192.168.1.1/tcp/8443");
    assert!(validate_tcp(&https_alt_port), 71);

    // Test cases for layered protocols
    let valid_quic = string::utf8(b"/ip4/127.0.0.1/udp/9090/quic");
    assert!(validate_with_transport(&valid_quic, string::utf8(b"udp")), 72);

    let valid_ipv6_tcp = string::utf8(b"/ip6/::1/tcp/3217");
    assert!(validate_tcp(&valid_ipv6_tcp), 73);

    let valid_http_resource = string::utf8(b"/ip4/127.0.0.1/tcp/80/http/baz.jpg");
    assert!(validate_tcp(&valid_http_resource), 74);

    let valid_dns4_http = string::utf8(b"/dns4/foo.com/tcp/80/http/bar/baz.jpg");
    assert!(validate_tcp(&valid_dns4_http), 75);

    let valid_dns6_https = string::utf8(b"/dns6/foo.com/tcp/443/https");
    assert!(validate_tcp(&valid_dns6_https), 76);

    let valid_quic_ipv6 = string::utf8(b"/ip6/2001:db8::1/udp/9090/quic");
    assert!(validate_with_transport(&valid_quic_ipv6, string::utf8(b"udp")), 77);

    let valid_https_resource = string::utf8(b"/ip4/127.0.0.1/tcp/443/https/api/v1");
    assert!(validate_tcp(&valid_https_resource), 78);

    // Invalid cases
    let invalid_missing_port = string::utf8(b"/ip4/127.0.0.1/tcp/http");
    assert!(!validate_tcp(&invalid_missing_port), 79);

    let invalid_wrong_order = string::utf8(b"/ip4/127.0.0.1/http/tcp/80");
    assert!(!validate_tcp(&invalid_wrong_order), 80);

    let invalid_unknown_protocol = string::utf8(b"/ip4/127.0.0.1/tcp/80/unknown");
    assert!(!validate_tcp(&invalid_unknown_protocol), 81);
}
