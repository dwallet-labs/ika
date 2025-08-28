# IKA Bitcoin Multisig Wallet

## ⚠️ Important Disclaimer

**This is an example implementation and NOT production ready.** This codebase demonstrates the integration of Bitcoin multisig functionality with the IKA dWallet 2PC-MPC protocol but should not be used in production environments without extensive security audits, testing, and modifications.

## Overview

This project implements a distributed multi-signature Bitcoin wallet using the IKA dWallet 2PC-MPC (Two-Party Computation Multi-Party Computation) protocol. It allows multiple parties to collectively approve and execute Bitcoin transactions through secure distributed key management and threshold-based decision making.

## Key Features

- **Distributed Key Generation**: Uses IKA's 2PC-MPC protocol for enhanced security
- **Configurable Thresholds**: Flexible approval and rejection thresholds
- **Time-based Expiration**: Automatic request expiration for security
- **Irrevocable Voting**: Once cast, votes cannot be changed
- **Governance Operations**: Support for adding/removing members and modifying wallet parameters
- **Balance Management**: Built-in support for funding protocol fees with IKA and SUI tokens

## Architecture

The implementation consists of several key modules:

- `multisig.move`: Main multisig wallet logic and state management
- `requestt.move`: Request lifecycle and voting system
- `events.move`: Event emissions for tracking wallet activities
- `constants.move`: Cryptographic constants and configuration
- `error.move`: Error codes and validation
- `lib/event_wrapper.move`: Event wrapper utilities

## License

BSD-3-Clause-Clear
