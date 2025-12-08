# bitisi - Bitcoin Multisig on Sui

**bitisi** is a Bitcoin multisig wallet application built on the Sui blockchain using the IKA protocol for secure multi-party computation (MPC) and distributed key management.

## ⚠️ CRITICAL WARNING - TESTNET ONLY

**This Bitcoin multisig demo is provided for developer testing and educational purposes only and must be used on Bitcoin testnet only (not mainnet).**

- ❌ **NOT audited** - May contain bugs or unexpected behavior
- ❌ **DO NOT use with real funds** or production wallets
- ✅ **Use only test keys** and disposable test amounts
- ⚠️ **You assume all risk by proceeding**

This is a demonstration application for developers to learn and test the IKA protocol. Never use this with real Bitcoin or in production environments.

## Features

### Core Multisig Functionality

- **Flexible Multisig Creation**: Create multisig wallets with customizable approval/rejection thresholds
- **Member Management**: Add or remove members through governance requests
- **Threshold Management**: Adjust approval and rejection thresholds dynamically
- **Transaction Requests**: Create, vote on, and execute Bitcoin transaction requests
- **Request Expiration**: Configurable expiration duration for pending requests

### Wallet Management

- **Multi-Wallet Support**: Manage multiple multisig wallets from one interface
- **Real-time Balance**: View IKA and SUI balances for each multisig
- **Transaction History**: Track all requests, votes, and executions
- **Member Visualization**: See all participants and their voting status

### Integration & Security

- **IKA Protocol**: Secure multi-party computation for distributed key generation
- **Sui Blockchain**: Built on Sui for fast, secure on-chain governance
- **Wallet Connection**: Seamless integration with Sui wallets (Sui Wallet, Ethos, etc.)
- **Modern UI**: Beautiful, responsive interface with dark mode support

## Getting Started

### Prerequisites

- Node.js 18+
- npm, pnpm, or bun
- Sui wallet (Sui Wallet, Ethos, etc.)
- Bitcoin testnet for testing transactions

### Installation

1. **Clone and navigate to the frontend:**

   ```bash
   cd examples/multisig-bitcoin/frontend
   npm install  # or pnpm install / bun install
   ```

2. **Start the development server:**

   ```bash
   npm run dev
   ```

3. **Open your browser:**
   Navigate to `http://localhost:3000`

### Build for Production

```bash
npm run build
npm start
```

## Usage Guide

### 1. Connect Your Wallet

- Click the "Connect Wallet" button in the header
- Select your preferred Sui wallet
- Approve the connection in your wallet
- The app will initialize encryption keys automatically

### 2. Create a Multisig Wallet

- Click "New Multisig" from the sidebar or main page
- Configure your multisig parameters:
  - **Members**: Add Sui addresses of participants
  - **Approval Threshold**: Number of approvals needed to execute
  - **Rejection Threshold**: Number of rejections needed to reject
  - **Expiration Duration**: How long requests remain valid (in seconds)
- Click "Create" and approve the transaction
- Wait for the distributed key generation to complete

### 3. Manage Your Multisig

Each multisig wallet displays:

- **Basic Information**: ID, status, and creation date
- **Members**: All participant addresses with their roles
- **Balances**: IKA and SUI token balances
- **Settings**: Approval/rejection thresholds and expiration duration

### 4. Create Transaction Requests

- Select a multisig from the sidebar
- Click "Create Transaction Request"
- Choose request type:
  - **Bitcoin Transaction**: Send Bitcoin from the multisig
  - **Add Member**: Propose adding a new member
  - **Remove Member**: Propose removing an existing member
  - **Change Threshold**: Adjust approval/rejection thresholds
  - **Change Expiration**: Modify request expiration duration
- Fill in the required details and submit

### 5. Vote on Requests

- View pending requests in the multisig details
- Each member can vote to **Approve** or **Reject**
- Votes are recorded on-chain immediately
- Request status updates based on threshold settings

### 6. Execute Approved Requests

- Once approval threshold is met, any member can execute
- Click "Execute" on an approved request
- For Bitcoin transactions:
  - Execute on-chain to create the presignature
  - Broadcast to Bitcoin network
  - View transaction hash and status

## Architecture

### Technology Stack

- **Frontend**: Next.js 14+ with React Server Components
- **UI Framework**: Tailwind CSS + shadcn/ui components
- **Blockchain**: Sui blockchain via @mysten/dapp-kit
- **MPC Protocol**: IKA 2PC MPC for distributed key generation
- **State Management**: React Context + SWR for data fetching
- **Type Safety**: TypeScript with auto-generated contract types

### Core Components

#### Pages & Layouts

- **Dashboard (page.tsx)**: Main application interface
- **Layout**: Wallet providers and global UI setup

#### Multisig Management

- **MultisigDetailsView**: Displays full multisig information and controls
- **MultisigRequestCard**: Individual request management UI
- **AppSidebar**: Navigation and multisig list

#### Request Modals

- **CreateMultisigModal**: Configure and create new multisigs
- **CreateTransactionModal**: Bitcoin transaction creation
- **MemberManagementModal**: Add/remove member requests
- **ThresholdManagementModal**: Adjust governance thresholds

#### Common Components

- **BalanceDisplay**: IKA and SUI token balances
- **EmptyState**: User-friendly empty states
- **UI Components**: shadcn/ui library (Button, Card, Dialog, etc.)

### Smart Contract Integration

The Move contracts in `contract/sources/` provide:

- **multisig.move**: Core multisig wallet logic
- **request.move**: Request lifecycle management
- **events.move**: On-chain event emissions
- **constants.move**: Protocol constants
- **error.move**: Error code definitions

### Key Features

- **Flexible Governance**: Customizable approval/rejection thresholds
- **Request System**: Structured proposal and voting mechanism
- **MPC Integration**: Secure distributed key generation via IKA protocol
- **Real-time Updates**: Automatic refresh on blockchain state changes
- **Error Handling**: Comprehensive error messages with toast notifications
- **Responsive Design**: Mobile-first design with desktop optimization

## Security Considerations

### MPC & Key Management

- **Distributed Keys**: Private keys never exist in one place
- **2PC Protocol**: Two-party computation for signature generation
- **IKA Network**: Decentralized validator network for MPC

### On-Chain Governance

- **Threshold Voting**: Configurable approval requirements
- **Rejection Mechanism**: Explicit rejection to prevent hanging requests
- **Expiration System**: Time-limited requests prevent stale proposals
- **Member Control**: Only members can vote and execute

### Application Security

- **Wallet Authentication**: Sui wallet signatures for all actions
- **Type Safety**: Full TypeScript coverage
- **Input Validation**: Client and contract-level validation
- **Testnet Only**: Designed exclusively for testing environments

## Development

### Project Structure

```
examples/multisig-bitcoin/
├── contract/                    # Move smart contracts
│   ├── sources/
│   │   ├── multisig.move       # Main multisig logic
│   │   ├── request.move        # Request management
│   │   ├── events.move         # Event definitions
│   │   ├── constants.move      # Protocol constants
│   │   ├── error.move          # Error codes
│   │   └── lib/
│   │       └── event_wrapper.move
│   └── Move.toml               # Package manifest
│
└── frontend/                   # Next.js application
    ├── src/
    │   ├── app/               # Next.js app router
    │   │   ├── page.tsx      # Main dashboard
    │   │   └── layout.tsx    # Root layout
    │   ├── components/
    │   │   ├── common/       # Shared components
    │   │   ├── modals/       # Dialog modals
    │   │   ├── multisig/     # Multisig-specific UI
    │   │   ├── sidebar/      # Navigation sidebar
    │   │   └── ui/           # shadcn/ui components
    │   ├── contexts/         # React contexts
    │   ├── generated/        # Auto-generated contract types
    │   ├── hooks/            # Custom React hooks
    │   ├── lib/              # Utility functions
    │   ├── multisig/         # Bitcoin integration
    │   └── workers/          # Web workers
    ├── scripts/              # Deployment scripts
    └── package.json
```

### Development Workflow

#### Working with Smart Contracts

1. **Edit contracts** in `contract/sources/`
2. **Build contracts:**
   ```bash
   cd contract
   sui move build
   ```
3. **Publish to testnet:**
   ```bash
   sui client publish --gas-budget 100000000
   ```
4. **Update frontend config** with new package ID

#### Frontend Development

1. **Generate types** from contracts:

   ```bash
   cd frontend
   npm run codegen  # Regenerates src/generated/
   ```

2. **Run development server:**

   ```bash
   npm run dev
   ```

3. **Build for production:**
   ```bash
   npm run build
   ```

#### Adding New Features

**New Request Type:**

1. Add request variant in `contract/sources/request.move`
2. Implement execution logic in `multisig.move`
3. Create modal component in `frontend/src/components/modals/`
4. Add UI in `MultisigDetailsView.tsx`
5. Regenerate types and integrate

**New UI Component:**

1. Add to `src/components/ui/` (use shadcn/ui CLI if available)
2. Import and use in relevant components
3. Ensure responsive design (mobile + desktop)

**New Hook:**

1. Create in `src/hooks/`
2. Use SWR for data fetching
3. Integrate with contract queries

### Testing

- **Manual Testing**: Use Sui testnet wallet with test tokens
- **Contract Testing**: Use `sui move test` for unit tests
- **Frontend Testing**: Test with multiple wallet providers
- **Network Testing**: Verify IKA validator integration

### Common Tasks

**Update Contract Address:**

```bash
cd frontend
./scripts/update_published_address.bash <NEW_PACKAGE_ID>
```

**Install Dependencies:**

```bash
npm install        # or pnpm install / bun install
```

**Clean Build:**

```bash
rm -rf .next node_modules
npm install
npm run build
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with clear commit messages
4. Test thoroughly on testnet
5. Submit a pull request with a detailed description

## Resources

- [IKA Network Documentation](../../docs)
- [Sui Documentation](https://docs.sui.io/)
- [Move Language Guide](https://move-language.github.io/move/)
- [Next.js Documentation](https://nextjs.org/docs)

## License

This project is part of the IKA Network. See the root LICENSE file for details.
