# IKA Multisig Bitcoin Wallet Frontend

A modern, secure multisignature Bitcoin wallet frontend built with the IKA protocol for distributed key generation and management.

## Features

- **Secure Multisig Creation**: Create 2-of-3 multisignature wallets with distributed key generation
- **Wallet Management**: View and manage your multisig wallets with detailed information
- **Transaction Creation**: Create and submit transactions from your multisig wallets
- **Network Integration**: Full integration with Sui blockchain and IKA protocol
- **Modern UI**: Beautiful, responsive interface with dark mode support
- **Wallet Connection**: Seamless integration with popular Sui wallets

## Getting Started

### Prerequisites

- Node.js 18+
- npm or pnpm
- Sui wallet (Sui Wallet, Ethos, etc.)

### Installation

1. **Install dependencies:**

   ```bash
   cd frontend
   npm install
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

## Usage

### 1. Connect Your Wallet

- Click the "Connect Wallet" button in the header
- Select your preferred Sui wallet
- Approve the connection

### 2. Create a Multisig Wallet

- Click "Create Multisig Wallet" in the main dashboard
- The system will automatically create a 2-of-3 multisig wallet
- Wait for the distributed key generation process to complete
- Your new wallet will appear in the "Your Multisig Wallets" section

### 3. View Wallet Details

Each multisig wallet displays:

- **Wallet ID**: Unique identifier for the multisig wallet
- **DWallet ID**: Associated distributed wallet identifier
- **Participants**: List of signer addresses (2 of 3 required)
- **Status**: Current wallet status (Active/Creating)

### 4. Create Transactions

- Click "Create Transaction" on any active multisig wallet
- Fill in the transaction details:
  - Recipient address
  - Amount in SUI
  - Optional description
- Submit the transaction for multisig approval

## Architecture

### Frontend Components

- **MultisigDashboard**: Main dashboard for wallet management
- **WalletConnection**: Handles Sui wallet connection status
- **NetworkStatus**: Shows IKA network connection status
- **CreateTransaction**: Modal for creating new transactions
- **UI Components**: Reusable components (Button, Card, Input, etc.)

### Key Features

- **Distributed Key Generation**: Uses IKA's MPC protocol for secure key distribution
- **2-of-3 Multisig**: Requires 2 out of 3 signatures for transaction execution
- **Real-time Status**: Live updates on wallet and transaction status
- **Error Handling**: Comprehensive error handling and user feedback
- **Responsive Design**: Works on desktop and mobile devices

## Security

- **MPC Protocol**: Uses secure multi-party computation for key generation
- **Distributed Keys**: No single point of failure for private keys
- **Wallet Integration**: Secure connection to user's Sui wallet
- **Transaction Signing**: Multi-signature requirement prevents unauthorized transactions

## Development

### Project Structure

```
frontend/
├── src/
│   ├── components/          # React components
│   │   ├── ui/             # Reusable UI components
│   │   ├── MultisigDashboard.tsx
│   │   ├── WalletConnection.tsx
│   │   ├── NetworkStatus.tsx
│   │   └── CreateTransaction.tsx
│   ├── contract/           # Contract integration
│   ├── hooks/              # Custom React hooks
│   ├── pages/              # Next.js pages
│   └── styles/             # Global styles
├── public/                 # Static assets
└── package.json
```

### Adding New Features

1. Create new components in `src/components/`
2. Add UI components to `src/components/ui/`
3. Integrate with IKA SDK in `src/contract/`
4. Update the main dashboard as needed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is part of the IKA Network and follows the same licensing terms.
