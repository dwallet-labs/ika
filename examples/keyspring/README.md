# KeySpring Demo (Ika Cross-Chain Wallet Demo)

Create an Ethereum wallet from any browser wallet **or passkey** and send ETH on Base Sepolia — all non-custodially using Ika's distributed key generation.

---

> ⚠️ **Testnet Only — Developer Warning**
>
> This cross-chain wallet demo is provided for **developer testing and educational purposes only** and must be used on **Base Sepolia testnet only** (not mainnet).
>
> It has not been audited and may contain bugs or unexpected behavior. **Do not use it with real funds or production wallets.** Use only test keys and disposable testnet amounts.
>
> **You assume all risk by proceeding.**

---

## What This Demo Shows

This demo showcases how Ika enables **cross-chain wallet creation**. Using your existing wallet (MetaMask, Phantom, etc.) or a **passkey**, you can:

1. **Create a new Ethereum address** — derived through distributed key generation on the Ika network
2. **Send ETH transactions** — sign and broadcast to Base Sepolia testnet
3. **Stay non-custodial** — your secret share never leaves your browser

### The Magic

- Connect with a **Solana** wallet → get an **Ethereum** address
- Connect with **MetaMask** → get a **new, separate** Ethereum address
- Use a **Passkey** (Face ID, Touch ID, Windows Hello) → get an **Ethereum** address with no wallet needed
- Your existing wallet or passkey derives encryption keys, then Ika's DKG creates your new wallet

## Try It Out

### 1. Start the Backend

```bash
cd backend
bun install
export SUI_ADMIN_SECRET_KEY="suiprivkey..."  # bech32 Sui signer
bun run dev
```

The backend now uses `@ika.xyz/plugins` for fee allocation, transaction
composition, and Ethereum broadcast. `IKA_COIN_ID` is no longer required —
fee coins are minted on demand via viem-style `coinWithBalance`.

### 2. Start the Frontend

```bash
cd frontend
bun install
bun run dev
```

### 3. Use the Demo

1. Open `http://localhost:3000`
2. Connect your wallet (MetaMask, Phantom, etc.) **or create a passkey wallet**
3. Click **"Create Wallet"** and sign the message (or authenticate with your passkey)
4. Wait for your new Ethereum address to be generated
5. Fund it with [Base Sepolia testnet ETH](https://www.alchemy.com/faucets/base-sepolia)
6. Send a transaction!

## How It Works

```
Your Wallet                    Ika Network                   Base Sepolia
    │                              │                              │
    │  1. Sign message             │                              │
    │─────────────────────────────▶│                              │
    │                              │                              │
    │  2. DKG creates dWallet      │                              │
    │◀─────────────────────────────│                              │
    │                              │                              │
    │  3. You get ETH address      │                              │
    │  (derived from dWallet)      │                              │
    │                              │                              │
    │  4. Sign tx locally          │                              │
    │  (secret never leaves)       │                              │
    │─────────────────────────────▶│                              │
    │                              │                              │
    │  5. Ika completes signature  │  6. Broadcast tx             │
    │                              │─────────────────────────────▶│
    │                              │                              │
    │  7. TX confirmed!            │◀─────────────────────────────│
    │◀─────────────────────────────│                              │
```

### Key Points

- **Non-custodial**: Your secret key share is computed in your browser and never sent to any server
- **Cross-chain**: Use any wallet to control an Ethereum address
- **Secure**: Based on Ika's [Zero-Trust dWallet](https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet) model

### Plugin Architecture

The backend uses three plugins from `@ika.xyz/plugins`:

| Plugin                          | Role                                                        |
| ------------------------------- | ----------------------------------------------------------- |
| `suiSource`                     | Sui-side transaction envelope: fee coins, signing, exec     |
| `ethPublisher`                  | Broadcasts signed Ethereum txs to Base Sepolia              |
| `assembleEthereumPayload`       | Helper: (r,s) + tx → serialized signed tx (yParity recovery) |

The source is constructed **without a USEK** — the backend never sees user
key material. Two non-custodial primitives bridge the gap:

- `ika.sui.compose.submitDKG(...)` — submit a DKG with a payload prepared
  by the browser. Optionally emits the encryption-key registration call.
- `ika.sui.compose.submitSign(...)` — submit a sign with a precomputed
  `userSignMessage`. Emits accept-share + verify-presign + approve +
  request-sign in a single PTB.

Both helpers wrap the low-level coordinator Move calls in a typed API and
get fee allocation + execution for free via `ika.sui.transaction(...)`.

### How Passkey Authentication Works

When using a passkey instead of a wallet:

1. **Registration**: A passkey is created with the WebAuthn PRF extension enabled
2. **Authentication**: The PRF extension derives a deterministic 32-byte secret from your passkey
3. **Key Derivation**: This secret is used as the seed for encryption keys (same as a wallet signature would be)
4. **DKG**: The rest of the flow is identical — Ika's DKG creates your new Ethereum wallet

> **Important**: If you delete your passkey, you lose access to the wallet permanently. There is no recovery option.

## Supported Authentication Methods

| Method               | Type     | Works? | Notes                                     |
| -------------------- | -------- | ------ | ----------------------------------------- |
| **Passkey**          | WebAuthn | ✅     | Face ID, Touch ID, Windows Hello, YubiKey |
| MetaMask             | Ethereum | ✅     |                                           |
| Phantom (Ethereum)   | Ethereum | ✅     |                                           |
| Phantom (Solana)     | Solana   | ✅     |                                           |
| Other Solana wallets | Solana   | ✅     |                                           |

### Passkey Browser Support

| Platform   | Browser           | Platform Passkey | Hardware Key |
| ---------- | ----------------- | ---------------- | ------------ |
| macOS 15+  | Chrome/Safari 18+ | ✅               | Chrome only  |
| Windows 11 | Chrome/Edge       | ✅               | ✅           |
| iOS 18+    | Safari            | ✅               | ❌           |
| Android    | Chrome            | ✅               | USB only     |

> **Note**: Passkey support requires the WebAuthn PRF extension for deterministic key derivation.

## Configuration

### Backend Environment

| Variable               | Description                                     | Default   |
| ---------------------- | ----------------------------------------------- | --------- |
| `PORT`                 | Server port                                     | `3001`    |
| `SUI_ADMIN_SECRET_KEY` | bech32 `suiprivkey...` Sui signer               | Required  |
| `SUI_NETWORK`          | `testnet` or `mainnet`                          | `testnet` |
| `SUI_RPC_URL`          | Override the Sui RPC endpoint                   | optional  |

### Frontend Environment

| Variable                    | Description               | Default                 |
| --------------------------- | ------------------------- | ----------------------- |
| `NEXT_PUBLIC_API_URL`       | Backend URL               | `http://localhost:5153` |
| `NEXT_PUBLIC_ADMIN_ADDRESS` | Sui admin address for DKG | Required                |

## Learn More

- [Ika Documentation](https://docs.ika.xyz)
- [Zero-Trust dWallet](https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet)
- [Get Base Sepolia ETH](https://www.alchemy.com/faucets/base-sepolia)
