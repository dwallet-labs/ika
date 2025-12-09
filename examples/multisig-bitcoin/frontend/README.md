# bitisi Frontend

The frontend application for **bitisi** - a Bitcoin multisig wallet built on Sui using the IKA protocol.

## ⚠️ TESTNET ONLY - DEVELOPER WARNING

**This Bitcoin multisig demo is for testing and educational purposes only. Use on Bitcoin testnet only (not mainnet).**

This application has not been audited and may contain bugs. Do not use with real funds or production wallets. Use only test keys and disposable test amounts. You assume all risk by proceeding.

## Quick Start

### Development Server

```bash
npm run dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) to view the application.

The page auto-updates as you edit files in `src/`.

### Production Build

```bash
npm run build
npm start
```

## Project Structure

```
frontend/
├── src/
│   ├── app/                 # Next.js App Router
│   │   ├── page.tsx        # Main dashboard
│   │   ├── layout.tsx      # Root layout with providers
│   │   └── globals.css     # Global styles
│   │
│   ├── components/
│   │   ├── common/         # Shared components
│   │   │   ├── BalanceDisplay.tsx
│   │   │   ├── EmptyState.tsx
│   │   │   └── ...
│   │   ├── modals/         # Request creation modals
│   │   │   ├── CreateMultisigModal.tsx
│   │   │   ├── CreateTransactionModal.tsx
│   │   │   └── ...
│   │   ├── multisig/       # Multisig-specific components
│   │   │   ├── MultisigDetailsView.tsx
│   │   │   ├── MultisigRequestCard.tsx
│   │   │   └── ...
│   │   ├── sidebar/        # Navigation sidebar
│   │   │   ├── AppSidebar.tsx
│   │   │   └── MultisigList.tsx
│   │   └── ui/             # shadcn/ui components
│   │
│   ├── contexts/           # React Context providers
│   │   └── MultisigContext.tsx
│   │
│   ├── generated/          # Auto-generated from contracts
│   │   ├── ika/
│   │   ├── ika_btc_multisig/
│   │   └── utils/
│   │
│   ├── hooks/              # Custom React hooks
│   │   ├── useMultisigData.ts
│   │   ├── useMultisigFunctions.ts
│   │   ├── useObjects.ts
│   │   └── ...
│   │
│   ├── lib/                # Utilities
│   │   ├── error-handling.ts
│   │   ├── formatting.ts
│   │   └── utils.ts
│   │
│   ├── multisig/           # Bitcoin integration
│   │   └── bitcoin.ts
│   │
│   └── workers/            # Web Workers
│       └── ...
│
├── scripts/                # Deployment & maintenance
│   ├── publish_and_update.bash
│   └── update_published_address.bash
│
└── package.json
```

## Key Technologies

- **Framework**: Next.js 14+ with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS + shadcn/ui
- **Blockchain**: @mysten/sui.js + @mysten/dapp-kit
- **Data Fetching**: SWR (stale-while-revalidate)
- **State**: React Context API
- **Forms**: React Hook Form (in modals)

## Development

### Generate Contract Types

After updating Move contracts, regenerate TypeScript types:

```bash
npm run codegen
```

This updates `src/generated/` with the latest contract definitions.

### Update Published Address

After deploying new contracts to Sui testnet:

```bash
./scripts/update_published_address.bash <PACKAGE_ID>
```

### Code Structure Guidelines

- **Components**: Keep components small and focused
- **Hooks**: Extract contract interactions to custom hooks
- **Types**: Use generated types from contracts
- **Errors**: Use error-handling utilities for consistent UX
- **Mobile**: Always test responsive design

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm start` - Start production server
- `npm run lint` - Run ESLint
- `npm run codegen` - Generate types from contracts

## Configuration

Key configuration files:

- `sui-codegen.config.ts` - Contract type generation
- `next.config.ts` - Next.js configuration
- `tsconfig.json` - TypeScript configuration
- `tailwind.config.ts` - Tailwind CSS configuration
- `components.json` - shadcn/ui configuration

## Learn More

### IKA & Sui

- [IKA Documentation](https://docs.ika.xyz/)
- [Sui Documentation](https://docs.sui.io/)
- [Move Language](https://move-language.github.io/move/)

### Frontend Stack

- [Next.js Documentation](https://nextjs.org/docs)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [shadcn/ui](https://ui.shadcn.com/)
- [SWR](https://swr.vercel.app/)

## Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Import to [Vercel](https://vercel.com/new)
3. Configure environment variables if needed
4. Deploy

See [Next.js deployment docs](https://nextjs.org/docs/app/building-your-application/deploying) for other platforms.

## Troubleshooting

**Wallet Connection Issues:**

- Ensure you're on Sui testnet
- Clear browser cache and reconnect
- Try a different wallet provider

**Contract Interaction Errors:**

- Verify contract addresses in `src/generated/`
- Check you have sufficient SUI for gas
- Ensure wallet is connected

**Type Errors After Contract Update:**

- Run `npm run codegen` to regenerate types
- Restart TypeScript server in your editor

## Support

For issues or questions:

- Check the main [README](../README.md) for detailed usage guide
- Review [IKA documentation](../../../docs)
- Open an issue on GitHub
