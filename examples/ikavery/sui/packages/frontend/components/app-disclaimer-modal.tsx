'use client';

import { DisclaimerModal, type DisclaimerClause } from '@fesal-packages/ikavery-frontend-ui';

const CLAUSES: DisclaimerClause[] = [
	{
		ord: '01',
		text: (
			<>
				Ikavery is a <span className="text-text">proof of concept</span> built for developers,
				researchers, and curious people exploring passkey-gated key custody. It is not a product,
				not a service, and not financial advice.
			</>
		),
	},
	{
		ord: '02',
		text: (
			<>
				Operates on <span className="text-text">Sui testnet</span> and{' '}
				<span className="text-text">Solana devnet</span> only. Do not point this at mainnet. Do not
				import keys that hold real funds.
			</>
		),
	},
	{
		ord: '03',
		text: (
			<>
				The Move contract, SDK, and frontend have{' '}
				<span className="text-text">not been independently audited</span>. They may contain bugs,
				race conditions, or unexpected behavior.
			</>
		),
	},
	{
		ord: '04',
		text: (
			<>
				Use only test keys you generated specifically for this demo. Use a disposable Solana keypair
				funded with <span className="text-text">devnet SOL only</span>.
			</>
		),
	},
	{
		ord: '05',
		text: (
			<>
				Passkey credentials created here are bound to this site. You are responsible for the device,
				browser, and authenticator that hold them.
			</>
		),
	},
	{
		ord: '06',
		text: (
			<>
				<span className="text-text">No warranty, no guarantee, no liability.</span> Any loss of
				access, funds, or data is yours alone to bear.
			</>
		),
	},
];

const INTRO = (
	<>
		Ikavery is a developer demo of passkey-gated key custody on Sui via Ika 2PC-MPC. It is intended
		as a reference and a conversation, not as a wallet you put real value into.
	</>
);

export function AppDisclaimerModal() {
	return <DisclaimerModal storageKey="recovery_disclaimer_v1" clauses={CLAUSES} intro={INTRO} />;
}
