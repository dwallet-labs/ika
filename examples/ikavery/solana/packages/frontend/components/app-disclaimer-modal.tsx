'use client';

import { DisclaimerModal, type DisclaimerClause } from '@fesal-packages/ikavery-frontend-ui';

const CLAUSES: DisclaimerClause[] = [
	{
		ord: '01',
		text: (
			<>
				Ikavery is a <span className="text-text">proof of concept</span> built for developers,
				researchers, and curious people exploring quorum-gated key custody on Solana. It is not a
				product, not a service, and not financial advice.
			</>
		),
	},
	{
		ord: '02',
		text: (
			<>
				Operates on <span className="text-text">Solana devnet</span> and the{' '}
				<span className="text-text">Ika pre-alpha mock signer</span> only. Do not point this at
				mainnet. Do not import keys that hold real funds. The Ika pre-alpha network resets without
				warning.
			</>
		),
	},
	{
		ord: '03',
		text: (
			<>
				The Solana program, SDK, and frontend have{' '}
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
				You are responsible for the wallet, browser session, and device that hold your keys.
				Whatever third-party wallet bridge brokers the connection has its own session model — that
				is on you.
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
		Ikavery on Solana is a developer demo of quorum-gated key custody via Ika 2PC-MPC. It is
		intended as a reference and a conversation, not as a wallet you put real value into.
	</>
);

export function AppDisclaimerModal() {
	return (
		<DisclaimerModal
			// Distinct storage key from the Sui app — running both on
			// *.ikavery.com would otherwise cross-contaminate the gate state if a
			// user visits both subdomains in the same browser profile.
			storageKey="recovery_disclaimer_solana_v1"
			clauses={CLAUSES}
			intro={INTRO}
		/>
	);
}
