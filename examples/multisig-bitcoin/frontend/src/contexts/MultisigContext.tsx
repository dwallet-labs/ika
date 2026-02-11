'use client';

import { createContext, ReactNode, useContext, useState } from 'react';

import type { MultisigOwnership } from '../hooks/useMultisigData';

interface MultisigContextType {
	selectedMultisigId: string | null;
	selectedMultisig: MultisigOwnership | null;
	selectMultisig: (multisig: MultisigOwnership | null) => void;
	clearSelection: () => void;
}

const MultisigContext = createContext<MultisigContextType | undefined>(undefined);

export function MultisigProvider({ children }: { children: ReactNode }) {
	const [selectedMultisig, setSelectedMultisig] = useState<MultisigOwnership | null>(null);

	const selectMultisig = (multisig: MultisigOwnership | null) => {
		setSelectedMultisig(multisig);
	};

	const clearSelection = () => {
		setSelectedMultisig(null);
	};

	return (
		<MultisigContext.Provider
			value={{
				selectedMultisigId: selectedMultisig?.id ?? null,
				selectedMultisig,
				selectMultisig,
				clearSelection,
			}}
		>
			{children}
		</MultisigContext.Provider>
	);
}

export function useMultisigContext() {
	const context = useContext(MultisigContext);
	if (context === undefined) {
		throw new Error('useMultisigContext must be used within a MultisigProvider');
	}
	return context;
}
