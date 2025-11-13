import { useContext } from 'react';

import { IkaClientContext, IkaClientContextType } from '../components/providers/IkaClientProvider';

export function useIkaClient(): IkaClientContextType {
	const context = useContext(IkaClientContext);

	if (context === undefined) {
		throw new Error('useIkaClient must be used within an IkaClientProvider');
	}

	return context;
}
