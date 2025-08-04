import { SuiEvent } from '@mysten/sui/client';

import { isStartDKGFirstRoundEvent } from './type-guards';
import { StartDKGFirstRoundEvent } from './types';

export function parseDKGFirstRoundEvents(events: SuiEvent[]): StartDKGFirstRoundEvent[] {
	const startDKGFirstRoundEvents = events.filter(isStartDKGFirstRoundEvent);
	return startDKGFirstRoundEvents.map((event) => event.parsedJson as StartDKGFirstRoundEvent);
}
