import { SuiObjectResponse } from '@mysten/sui/client';

import { InvalidObjectError } from './errors';

export function objResToBcs(resp: SuiObjectResponse): string {
	if (resp.data?.bcs?.dataType !== 'moveObject') {
		throw new InvalidObjectError(`Response bcs missing: ${JSON.stringify(resp, null, 2)}`);
	}

	return resp.data.bcs.bcsBytes;
}
