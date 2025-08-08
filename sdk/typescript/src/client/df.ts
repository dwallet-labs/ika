import type { BcsType } from '@mysten/sui/bcs';
import { bcs, BcsStruct } from '@mysten/sui/bcs';

import * as coordinator_inner from '../generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as system_inner from '../generated/ika_system/system_inner.js';

export function DynamicField<E extends BcsType<any>>(...typeParameters: [E]) {
	return new BcsStruct({
		name: `dynamic_field::Field<u64, ${typeParameters[0].name as E['name']}>`,
		fields: {
			id: bcs.Address,
			name: bcs.u64(),
			value: typeParameters[0],
		},
	});
}

export const CoordinatorInnerDynamicField = DynamicField(coordinator_inner.DWalletCoordinatorInner);

export const SystemInnerDynamicField = DynamicField(system_inner.SystemInner);
