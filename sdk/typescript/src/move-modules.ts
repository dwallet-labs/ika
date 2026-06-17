// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Aggregates the codegen'd Move-module bindings into one namespace per
// on-chain package. Consumers reach individual modules as e.g.
//   ikaDwallet2pcMpc.PricingModule.SomeStruct
//   ikaSystem.ValidatorSetModule.NextEpochValidators
//   ikaCommon.BlsCommitteeModule.BlsCommittee
//
// Keep this file in sync with `src/generated/<package>/*.ts` after codegen.

import * as AddressModule from './generated/ika_common/address.js';
import * as AdvanceEpochApproverModule from './generated/ika_common/advance_epoch_approver.js';
import * as BlsCommitteeModule from './generated/ika_common/bls_committee.js';
import * as ExtendedFieldModule from './generated/ika_common/extended_field.js';
import * as MultiaddrModule from './generated/ika_common/multiaddr.js';
import * as ProtocolCapModule from './generated/ika_common/protocol_cap.js';
import * as SystemCurrentStatusInfoModule from './generated/ika_common/system_current_status_info.js';
import * as SystemObjectCapModule from './generated/ika_common/system_object_cap.js';
import * as UpgradePackageApproverModule from './generated/ika_common/upgrade_package_approver.js';
import * as ValidatorCapModule from './generated/ika_common/validator_cap.js';
import * as CoordinatorInnerModule from './generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as CoordinatorModule from './generated/ika_dwallet_2pc_mpc/coordinator.js';
import * as IkaDwallet2pcMpcDisplayModule from './generated/ika_dwallet_2pc_mpc/ika_dwallet_2pc_mpc_display.js';
import * as IkaDwallet2pcMpcInitModule from './generated/ika_dwallet_2pc_mpc/ika_dwallet_2pc_mpc_init.js';
import * as PricingAndFeeManagerModule from './generated/ika_dwallet_2pc_mpc/pricing_and_fee_manager.js';
import * as PricingModule from './generated/ika_dwallet_2pc_mpc/pricing.js';
import * as SessionsManagerModule from './generated/ika_dwallet_2pc_mpc/sessions_manager.js';
import * as SupportConfigModule from './generated/ika_dwallet_2pc_mpc/support_config.js';
import * as IkaSystemDisplayModule from './generated/ika_system/display.js';
import * as IkaSystemInitModule from './generated/ika_system/init.js';
import * as PendingActiveSetModule from './generated/ika_system/pending_active_set.js';
import * as PendingValuesModule from './generated/ika_system/pending_values.js';
import * as ProtocolTreasuryModule from './generated/ika_system/protocol_treasury.js';
import * as StakedIkaModule from './generated/ika_system/staked_ika.js';
import * as SystemInnerModule from './generated/ika_system/system_inner.js';
import * as SystemModule from './generated/ika_system/system.js';
import * as TokenExchangeRateModule from './generated/ika_system/token_exchange_rate.js';
import * as ValidatorInfoModule from './generated/ika_system/validator_info.js';
import * as ValidatorMetadataModule from './generated/ika_system/validator_metadata.js';
import * as ValidatorSetModule from './generated/ika_system/validator_set.js';
import * as ValidatorModule from './generated/ika_system/validator.js';
import * as IkaTokenModule from './generated/ika/ika.js';

export const ikaDwallet2pcMpc = {
	CoordinatorModule,
	CoordinatorInnerModule,
	SessionsManagerModule,
	PricingModule,
	PricingAndFeeManagerModule,
	SupportConfigModule,
	IkaDwallet2pcMpcDisplayModule,
	IkaDwallet2pcMpcInitModule,
} as const;

export const ikaSystem = {
	SystemModule,
	SystemInnerModule,
	ValidatorModule,
	ValidatorInfoModule,
	ValidatorMetadataModule,
	ValidatorSetModule,
	StakedIkaModule,
	PendingActiveSetModule,
	PendingValuesModule,
	ProtocolTreasuryModule,
	TokenExchangeRateModule,
	IkaSystemDisplayModule,
	IkaSystemInitModule,
} as const;

export const ikaCommon = {
	AddressModule,
	AdvanceEpochApproverModule,
	BlsCommitteeModule,
	ExtendedFieldModule,
	MultiaddrModule,
	ProtocolCapModule,
	SystemCurrentStatusInfoModule,
	SystemObjectCapModule,
	UpgradePackageApproverModule,
	ValidatorCapModule,
} as const;

export const ika = {
	IkaTokenModule,
} as const;
