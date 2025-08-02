import { SuiClient } from '@mysten/sui/client';

export interface IkaPackageConfig {
	ikaPackage: string;
	ikaCommonPackage: string;
	ikaDwallet2pcMpcPackage: string;
	ikaSystemPackage: string;
}

export interface IkaObjectsConfig {
	ikaSystemObject: {
		objectID: string;
		initialSharedVersion: number;
	};
	ikaDWalletCoordinator: {
		objectID: string;
		initialSharedVersion: number;
	};
	ikaDWalletCoordinatorInner: {
		objectID: string;
		initialSharedVersion: number;
	};
	ikaDWalletCoordinatorInnerKeys: {
		objectID: string;
		initialSharedVersion: number;
	};
}

export interface IkaConfig {
	packages: IkaPackageConfig;
	objects: IkaObjectsConfig;
}

export interface IkaClientOptions {
	config: IkaConfig;
	suiClient: SuiClient;
	timeout?: number;
	publicParameters?: {
		decryptionKeyPublicOutputID: string;
		epoch: number;
		publicParameters: Uint8Array;
	};
}

export interface CoordinatorInner {
	fields: {
		value: {
			fields: {
				dwallet_network_encryption_keys: {
					fields: {
						id: {
							id: string;
						};
						size: number;
					};
				};
				current_epoch: number;
				pricing_and_fee_manager: {
					fields: {
						gas_fee_reimbursement_sui_system_call_value: number;
						/// SUI balance for gas fee reimbursement to fund network tx responses
						gas_fee_reimbursement_sui_system_call_balance: number;
						/// IKA fees charged for consensus validation
						fee_charged_ika: number;
					};
				};
			};
		};
	};
}

export interface SystemInner {
	fields: {
		value: {
			fields: {
				validator_set: {
					fields: {
						validators: {
							fields: {
								id: {
									id: string;
								};
								size: number;
							};
						};
					};
				};
			};
		};
	};
}

export interface DWalletNetworkDecryptionKey {
	fields: {
		id: { id: string };
		network_dkg_public_output: MoveObject<{
			contents: {
				fields: {
					id: { id: string };
				};
			};
		}>;
	};
}

export interface MoveObject<TFields> {
	fields: TFields;
}

export interface MoveDynamicField {
	fields: {
		name: string;
		value: Uint8Array;
	};
}
