/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { MoveStruct } from '../utils/index.js';
import { bcs } from '@mysten/sui/bcs';
import * as vec_map from './deps/sui/vec_map.js';
const $moduleName = '@local-pkg/2pc-mpc::support_config';
export const SupportConfig = new MoveStruct({ name: `${$moduleName}::SupportConfig`, fields: {
        /**
           * A nested map of supported curves to signature algorithms to hash schemes. e.g.
           * secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
           */
        supported_curves_to_signature_algorithms_to_hash_schemes: vec_map.VecMap(bcs.u32(), vec_map.VecMap(bcs.u32(), bcs.vector(bcs.u32()))),
        /** List of paused curves in case of emergency (e.g. [secp256k1, ristretto]) */
        paused_curves: bcs.vector(bcs.u32()),
        /** List of paused signature algorithms in case of emergency (e.g. [ecdsa, schnorr]) */
        paused_signature_algorithms: bcs.vector(bcs.u32()),
        /** List of paused hash schemes in case of emergency (e.g. [sha256, keccak256]) */
        paused_hash_schemes: bcs.vector(bcs.u32()),
        /** Signature algorithms that are allowed for global presign */
        signature_algorithms_allowed_global_presign: bcs.vector(bcs.u32())
    } });