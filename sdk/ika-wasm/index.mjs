import wasmInit, { initSync } from './dist/web/dwallet_mpc_wasm.js';

export * from './dist/web/dwallet_mpc_wasm.js';

// Export the WASM initialization function as the default export
// This must be called before using any WASM functions in the browser
export default wasmInit;

// Also export the sync version for cases where WASM binary is already loaded
export { initSync };
