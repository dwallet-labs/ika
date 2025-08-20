const wasmModule = require('./dist/web/dwallet_mpc_wasm.js');

// For CommonJS environments, we need to export a function that initializes the WASM
// and then return all the WASM exports
async function init(wasmPath) {
	await wasmModule.default(wasmPath);
	return wasmModule;
}

// Export the init function as default
module.exports = init;

// Also export all WASM functions directly for backwards compatibility
// Note: These will only work after init() has been called
Object.assign(module.exports, wasmModule);
