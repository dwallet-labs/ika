import { z } from 'zod';

/**
 * Environment variable schema definition
 */
const envSchema = z.object({
	PORT: z.coerce.number().positive().default(3001),
	HOST: z.string().default('0.0.0.0'),

	// Sui Admin Keypair (base64 encoded secret key)
	SUI_ADMIN_SECRET_KEY: z.string().min(1, 'SUI_ADMIN_SECRET_KEY is required'),

	// Budget, in MIST, for the IKA fee attached to each dWallet operation. The
	// coin is selected from the admin's own IKA at build time; anything unspent
	// is returned by the coordinator.
	IKA_FEE_BUDGET: z.coerce.number().positive().default(1_000_000_000),

	// Sui Network
	SUI_NETWORK: z.enum(['testnet', 'mainnet']).default('testnet'),

	// Optional override for the Sui gRPC endpoint (public fullnodes no longer
	// serve JSON-RPC, so this is a gRPC base URL).
	SUI_GRPC_URL: z.string().url().optional(),
});

export type Env = z.infer<typeof envSchema>;

function validateEnv(): Env {
	try {
		return envSchema.parse(process.env);
	} catch (error) {
		if (error instanceof z.ZodError) {
			const errorMessages = error.issues
				.map((err: z.ZodIssue) => `${err.path.join('.')}: ${err.message}`)
				.join('\n');

			console.error('❌ Environment validation failed:');
			console.error(errorMessages);
			process.exit(1);
		}
		throw error;
	}
}

export const env = validateEnv();

export const config = {
	server: {
		port: env.PORT,
		host: env.HOST,
	},
	ika: {
		feeBudget: env.IKA_FEE_BUDGET,
	},
	sui: {
		network: env.SUI_NETWORK,
		adminSecretKey: env.SUI_ADMIN_SECRET_KEY,
		grpcUrl: env.SUI_GRPC_URL,
	},
} as const;
