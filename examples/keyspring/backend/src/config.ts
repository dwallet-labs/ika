import { z } from 'zod';

/**
 * Environment variable schema definition
 */
const envSchema = z.object({
	PORT: z.coerce.number().positive().default(3001),
	HOST: z.string().default('0.0.0.0'),

	// Sui Admin Keypair (base64 encoded secret key)
	SUI_ADMIN_SECRET_KEY: z.string().min(1, 'SUI_ADMIN_SECRET_KEY is required'),

	// Sui Network
	SUI_NETWORK: z.enum(['testnet', 'mainnet']).default('testnet'),

	// Optional Sui RPC URL override.
	SUI_RPC_URL: z.string().optional(),
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
	sui: {
		network: env.SUI_NETWORK,
		adminSecretKey: env.SUI_ADMIN_SECRET_KEY,
		rpcUrl: env.SUI_RPC_URL,
	},
} as const;
