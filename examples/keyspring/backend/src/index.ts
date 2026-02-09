import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { dkgExecutor } from "./dkg-executor.js";

/**
 * Demo Backend for Phantom + Ephemeral Keys + DKG + Ethereum Signing
 *
 * This is a simplified backend that:
 * 1. Accepts DKG submissions from the frontend
 * 2. Executes DKG transactions on the Ika network (SECP256K1 for Ethereum)
 * 3. Transfers dWallet cap to SUI_ADMIN
 * 4. Creates presigns for signing
 * 5. Signs Ethereum transactions
 */
function createApp() {
  const app = new Elysia()
    // Request logging
    .onRequest(({ request }) => {
      const startTime = Date.now();
      request.headers.set("x-request-start", startTime.toString());
    })
    .onAfterResponse(({ request, set }) => {
      const startTime = parseInt(request.headers.get("x-request-start") || "0");
      const duration = Date.now() - startTime;
      const method = request.method;
      const path = new URL(request.url).pathname;
      const statusCode = typeof set.status === "number" ? set.status : 200;

      logger.info({ method, path, statusCode, duration }, "HTTP Request");
    })

    // Error handler
    .onError(({ error, code, set }) => {
      logger.error({ err: error, code }, "Request error");

      if (code === "VALIDATION") {
        set.status = 400;
        return {
          success: false,
          error: "Validation Error",
          message: (error as Error).message || "Validation failed",
        };
      }

      set.status = 500;
      return {
        success: false,
        error: "Internal Server Error",
        message: (error as Error).message || "Unknown error",
      };
    })

    // CORS
    .use(
      cors({
        origin: "*",
        credentials: true,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type"],
      })
    )

    // Health check
    .get("/health", () => ({
      status: "healthy",
      timestamp: new Date().toISOString(),
      adminAddress: dkgExecutor.getAdminAddress(),
    }))

    // DKG Submit endpoint
    .post(
      "/api/dkg/submit",
      ({ body }) => {
        const request = dkgExecutor.submitRequest(body);
        return {
          success: true,
          requestId: request.id,
          status: request.status,
        };
      },
      {
        body: t.Object({
          userPublicOutput: t.Array(t.Number()),
          userDkgMessage: t.Array(t.Number()),
          encryptedUserShareAndProof: t.Array(t.Number()),
          sessionIdentifier: t.Array(t.Number()),
          signerPublicKey: t.Array(t.Number()),
          encryptionKeyAddress: t.String(),
          encryptionKey: t.Array(t.Number()),
          encryptionKeySignature: t.Array(t.Number()),
          curve: t.Optional(t.Number()),
        }),
        detail: {
          summary: "Submit DKG data",
          description:
            "Submit DKG computation results to create a dWallet (SECP256K1 for Ethereum by default)",
        },
      }
    )

    // DKG Status endpoint
    .get(
      "/api/dkg/status/:requestId",
      ({ params }) => {
        const request = dkgExecutor.getRequest(params.requestId);
        if (!request) {
          return {
            success: false,
            error: "Request not found",
          };
        }
        return {
          success: true,
          requestId: request.id,
          status: request.status,
          dWalletCapObjectId: request.dWalletCapObjectId,
          dWalletObjectId: request.dWalletObjectId,
          encryptedUserSecretKeyShareId: request.encryptedUserSecretKeyShareId,
          ethereumAddress: request.ethereumAddress,
          error: request.error,
        };
      },
      {
        params: t.Object({
          requestId: t.String(),
        }),
        detail: {
          summary: "Get DKG status",
          description: "Check the status of a DKG request",
        },
      }
    )

    // Presign request endpoint
    .post(
      "/api/presign/request",
      ({ body }) => {
        const request = dkgExecutor.submitPresignRequest(body.dWalletId);
        return {
          success: true,
          requestId: request.id,
          status: request.status,
        };
      },
      {
        body: t.Object({
          dWalletId: t.String(),
        }),
        detail: {
          summary: "Request presign",
          description: "Request a presign for signing messages",
        },
      }
    )

    // Presign status endpoint
    .get(
      "/api/presign/status/:requestId",
      ({ params }) => {
        const request = dkgExecutor.getPresignRequest(params.requestId);
        if (!request) {
          return {
            success: false,
            error: "Request not found",
          };
        }
        return {
          success: true,
          requestId: request.id,
          status: request.status,
          presignId: request.presignId,
          error: request.error,
        };
      },
      {
        params: t.Object({
          requestId: t.String(),
        }),
        detail: {
          summary: "Get presign status",
          description: "Check the status of a presign request",
        },
      }
    )

    // Get dWallet details (for fetching after DKG)
    .get(
      "/api/dwallet/:dWalletId",
      async ({ params }) => {
        try {
          const ikaClient = dkgExecutor.getIkaClient();
          const dWallet = await ikaClient.getDWallet(params.dWalletId);
          return {
            success: true,
            dWallet: {
              id: dWallet?.id,
              state: dWallet?.state,
              dwalletCapId: dWallet?.dwallet_cap_id,
            },
          };
        } catch (error) {
          return {
            success: false,
            error:
              error instanceof Error ? error.message : "Failed to get dWallet",
          };
        }
      },
      {
        params: t.Object({
          dWalletId: t.String(),
        }),
        detail: {
          summary: "Get dWallet details",
          description: "Fetch dWallet state from the network",
        },
      }
    )

    // Sign request endpoint (non-custodial)
    // The userSignMessage is computed client-side - secret share never leaves the client
    .post(
      "/api/sign/request",
      ({ body }) => {
        const request = dkgExecutor.submitSignRequest(body);
        return {
          success: true,
          requestId: request.id,
          status: request.status,
        };
      },
      {
        body: t.Object({
          dWalletId: t.String(),
          dWalletCapId: t.String(),
          encryptedUserSecretKeyShareId: t.String(),
          userOutputSignature: t.Array(t.Number()),
          presignId: t.String(),
          messageHex: t.String(),
          userSignMessage: t.Array(t.Number()),
          // Optional: Ethereum transaction for broadcast to Sepolia
          ethTx: t.Optional(
            t.Object({
              to: t.String(),
              value: t.String(),
              nonce: t.Number(),
              gasLimit: t.String(),
              maxFeePerGas: t.String(),
              maxPriorityFeePerGas: t.String(),
              chainId: t.Number(),
              from: t.String(),
            })
          ),
        }),
        detail: {
          summary: "Request signature (non-custodial)",
          description:
            "Submit userSignMessage (computed client-side) to complete Ethereum signature. Optionally broadcast to Sepolia.",
        },
      }
    )

    // Sign status endpoint
    .get(
      "/api/sign/status/:requestId",
      ({ params }) => {
        const request = dkgExecutor.getSignRequest(params.requestId);
        if (!request) {
          return {
            success: false,
            error: "Request not found",
          };
        }
        return {
          success: true,
          requestId: request.id,
          status: request.status,
          signatureHex: request.signatureHex,
          signId: request.signId,
          ethTxHash: request.ethTxHash,
          ethBlockNumber: request.ethBlockNumber,
          error: request.error,
        };
      },
      {
        params: t.Object({
          requestId: t.String(),
        }),
        detail: {
          summary: "Get sign request status",
          description: "Check the status of a sign request",
        },
      }
    )

    // Get Ethereum transaction parameters (nonce, gas prices) for signing
    .get(
      "/api/eth/tx-params/:address",
      async ({ params }) => {
        try {
          const txParams = await dkgExecutor.getEthTxParams(params.address);
          return {
            success: true,
            ...txParams,
          };
        } catch (error) {
          return {
            success: false,
            error:
              error instanceof Error
                ? error.message
                : "Failed to get transaction parameters",
          };
        }
      },
      {
        params: t.Object({
          address: t.String(),
        }),
        detail: {
          summary: "Get ETH transaction parameters",
          description:
            "Fetch nonce and gas prices for an Ethereum address (for signing)",
        },
      }
    );

  return app;
}

// Graceful shutdown
let keepaliveInterval: NodeJS.Timeout | null = null;
let selfPingInterval: NodeJS.Timeout | null = null;

async function gracefulShutdown(signal: string) {
  logger.info({ signal }, "Starting graceful shutdown");
  if (keepaliveInterval) {
    clearInterval(keepaliveInterval);
    keepaliveInterval = null;
  }
  if (selfPingInterval) {
    clearInterval(selfPingInterval);
    selfPingInterval = null;
  }
  dkgExecutor.stop();
  process.exit(0);
}

// Start server
async function start() {
  // Global error handlers to prevent crashes
  process.on("uncaughtException", (error) => {
    logger.error(
      { error: error.message, stack: error.stack },
      "Uncaught exception - process continuing"
    );
    // Don't exit - keep the process running
  });

  process.on("unhandledRejection", (reason) => {
    logger.error(
      { reason },
      "Unhandled promise rejection - process continuing"
    );
    // Don't exit - keep the process running
  });

  logger.info(
    {
      adminAddress: dkgExecutor.getAdminAddress(),
    },
    "Starting Demo DKG Backend"
  );

  // Start DKG executor
  dkgExecutor.start();

  // Create and start app
  const app = createApp();

  app.listen({
    port: config.server.port,
    hostname: config.server.host,
  });

  logger.info(
    {
      url: `http://${config.server.host}:${config.server.port}`,
      adminAddress: dkgExecutor.getAdminAddress(),
    },
    "Server is running"
  );

  // Keepalive interval - logs heartbeat every 5 minutes
  keepaliveInterval = setInterval(() => {
    const memUsage = process.memoryUsage();
    logger.info(
      {
        uptime: Math.floor(process.uptime()),
        heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024),
        rssMB: Math.round(memUsage.rss / 1024 / 1024),
      },
      "Service heartbeat"
    );
  }, 5 * 60 * 1000); // Every 5 minutes

  // Self-ping interval - keeps the HTTP server active by making internal requests
  // This prevents Bun's HTTP server from going into an idle state on Railway
  selfPingInterval = setInterval(async () => {
    try {
      const response = await fetch(
        `http://127.0.0.1:${config.server.port}/health`
      );
      if (!response.ok) {
        logger.warn(
          { status: response.status },
          "Self-ping health check returned non-OK status"
        );
      }
    } catch (error) {
      logger.error({ error }, "Self-ping health check failed");
    }
  }, 60 * 1000); // Every 1 minute

  // Shutdown handlers
  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

start();
