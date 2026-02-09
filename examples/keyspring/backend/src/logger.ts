import pino from "pino";

// pino-pretty transport uses Node.js worker threads which Bun doesn't support
// Use basic pino - Railway captures JSON logs properly
export const logger = pino({
  level: process.env.LOG_LEVEL || "debug",
});
