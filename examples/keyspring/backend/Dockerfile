# Use official Bun image for better stability on Railway
FROM oven/bun:1.1-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app

# Copy package files
COPY package.json bun.lockb ./

# Install dependencies
RUN bun install --frozen-lockfile

# Production image
FROM base AS runner
WORKDIR /app

# Don't run as root for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 bunjs

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY --chown=bunjs:nodejs . .

# Switch to non-root user
USER bunjs

# Expose port (Railway will set PORT env var)
EXPOSE 3001

# Set environment
ENV NODE_ENV=production
ENV HOST=0.0.0.0

# Health check - Railway will also use /health endpoint
# Using bun to make the health check request
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD bun -e "fetch('http://localhost:' + (process.env.PORT || 3001) + '/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Run the app
CMD ["bun", "run", "src/index.ts"]

