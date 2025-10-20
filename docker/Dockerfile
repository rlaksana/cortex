# Cortex Memory MCP - Multi-stage Docker Build
# Stage 1: Build TypeScript
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including devDependencies for build)
RUN npm install

# Copy source code
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# Stage 2: Production runtime
FROM node:20-alpine AS runtime

WORKDIR /app

# Install dumb-init for proper signal handling and netcat for connection testing
RUN apk add --no-cache dumb-init netcat-openbsd

# Create non-root user
RUN addgroup -g 1001 cortex && \
    adduser -D -u 1001 -G cortex cortex

# Copy built artifacts from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/migrations ./migrations

# Copy environment template
COPY .env.example ./.env.example

# Set ownership to non-root user
RUN chown -R cortex:cortex /app

# Switch to non-root user
USER cortex

# Expose health check port (if implementing HTTP endpoint later)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "process.exit(0)" || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start MCP server
CMD ["node", "dist/index.js"]
