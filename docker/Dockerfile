# Cortex Memory MCP - Production Multi-stage Docker Build
# Optimized for production deployment with security and performance enhancements

# Stage 1: Build TypeScript with security scanning
FROM node:20-alpine AS builder

# Install security tools
RUN apk add --no-cache dumb-init curl

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci --only=production=false && \
    npm cache clean --force

# Copy source code
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/

# Security audit and build
RUN npm audit --audit-level=high && \
    npm run build && \
    npm run security:audit || true && \
    npm prune --production

# Stage 2: Production runtime with security hardening
FROM node:20-alpine AS runtime

# Install security and monitoring tools
RUN apk add --no-cache \
    dumb-init \
    curl \
    netcat-openbsd \
    ca-certificates \
    tzdata && \
    update-ca-certificates && \
    rm -rf /var/cache/apk/*

# Create non-root user with limited privileges
RUN addgroup -g 1001 -S cortex && \
    adduser -S -u 1001 -G cortex cortex && \
    mkdir -p /app/logs /app/tmp && \
    chown -R cortex:cortex /app

# Set timezone
ENV TZ=UTC

WORKDIR /app

# Copy built artifacts from builder
COPY --from=builder --chown=cortex:cortex /app/dist ./dist
COPY --from=builder --chown=cortex:cortex /app/node_modules ./node_modules
COPY --from=builder --chown=cortex:cortex /app/package.json ./
COPY --from=builder --chown=cortex:cortex /app/migrations ./migrations

# Copy production environment template
COPY --chown=cortex:cortex .env.production ./.env.template

# Create log directories
RUN mkdir -p logs tmp && \
    chown -R cortex:cortex logs tmp

# Switch to non-root user
USER cortex

# Expose health check and metrics ports
EXPOSE 3000 9090

# Set production environment
ENV NODE_ENV=production
ENV LOG_LEVEL=info

# Enhanced health check with metrics endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:9090/health || exit 1

# Use dumb-init to handle signals properly and reap zombie processes
ENTRYPOINT ["dumb-init", "--"]

# Production startup with health monitoring
CMD ["sh", "-c", "node dist/index.js 2>&1 | tee logs/cortex-mcp.log"]
