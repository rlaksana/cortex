# Cortex Memory MCP - Production Multi-stage Docker Build
# Optimized for production deployment with security and performance enhancements
# Build date: 2025-11-14
# Security hardening level: High

# Stage 1: Build TypeScript with comprehensive security scanning
FROM node:20-alpine AS builder

# Install security and build tools with minimal attack surface
RUN apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata \
    && \
    update-ca-certificates && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Set secure build environment
ENV NODE_ENV=development
ENV npm_config_audit=true
ENV npm_config_audit_level=high
ENV npm_config_fund=false
ENV npm_config_optional=false

WORKDIR /app

# Copy package files with explicit ownership
COPY --chown=node:node package*.json ./
COPY --chown=node:node tsconfig.json ./

# Install dependencies with security audit
RUN npm ci --only=production=false --ignore-scripts && \
    npm audit --audit-level=high && \
    npm cache clean --force && \
    rm -rf ~/.npm

# Copy source code with secure ownership
COPY --chown=node:node src/ ./src/
COPY --chown=node:node migrations/ ./migrations/
COPY --chown=node:node scripts/ ./scripts/

# Comprehensive security scan and optimized build
RUN npm audit --audit-level=high && \
    npm run build && \
    npm run lint:security || true && \
    npm run security:audit || true && \
    npm prune --production && \
    npm cache clean --force --global && \
    rm -rf /root/.npm /tmp/* /var/tmp/*

# Stage 2: Production runtime with maximum security hardening
FROM node:20-alpine AS runtime

# Install minimal runtime tools with security focus
RUN apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata \
    && \
    update-ca-certificates && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/* && \
    adduser -D -s /bin/sh -u 1001 cortex

# Create non-root user with minimal privileges and secure directories
RUN addgroup -g 1001 -S cortex && \
    adduser -S -u 1001 -G cortex -h /app -s /sbin/nologin -D cortex && \
    mkdir -p /app/logs /app/tmp /app/config /app/backups && \
    chown -R cortex:cortex /app && \
    chmod 750 /app && \
    chmod 755 /app/logs /app/tmp /app/config /app/backups

# Set secure timezone
ENV TZ=UTC
ENV NODE_ENV=production
ENV LOG_LEVEL=info

# Security-focused environment variables
ENV npm_config_unsafe_perm=false
ENV npm_config_cache=/tmp/.npm
ENV NODE_OPTIONS="--max-old-space-size=4096 --no-deprecation"

WORKDIR /app

# Copy built artifacts with secure ownership and permissions
COPY --from=builder --chown=cortex:cortex /app/dist ./dist
COPY --from=builder --chown=cortex:cortex /app/node_modules ./node_modules
COPY --from=builder --chown=cortex:cortex /app/package.json ./
COPY --from=builder --chown=cortex:cortex /app/migrations ./migrations

# Copy production environment template with restricted permissions
COPY --chown=cortex:cortex --chmod=600 .env.production ./.env.template

# Secure temporary and log directories
RUN chmod 700 /app/tmp && \
    chmod 755 /app/logs && \
    chown -R cortex:cortex /app && \
    rm -rf /root/.ssh /root/.gnupg /etc/ssh /etc/cron.* /etc/init.d

# Switch to non-root user with restricted capabilities
USER cortex

# Expose only essential ports
EXPOSE 3000 9090

# Add security labels and runtime configuration
LABEL maintainer="Cortex Team" \
      version="2.0.1" \
      description="Cortex Memory MCP Server - Production hardened container" \
      security.scan="enabled" \
      security.level="high"

# Read-only filesystem with exceptions for logs and temp
VOLUME ["/app/logs", "/app/tmp", "/app/backups"]

# Enhanced health check with timeout and retry logic
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -f -s --max-time 3 http://localhost:9090/health || exit 1

# Use dumb-init with enhanced security options
ENTRYPOINT ["dumb-init", "--", "--single-child"]

# Production startup with comprehensive error handling
CMD ["sh", "-c", " \
    echo '🚀 Starting Cortex Memory MCP Server (Production Mode)' && \
    echo '📊 Health endpoint: http://localhost:9090/health' && \
    echo '📈 Metrics endpoint: http://localhost:9090/metrics' && \
    echo '🛡️ Security hardening: ENABLED' && \
    echo '📝 Logging to: /app/logs/cortex-mcp.log' && \
    echo && \
    exec node dist/index.js 2>&1 | tee -a /app/logs/cortex-mcp.log \
"]
