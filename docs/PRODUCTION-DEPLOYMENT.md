# Production Deployment Guide

## Overview

This guide covers deploying the Cortex Memory MCP Server v2.0.1 in production environments with comprehensive security, monitoring, and operational excellence.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Configuration](#environment-configuration)
3. [Security Setup](#security-setup)
4. [Deployment Process](#deployment-process)
5. [Monitoring & Health Checks](#monitoring--health-checks)
6. [Operations & Maintenance](#operations--maintenance)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Node.js**: v20.x or higher
- **Memory**: Minimum 4GB RAM, 8GB+ recommended
- **Storage**: 10GB+ available disk space
- **Network**: HTTPS access to external services (OpenAI, Qdrant)

### External Dependencies

- **Qdrant Vector Database**: v1.7+ cluster
- **OpenAI API**: Valid API key with embedding access
- **Reverse Proxy**: Nginx, Traefik, or similar (recommended)

### Security Requirements

- **TLS/SSL**: HTTPS required for all production endpoints
- **API Keys**: Valid secrets for all external services
- **Network**: Firewall configuration for restricted access
- **Monitoring**: Logging and metrics infrastructure

## Environment Configuration

### 1. Production Environment File

Create `.env.production` with strict production settings:

```bash
# Copy the template
cp .env.example .env.production

# Edit with production values
nano .env.production
```

### 2. Critical Configuration Items

#### Required Secrets (MUST be configured):

```bash
# OpenAI API - MANDATORY
OPENAI_API_KEY=sk-proj-your-production-openai-api-key

# Security secrets - MANDATORY
JWT_SECRET=your_64_character_minimum_jwt_secret_here
ENCRYPTION_KEY=your_64_character_hex_encryption_key_here

# Optional: MCP API key for additional security
MCP_API_KEY=your_48_character_minimum_mcp_api_key
```

#### Database Configuration:

```bash
# Qdrant cluster
QDRANT_URL=https://your-production-qdrant-cluster.com
QDRANT_API_KEY=your-production-qdrant-api-key
QDRANT_COLLECTION_NAME=cortex-memory-production
```

#### Security Settings:

```bash
# CORS - Restrict to specific domains
CORS_ORIGIN=https://your-production-domain.com

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=1000
RATE_LIMIT_WINDOW_MS=900000

# Security headers
HELMET_ENABLED=true
```

### 3. Environment Validation

Validate your configuration before deployment:

```bash
npm run prod:validate
```

## Security Setup

### 1. TLS/SSL Configuration

#### Nginx Example:

```nginx
server {
    listen 443 ssl http2;
    server_name your-production-domain.com;

    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check endpoints
    location /health {
        proxy_pass http://localhost:3000/health;
        access_log off;
    }
}
```

### 2. Firewall Configuration

Restrict access to only necessary ports:

```bash
# Allow only HTTP/HTTPS and SSH
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### 3. API Security

Configure API key authentication:

```bash
# Require API key for MCP operations
REQUIRE_API_KEY=true

# Set up health endpoint authentication
HEALTH_ENDPOINT_AUTH_REQUIRED=true
HEALTH_ENDPOINT_ALLOWED_IPS=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

## Deployment Process

### 1. Preparation

```bash
# Clone repository
git clone https://github.com/cortex-ai/cortex-memory-mcp.git
cd cortex-memory-mcp

# Install dependencies
npm ci --production

# Build application
npm run build
```

### 2. Configuration Setup

```bash
# Validate production configuration
npm run prod:validate

# Perform health check
npm run prod:health
```

### 3. Start Production Server

```bash
# Start with full production configuration
npm run prod:start

# Or with custom options
NODE_ENV=production npm run start:prod
```

### 4. Systemd Service (Optional)

Create `/etc/systemd/system/cortex-mcp.service`:

```ini
[Unit]
Description=Cortex Memory MCP Server
After=network.target

[Service]
Type=simple
User=cortex
WorkingDirectory=/opt/cortex-mcp
Environment=NODE_ENV=production
EnvironmentFile=/opt/cortex-mcp/.env.production
ExecStart=/usr/bin/node scripts/start-production.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cortex-mcp
sudo systemctl start cortex-mcp
```

## Monitoring & Health Checks

### 1. Health Endpoints

The server provides several health check endpoints:

- **Main Health**: `/health` - Comprehensive health status
- **Liveness Probe**: `/health/live` - Container liveness check
- **Readiness Probe**: `/health/ready` - Container readiness check
- **Detailed Health**: `/health/detailed` - Detailed system information
- **Metrics**: `/metrics` - Performance and operational metrics

### 2. Health Check Examples

```bash
# Basic health check
curl https://your-domain.com/health

# Liveness probe (for Kubernetes)
curl https://your-domain.com/health/live

# Detailed system information
curl https://your-domain.com/health/detailed

# Metrics (JSON format)
curl https://your-domain.com/metrics
```

### 3. Monitoring Integration

#### Prometheus Configuration:

```yaml
scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
    scheme: 'https'
```

#### Grafana Dashboard:

Monitor the following metrics:
- System health status
- Request latency and throughput
- Memory and CPU usage
- Error rates
- Database connection health

### 4. Alerting

Set up alerts for:

- **Critical**: Service down, health check failures
- **Warning**: High memory usage, degraded performance
- **Info**: Configuration changes, deployments

## Operations & Maintenance

### 1. Log Management

Production logs are structured JSON format:

```bash
# View recent logs
npm run prod:logs

# View only errors and warnings
tail -f /app/logs/cortex-mcp.log | jq 'select(.level == "ERROR" or .level == "WARN")'
```

### 2. Performance Monitoring

```bash
# Check current status
npm run prod:status

# View metrics
npm run prod:metrics

# Monitor memory usage
watch -n 5 'ps aux | grep "node.*start-production"'
```

### 3. Backup and Recovery

```bash
# Create backup
npm run ops:backup

# Verify backup integrity
npm run ops:backup:verify

# Restore from backup
npm run ops:restore
```

### 4. Updates and Maintenance

```bash
# Quality checks before deployment
npm run quality:production

# Validate deployment
npm run deploy:validate

# Rolling restart (if using cluster)
npm run ops:restart
```

## Container Deployment

### 1. Docker Configuration

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --production && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S cortex && \
    adduser -S cortex -u 1001

USER cortex

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["npm", "run", "start:prod"]
```

### 2. Docker Compose

```yaml
version: '3.8'

services:
  cortex-mcp:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    depends_on:
      - qdrant

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
    volumes:
      - qdrant_data:/qdrant/storage
    restart: unless-stopped

volumes:
  qdrant_data:
```

### 3. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-mcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cortex-mcp
  template:
    metadata:
      labels:
        app: cortex-mcp
    spec:
      containers:
      - name: cortex-mcp
        image: cortex-mcp:2.0.1
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        envFrom:
        - secretRef:
            name: cortex-mcp-secrets
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "8Gi"
            cpu: "2000m"
```

## Troubleshooting

### Common Issues

#### 1. Server Won't Start

```bash
# Check configuration
npm run prod:validate

# Check environment variables
env | grep -E "(OPENAI_API_KEY|QDRANT_URL|NODE_ENV)"

# View startup logs
journalctl -u cortex-mcp -f
```

#### 2. Health Check Failures

```bash
# Check detailed health status
curl https://your-domain.com/health/detailed | jq .

# Check Qdrant connection
curl -H "api-key: $QDRANT_API_KEY" https://your-qdrant-cluster.com/health

# Check OpenAI API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

#### 3. Performance Issues

```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Check CPU usage
top -p $(pgrep -f "start-production")

# Check network connectivity
ping your-qdrant-cluster.com
curl -I https://api.openai.com
```

#### 4. Database Issues

```bash
# Check Qdrant cluster status
curl -H "api-key: $QDRANT_API_KEY" https://your-qdrant-cluster.com/collections

# Verify collection exists
curl -H "api-key: $QDRANT_API_KEY" \
  https://your-qdrant-cluster.com/collections/cortex-memory-production
```

### Debug Mode

For troubleshooting, you can temporarily enable debug mode:

```bash
# Enable debug logging
export ENABLE_DEBUG_MODE=true
export LOG_LEVEL=debug

# Start with debug output
npm run mcp:debug
```

### Getting Help

1. **Check Logs**: Always check application logs first
2. **Validate Configuration**: Use `npm run prod:validate`
3. **Health Checks**: Use `/health/detailed` endpoint
4. **Documentation**: Check the main documentation
5. **Issues**: File GitHub issues with full logs and configuration

## Security Best Practices

1. **Regular Updates**: Keep Node.js and dependencies updated
2. **Secret Rotation**: Rotate API keys and secrets regularly
3. **Access Control**: Implement proper network segmentation
4. **Monitoring**: Set up comprehensive logging and alerting
5. **Backups**: Regular automated backups of configuration and data
6. **Audit Trails**: Enable audit logging for all operations
7. **Penetration Testing**: Regular security assessments

## Performance Optimization

1. **Memory Management**: Monitor and tune Node.js memory settings
2. **Connection Pooling**: Optimize database connection pools
3. **Caching**: Enable appropriate caching strategies
4. **Load Balancing**: Use multiple instances behind a load balancer
5. **CDN**: Use CDN for static content if applicable
6. **Monitoring**: Continuous performance monitoring and optimization

## Compliance

1. **Data Protection**: Ensure compliance with GDPR/CCPA if applicable
2. **Audit Logging**: Maintain comprehensive audit trails
3. **Data Retention**: Implement appropriate data retention policies
4. **Access Controls**: Maintain proper access control documentation
5. **Incident Response**: Have security incident response procedures

---

For additional support or questions, refer to the main documentation or create an issue in the repository.