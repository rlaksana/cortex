# Production AI Services Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying MCP-Cortex AI services in production environments with full monitoring, observability, and operational readiness.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Configuration](#environment-configuration)
3. [Deployment Architecture](#deployment-architecture)
4. [Step-by-Step Deployment](#step-by-step-deployment)
5. [Monitoring Setup](#monitoring-setup)
6. [Security Configuration](#security-configuration)
7. [Performance Tuning](#performance-tuning)
8. [Testing and Validation](#testing-and-validation)
9. [Troubleshooting](#troubleshooting)
10. [Maintenance and Operations](#maintenance-and-operations)

## Prerequisites

### System Requirements

**Minimum Requirements:**

- CPU: 4 cores
- Memory: 8GB RAM
- Storage: 50GB SSD
- Network: 1Gbps

**Recommended Production Requirements:**

- CPU: 8+ cores
- Memory: 16GB+ RAM
- Storage: 100GB+ SSD
- Network: 10Gbps
- High Availability: Multi-zone deployment

### Software Dependencies

- Node.js 24.x or later
- Docker 20.x or later (for containerized deployment)
- Kubernetes 1.28+ (for orchestration)
- Qdrant vector database 1.7+
- Redis 7.x (for caching)

### External Services

- Z.AI API access with valid API key
- Monitoring system (Prometheus/Grafana recommended)
- Log aggregation (ELK stack or similar)
- Alert management (PagerDuty, Slack, etc.)

## Environment Configuration

### Environment Variables

```bash
# Core Configuration
NODE_ENV=production
PORT=3000

# Z.AI Services Configuration
ZAI_URL=https://api.z.ai/api/anthropic
ZAI_API_KEY=your_api_key_here
ZAI_MODEL=glm-4.6

# Database Configuration
QDRANT_URL=http://qdrant:6333
QDRANT_API_KEY=your_qdrant_key
QDRANT_COLLECTION_NAME=cortex_memory

# AI Service Configuration
AI_ENABLED=true
AI_INSIGHTS_ENABLED=true
AI_CONTRADICTION_DETECTION_ENABLED=true
AI_SEMANTIC_SEARCH_ENABLED=true
AI_BACKGROUND_PROCESSING_ENABLED=true

# Monitoring and Observability
MONITORING_ENABLED=true
METRICS_COLLECTION_INTERVAL=30000
HEALTH_CHECK_INTERVAL=60000
ALERTING_ENABLED=true

# Security
ENABLE_ENCRYPTION=true
ENABLE_AUDIT_LOGGING=true
IP_WHITELIST=10.0.0.0/8,192.168.0.0/16

# Performance
MAX_MEMORY_USAGE_MB=2048
MAX_CPU_USAGE_PERCENT=80
MAX_CONCURRENT_REQUESTS=100
CACHING_ENABLED=true

# Cost Control
DAILY_AI_BUDGET=1000
MONTHLY_AI_BUDGET=20000
COST_TRACKING_ENABLED=true
```

### Configuration Files

#### AI Service Configuration (config/production-zai-config.ts)

The production configuration is automatically loaded based on the `NODE_ENV` environment variable. Ensure the configuration matches your environment:

```typescript
// Example production overrides
const productionOverrides = {
  ai: {
    enabled: true,
    features: {
      insights: {
        enabled: true,
        strategies: [
          'pattern_recognition',
          'knowledge_gap',
          'anomaly_detection',
          'predictive_insight',
        ],
      },
      contradiction_detection: {
        enabled: true,
        confidence_threshold: 0.85,
        strategies: [
          'factual_verification',
          'logical_contradiction',
          'semantic_contradiction',
          'temporal_contradiction',
        ],
      },
    },
  },
  performance: {
    latency_targets: {
      insight_generation: 5000,
      contradiction_detection: 4000,
      semantic_search: 1000,
    },
    resource_limits: {
      max_memory_usage_mb: 2048,
      max_cpu_usage_percent: 80,
      max_concurrent_requests: 100,
    },
  },
};
```

## Deployment Architecture

### High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │────│  MCP Cortex AI   │────│  Vector Database│
│    (HAProxy)    │    │     Services     │    │    (Qdrant)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌────────┴────────┐              │
         │              │                 │              │
         │       ┌──────▼──────┐   ┌──────▼──────┐    │
         │       │ AI Services │   │ Monitoring  │    │
         │       │   Core      │   │ & Alerting  │    │
         │       └─────────────┘   └─────────────┘    │
         │                                           │
         │                                   ┌──────▼──────┐
         └───────────────────────────────────│ Z.AI API    │
                                               │ (External)  │
                                               └─────────────┘
```

### Container Architecture

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  mcp-cortex-ai:
    image: cortex/mcp-cortex-ai:latest
    restart: unless-stopped
    ports:
      - '3000:3000'
    environment:
      - NODE_ENV=production
      - ZAI_API_KEY=${ZAI_API_KEY}
      - QDRANT_URL=http://qdrant:6333
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    depends_on:
      - qdrant
      - redis
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:3000/health']
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'

  qdrant:
    image: qdrant/qdrant:latest
    restart: unless-stopped
    ports:
      - '6333:6333'
    volumes:
      - qdrant_data:/qdrant/storage
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__GRPC_PORT=6334
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  prometheus:
    image: prom/prometheus:latest
    restart: unless-stopped
    ports:
      - '9090:9090'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:latest
    restart: unless-stopped
    ports:
      - '3001:3000'
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards

volumes:
  qdrant_data:
  redis_data:
  prometheus_data:
  grafana_data:
```

## Step-by-Step Deployment

### 1. Preparation Phase

```bash
# Clone repository
git clone https://github.com/your-org/mcp-cortex.git
cd mcp-cortex

# Install dependencies
npm install --production

# Build application
npm run build

# Validate configuration
node -e "const config = require('./config/production-zai-config.js').productionZAIConfigManager; console.log(config.validateConfig())"
```

### 2. Database Setup

```bash
# Deploy Qdrant
docker-compose up -d qdrant

# Wait for Qdrant to be ready
curl -f http://localhost:6333/health

# Initialize collections
npm run db:init
npm run db:migrate
```

### 3. Application Deployment

#### Docker Deployment

```bash
# Build Docker image
docker build -t cortex/mcp-cortex-ai:latest .

# Deploy with Docker Compose
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
docker-compose ps
docker-compose logs -f mcp-cortex-ai
```

#### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-cortex-ai
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-cortex-ai
  template:
    metadata:
      labels:
        app: mcp-cortex-ai
    spec:
      containers:
        - name: mcp-cortex-ai
          image: cortex/mcp-cortex-ai:latest
          ports:
            - containerPort: 3000
          env:
            - name: NODE_ENV
              value: 'production'
            - name: ZAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: ai-secrets
                  key: zai-api-key
            - name: QDRANT_URL
              value: 'http://qdrant-service:6333'
          resources:
            requests:
              memory: '1Gi'
              cpu: '500m'
            limits:
              memory: '2Gi'
              cpu: '1000m'
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-cortex-ai-service
  namespace: production
spec:
  selector:
    app: mcp-cortex-ai
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: ClusterIP
```

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/
kubectl get pods -n production
kubectl logs -f deployment/mcp-cortex-ai -n production
```

### 4. Monitoring Setup

#### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'mcp-cortex-ai'
    static_configs:
      - targets: ['mcp-cortex-ai:3000']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'qdrant'
    static_configs:
      - targets: ['qdrant:6333']
    metrics_path: /metrics
```

#### Grafana Dashboards

Import the pre-configured dashboards:

- AI Services Overview
- Performance Metrics
- Health Monitoring
- Cost Analysis

### 5. Load Balancer Configuration

```nginx
# nginx.conf
upstream mcp_cortex_ai {
    least_conn;
    server mcp-cortex-ai-1:3000 max_fails=3 fail_timeout=30s;
    server mcp-cortex-ai-2:3000 max_fails=3 fail_timeout=30s;
    server mcp-cortex-ai-3:3000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name ai.cortex.example.com;

    location / {
        proxy_pass http://mcp_cortex_ai;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for AI operations
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /health {
        proxy_pass http://mcp_cortex_ai/health;
        access_log off;
    }
}
```

## Monitoring Setup

### Key Metrics to Monitor

**AI Service Metrics:**

- Request rate and latency
- Error rates and success rates
- AI operation performance (insight generation, contradiction detection)
- Resource utilization (CPU, memory, network)
- Cost tracking and budget compliance

**Health Monitoring:**

- Service availability and uptime
- Circuit breaker status
- Dependency health (Z.AI API, Qdrant, Redis)
- Background queue health

**Quality Metrics:**

- Insight accuracy scores
- Contradiction detection effectiveness
- User satisfaction ratings
- Model performance drift

### Alert Configuration

```yaml
# alerts/ai-services.yml
groups:
  - name: ai-services
    rules:
      - alert: AIServiceDown
        expr: up{job="mcp-cortex-ai"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: 'AI service is down'
          description: 'AI service has been down for more than 1 minute'

      - alert: HighAILatency
        expr: histogram_quantile(0.95, rate(ai_operation_duration_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'High AI operation latency'
          description: '95th percentile latency is above 5 seconds'

      - alert: AIErrorRate
        expr: rate(ai_operation_errors_total[5m]) / rate(ai_operation_total[5m]) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: 'High AI error rate'
          description: 'AI error rate is above 5%'

      - alert: AIBudgetExceeded
        expr: ai_daily_cost > ai_daily_budget
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: 'AI budget exceeded'
          description: 'Daily AI cost has exceeded the budget'
```

## Security Configuration

### API Security

```typescript
// security/middleware.ts
export const aiSecurityMiddleware = [
  // Rate limiting
  rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 1000, // 1000 requests per minute
    message: 'Too many requests from this IP',
  }),

  // API key validation
  (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !isValidAPIKey(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  },

  // IP whitelisting
  (req, res, next) => {
    const clientIP = req.ip;
    if (!isIPWhitelisted(clientIP)) {
      return res.status(403).json({ error: 'IP not whitelisted' });
    }
    next();
  },
];
```

### Data Encryption

```typescript
// Enable encryption in production
const securityConfig = {
  encryption: {
    at_rest: {
      enabled: true,
      algorithm: 'aes-256-gcm',
      key_rotation_interval: 86400000, // 24 hours
    },
    in_transit: {
      enabled: true,
      tls_version: '1.3',
      cipher_suites: ['TLS_AES_256_GCM_SHA384'],
    },
  },
};
```

## Performance Tuning

### Resource Optimization

```typescript
// Production performance settings
const performanceConfig = {
  // Connection pooling
  database: {
    max_connections: 20,
    connection_timeout: 30000,
    idle_timeout: 300000,
  },

  // Caching strategy
  cache: {
    strategy: 'lru',
    max_size: 500, // MB
    ttl: 1800, // 30 minutes
    background_refresh: true,
  },

  // Batch processing
  batch_processing: {
    enabled: true,
    batch_size: 50,
    flush_interval: 10000, // 10 seconds
    max_wait_time: 30000, // 30 seconds
  },

  // Circuit breaker settings
  circuit_breaker: {
    threshold: 5,
    reset_timeout: 60000,
    monitoring_window: 120000,
  },
};
```

### AI Model Optimization

```typescript
// Model selection based on cost/performance trade-offs
const modelOptimization = {
  insight_generation: {
    primary_model: 'glm-4.6',
    fallback_models: ['gpt-3.5-turbo'],
    cost_threshold: 0.01,
    latency_threshold: 5000,
  },

  contradiction_detection: {
    primary_model: 'glm-4.6',
    fallback_models: ['claude-instant'],
    cost_threshold: 0.008,
    latency_threshold: 4000,
  },

  semantic_search: {
    embedding_model: 'text-embedding-3-large',
    dimension: 3072,
    batch_size: 100,
  },
};
```

## Testing and Validation

### Pre-deployment Testing

```bash
# Health check tests
npm run test:health

# Load testing
npm run test:load

# Integration tests
npm run test:integration

# AI functionality tests
npm run test:ai-functionality
```

### Smoke Tests

```bash
#!/bin/bash
# scripts/smoke-test.sh

echo "Running smoke tests..."

# Test basic health
curl -f http://localhost:3000/health || exit 1

# Test AI services status
curl -f http://localhost:3000/health/ai || exit 1

# Test basic AI operation
curl -X POST http://localhost:3000/api/ai/status \
  -H "Content-Type: application/json" \
  -d '{"include_metrics": true}' || exit 1

echo "Smoke tests passed!"
```

### Load Testing

```javascript
// tests/load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 10 },
    { duration: '5m', target: 50 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  let response = http.post(
    'http://localhost:3000/api/ai/status',
    JSON.stringify({ include_metrics: true }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );

  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 5s': (r) => r.timings.duration < 5000,
  });

  sleep(1);
}
```

## Troubleshooting

### Common Issues

#### 1. AI Services Not Starting

**Symptoms:**

- Health checks failing
- AI services showing as disabled

**Solutions:**

```bash
# Check configuration
node -e "console.log(require('./config/production-zai-config.js').productionZAIConfigManager.validateConfig())"

# Check Z.AI API connectivity
curl -H "Authorization: Bearer $ZAI_API_KEY" \
  https://api.z.ai/api/anthropic/health

# Check logs
docker-compose logs mcp-cortex-ai
```

#### 2. High Latency

**Symptoms:**

- AI operations taking >10 seconds
- Users experiencing delays

**Solutions:**

```bash
# Check resource utilization
docker stats mcp-cortex-ai

# Check circuit breaker status
curl http://localhost:3000/api/ai/status?include_health=true

# Optimize configuration
export AI_BATCH_SIZE=25
export AI_MAX_CONCURRENT_REQUESTS=50
```

#### 3. Memory Issues

**Symptoms:**

- Out of memory errors
- Container restarts

**Solutions:**

```bash
# Increase memory limits
docker-compose up -d --scale mcp-cortex-ai=2

# Enable garbage collection
export NODE_OPTIONS="--max-old-space-size=4096"

# Monitor memory usage
curl http://localhost:3000/metrics | grep memory
```

### Debug Commands

```bash
# Comprehensive health check
curl -s http://localhost:3000/api/ai/status \
  -H "Content-Type: application/json" \
  -d '{"include_metrics": true, "include_health": true, "include_observability": true}' | jq .

# Check specific service health
curl -s http://localhost:3000/health/ai | jq .

# Monitor real-time metrics
watch -n 5 'curl -s http://localhost:3000/metrics | grep ai_'

# Check background job queue
curl -s http://localhost:3000/api/ai/background/status | jq .
```

## Maintenance and Operations

### Regular Maintenance Tasks

**Daily:**

- Monitor AI service health and performance
- Check cost tracking against budgets
- Review error logs and alerts

**Weekly:**

- Analyze performance trends
- Update AI model configurations if needed
- Review and optimize costs

**Monthly:**

- Comprehensive performance review
- Update dependencies and patches
- Backup configurations and data

### Backup Strategy

```bash
#!/bin/bash
# scripts/backup.sh

# Backup configurations
cp -r config/ backups/config-$(date +%Y%m%d)/

# Backup Qdrant data
docker exec qdrant tar -czf /tmp/qdrant-backup.tar.gz /qdrant/storage
docker cp qdrant:/tmp/qdrant-backup.tar.gz backups/qdrant-$(date +%Y%m%d).tar.gz

# Backup metrics data
curl http://localhost:9090/api/v1/admin/tsdb/snapshot | jq .
```

### Update Process

```bash
# Zero-downtime deployment
#!/bin/bash

# Build new version
docker build -t cortex/mcp-cortex-ai:v2.0.1 .

# Update one instance at a time
docker-compose up -d --no-deps mcp-cortex-ai
docker-compose scale mcp-cortex-ai=2

# Wait for health checks
sleep 30

# Update remaining instances
docker-compose scale mcp-cortex-ai=3

# Verify deployment
curl -f http://localhost:3000/health
```

## Monitoring and Alerting Contacts

### Escalation Policy

**Level 1 (5 minutes):** Development team
**Level 2 (15 minutes):** Operations team
**Level 3 (30 minutes):** Management

### Contact Information

- **Development Team:** dev-team@example.com
- **Operations Team:** ops-team@example.com
- **On-call Engineer:** +1-555-0123
- **Emergency Slack:** #ai-services-emergency

## Compliance and Auditing

### Data Privacy

- All data encrypted at rest and in transit
- User data anonymization enabled
- GDPR compliance features active
- Data retention policies enforced

### Audit Logging

```typescript
// Enable comprehensive audit logging
const auditConfig = {
  enabled: true,
  log_all_ai_operations: true,
  include_user_context: true,
  retention_days: 2555, // 7 years
  export_format: 'json',
};
```

### Compliance Reports

Generate regular compliance reports:

```bash
# Generate monthly compliance report
npm run report:compliance -- --month=$(date +%Y-%m)

# Generate security audit report
npm run audit:security
```

This comprehensive production deployment guide ensures that MCP-Cortex AI services are deployed with high availability, robust monitoring, and operational excellence. Regular review and updates of this guide are recommended to maintain alignment with evolving best practices and requirements.
