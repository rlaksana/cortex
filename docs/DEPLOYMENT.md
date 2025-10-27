# Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Cortex Memory MCP Server in various environments, including development, staging, and production. It covers Docker deployment, Kubernetes orchestration, cloud platform setup, and monitoring configurations.

## Deployment Architectures

### 1. Development Environment

```
Development Machine
├── Docker Desktop
│   ├── Qdrant (port 6333)
│   └── Cortex MCP (port 3000)
└── Local Development Tools
```

### 2. Production Environment

```
Production Cluster
├── Load Balancer (HTTPS termination)
├── Cortex MCP Services (3+ instances)
│   └── Qdrant Cluster (3+ nodes)
├── Monitoring Stack
│   ├── Prometheus
│   ├── Grafana
│   └── AlertManager
└── Logging Stack
    ├── ELK Stack
    └── Filebeat
```

⚠️ **IMPORTANT**: This system uses **QDRANT ONLY**. Do NOT install, configure, or connect to PostgreSQL.

## Docker Deployment

### 1. Quick Start with Docker Compose

#### Development Environment

```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  cortex-mcp:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
      - "9229:9229"  # Node.js debugger
    environment:
      - NODE_ENV=development
      - QDRANT_URL=http://qdrant:6333
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - DEBUG=cortex:*
      - HOT_RELOAD=true
      - # NO DATABASE_URL NEEDED - QDRANT ONLY!
    volumes:
      - .:/app
      - /app/node_modules
      - ./logs:/app/logs
    depends_on:
      qdrant:
        condition: service_healthy
    restart: unless-stopped
    command: npm run dev

  qdrant:
    image: qdrant/qdrant:v1.7.0
    ports:
      - "6333:6333"  # HTTP API
      - "6334:6334"  # gRPC API
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__GRPC_PORT=6334
      - QDRANT__LOG_LEVEL=DEBUG
    volumes:
      - qdrant_dev_data:/qdrant/storage
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:6333/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

volumes:
  qdrant_dev_data:
```

⚠️ **NOTICE**: No PostgreSQL container is needed. Cortex uses Qdrant only for all storage operations.

#### Production Environment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  cortex-mcp:
    image: your-registry/cortex-memory-mcp:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
    environment:
      - NODE_ENV=production
      - QDRANT_URL=http://qdrant:6333
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ENABLE_CACHE=true
      - ENABLE_METRICS=true
      - LOG_LEVEL=warn
      - API_KEY_ENABLED=true
      - # NO DATABASE_URL - QDRANT ONLY!
    ports:
      - "3000:3000"
    depends_on:
      qdrant:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped

  qdrant:
    image: qdrant/qdrant:v1.7.0
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__GRPC_PORT=6334
      - QDRANT__SERVICE__MAX_REQUEST_SIZE_MB=32
      - QDRANT__STORAGE__PERFORMANCE__MAX_SEARCH_THREADS=4
      - QDRANT__STORAGE__PERFORMANCE__UPDATE_THREADS=2
    volumes:
      - qdrant_prod_data:/qdrant/storage
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:6333/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - cortex-mcp
    restart: unless-stopped

volumes:
  qdrant_prod_data:
```

⚠️ **IMPORTANT**: Production deployment requires only Qdrant. No PostgreSQL database is needed or supported.

### 2. Dockerfile Configuration

#### Production Dockerfile

```dockerfile
# Dockerfile
FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json* ./
RUN npm ci --only=production && npm cache clean --force

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the application
RUN npm run build

# Production image, copy all the files and run the app
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

# Create a non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nodejs

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json

# Create logs directory
RUN mkdir -p /app/logs && chown nodejs:nodejs /app/logs

USER nodejs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/health-check.js

CMD ["node", "dist/index.js"]
```

#### Development Dockerfile

```dockerfile
# Dockerfile.dev
FROM node:20-alpine

WORKDIR /app

# Install development dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 3000 9229

# Run in development mode with hot reload
CMD ["npm", "run", "dev"]
```

## Kubernetes Deployment

### 1. Namespace and Configuration

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cortex-mcp
  labels:
    name: cortex-mcp

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cortex-config
  namespace: cortex-mcp
data:
  NODE_ENV: "production"
  LOG_LEVEL: "warn"
  DB_POOL_SIZE: "20"
  ENABLE_CACHE: "true"
  ENABLE_METRICS: "true"
  SEARCH_LIMIT: "50"
  SIMILARITY_THRESHOLD: "0.7"
  API_KEY_ENABLED: "true"
  RATE_LIMIT_ENABLED: "true"

---
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cortex-secrets
  namespace: cortex-mcp
type: Opaque
data:
  OPENAI_API_KEY: <base64-encoded-openai-key>
  QDRANT_API_KEY: <base64-encoded-qdrant-key>
  API_KEY: <base64-encoded-api-key>
  # NO DATABASE_URL - QDRANT ONLY
```

### 2. Application Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-mcp
  namespace: cortex-mcp
  labels:
    app: cortex-mcp
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
        image: your-registry/cortex-memory-mcp:latest
        ports:
        - containerPort: 3000
          name: http
        - containerPort: 9090
          name: metrics
        envFrom:
        - configMapRef:
            name: cortex-config
        - secretRef:
            name: cortex-secrets
        resources:
          requests:
            cpu: 1000m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 2Gi
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /startup
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
        securityContext:
          runAsNonRoot: true
          runAsUser: 1001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
      securityContext:
        fsGroup: 1001
```

### 3. Service and Ingress

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cortex-mcp-service
  namespace: cortex-mcp
  labels:
    app: cortex-mcp
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 3000
    protocol: TCP
    name: http
  - port: 9090
    targetPort: 9090
    protocol: TCP
    name: metrics
  selector:
    app: cortex-mcp

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cortex-mcp-ingress
  namespace: cortex-mcp
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - api.cortex-memory.com
    secretName: cortex-mcp-tls
  rules:
  - host: api.cortex-memory.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cortex-mcp-service
            port:
              number: 80
```

### 4. Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: cortex-mcp-hpa
  namespace: cortex-mcp
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: cortex-mcp
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 2
        periodSeconds: 60
      selectPolicy: Max
```

## Cloud Platform Deployment

### 1. AWS Deployment

#### ECS Task Definition

```json
{
  "family": "cortex-mcp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "cortex-mcp",
      "image": "your-account.dkr.ecr.region.amazonaws.com/cortex-mcp:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:cortex/openai-key"
        }
      ],
      # NO DATABASE_URL SECRET - QDRANT ONLY
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cortex-mcp",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

#### Terraform Configuration

```hcl
# terraform/main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC Configuration
resource "aws_vpc" "cortex_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cortex-vpc"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "cortex_cluster" {
  name = "cortex-mcp"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# NO RDS/POSTGRESQL RESOURCES NEEDED - QDRANT ONLY

# ElastiCache for Redis
resource "aws_elasticache_subnet_group" "cortex_cache" {
  name       = "cortex-cache-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_cluster" "cortex_redis" {
  cluster_id           = "cortex-redis"
  engine               = "redis"
  node_type            = "cache.m5.large"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.cortex_cache.name
  security_group_ids   = [aws_security_group.redis.id]

  tags = {
    Name = "cortex-redis"
  }
}

# Application Load Balancer
resource "aws_lb" "cortex_alb" {
  name               = "cortex-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name = "cortex-alb"
  }
}
```

### 2. Google Cloud Platform Deployment

#### Cloud Run Service

```yaml
# gcp/cloud-run.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: cortex-mcp
  namespace: cortex
  annotations:
    run.googleapis.com/ingress: all
    run.googleapis.com/execution-environment: gen2
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/memory: "2Gi"
        run.googleapis.com/cpu: "1000m"
        autoscaling.knative.dev/maxScale: "10"
        autoscaling.knative.dev/minScale: "3"
    spec:
      containerConcurrency: 100
      timeoutSeconds: 300
      containers:
      - image: gcr.io/project-id/cortex-mcp:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: cortex-secrets
              key: OPENAI_API_KEY
        # NO DATABASE_URL ENVIRONMENT VARIABLE - QDRANT ONLY
        resources:
          limits:
            cpu: 2000m
            memory: 2Gi
          requests:
            cpu: 1000m
            memory: 1Gi
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
```

## Monitoring and Observability

### 1. Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "cortex-rules.yml"

scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['cortex-mcp-service:9090']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'qdrant'
    static_configs:
      - targets: ['qdrant:6333']
    metrics_path: /metrics

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Cortex MCP Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "pg_stat_activity_count",
            "legendFormat": "Active Connections"
          }
        ]
      },
      {
        "title": "Search Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(search_requests_total[5m])",
            "legendFormat": "Search Rate"
          }
        ]
      }
    ]
  }
}
```

### 3. Alerting Rules

```yaml
# monitoring/cortex-rules.yml
groups:
- name: cortex-mcp.rules
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"

  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"
      description: "95th percentile response time is {{ $value }}s"

  - alert: DatabaseConnectionHigh
    expr: pg_stat_activity_count > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High database connection count"
      description: "Database has {{ $value }} active connections"

  - alert: PodCrashLooping
    expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Pod is crash looping"
      description: "Pod {{ $labels.pod }} is restarting frequently"
```

## Deployment Scripts

### 1. Automated Deployment Script

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

# Configuration
ENVIRONMENT=${1:-production}
VERSION=${2:-latest}
REGISTRY="your-registry.com"
IMAGE_NAME="cortex-memory-mcp"

echo "🚀 Deploying Cortex MCP to $ENVIRONMENT environment..."

# Build and push Docker image
echo "📦 Building Docker image..."
docker build -t $REGISTRY/$IMAGE_NAME:$VERSION .
docker push $REGISTRY/$IMAGE_NAME:$VERSION

# Deploy based on environment
case $ENVIRONMENT in
  "development")
    echo "🔧 Deploying to development..."
    docker-compose -f docker-compose.dev.yml up -d
    ;;
  "staging")
    echo "🧪 Deploying to staging..."
    docker-compose -f docker-compose.staging.yml up -d
    ;;
  "production")
    echo "🌟 Deploying to production..."
    # Kubernetes deployment
    kubectl apply -f k8s/
    kubectl set image deployment/cortex-mcp cortex-mcp=$REGISTRY/$IMAGE_NAME:$VERSION -n cortex-mcp
    kubectl rollout status deployment/cortex-mcp -n cortex-mcp
    ;;
  *)
    echo "❌ Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

echo "✅ Deployment completed successfully!"

# Health check
echo "🔍 Performing health check..."
sleep 30

case $ENVIRONMENT in
  "development"|"staging")
    curl -f http://localhost:3000/health || exit 1
    ;;
  "production")
    kubectl get pods -n cortex-mcp
    kubectl exec -n cortex-mcp deployment/cortex-mcp -- curl -f http://localhost:3000/health || exit 1
    ;;
esac

echo "🎉 Deployment is healthy and ready!"
```

### 2. Database Migration Script

```bash
#!/bin/bash
# scripts/migrate.sh

set -e

ENVIRONMENT=${1:-production}
echo "🗄️ Preparing Qdrant deployment for $ENVIRONMENT..."

# Set environment variables
export NODE_ENV=$ENVIRONMENT
# NO DATABASE_URL - QDRANT ONLY

# No database migrations needed for Qdrant
echo "✅ No migrations required for Qdrant-only deployment"

echo "✅ Qdrant deployment preparation completed!"
```

## Backup and Recovery

### 1. Qdrant Backup Script

```bash
#!/bin/bash
# scripts/backup-qdrant.sh

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="cortex_qdrant_backup_$DATE"

# Create backup directory
mkdir -p $BACKUP_DIR

# Qdrant snapshot backup
curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots" \
  -H "Content-Type: application/json" \
  -d '{"name": "'$BACKUP_FILE'"}'

# Wait for snapshot creation
sleep 10

# Find and copy the snapshot
SNAPSHOT_PATH="/qdrant/snapshots/cortex-memory/$BACKUP_FILE.snapshot"
cp $SNAPSHOT_PATH "$BACKUP_DIR/"

# Compress backup
gzip "$BACKUP_DIR/$BACKUP_FILE.snapshot"

# Upload to S3 (AWS)
aws s3 cp "$BACKUP_DIR/$BACKUP_FILE.snapshot.gz" "s3://cortex-backups/qdrant/"

# Clean local files older than 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "✅ Qdrant backup completed: $BACKUP_FILE.snapshot.gz"
```

### 2. Qdrant Restore Script

```bash
#!/bin/bash
# scripts/restore-qdrant.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup_file>"
  exit 1
fi

echo "🔄 Restoring Qdrant from $BACKUP_FILE..."

# Download from S3 if needed
if [[ $BACKUP_FILE == s3://* ]]; then
  aws s3 cp $BACKUP_FILE /tmp/restore.snapshot.gz
  BACKUP_FILE="/tmp/restore.snapshot.gz"
fi

# Decompress if needed
if [[ $BACKUP_FILE == *.gz ]]; then
  gunzip -c $BACKUP_FILE > /tmp/restore.snapshot
  BACKUP_FILE="/tmp/restore.snapshot"
fi

# Copy to Qdrant snapshots directory
cp $BACKUP_FILE "/qdrant/snapshots/cortex-memory/"

# Restore from snapshot
curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots/restore" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_name": "'$(basename $BACKUP_FILE)'"}'

echo "✅ Qdrant restore completed!"
```

⚠️ **IMPORTANT**: This system uses Qdrant-only backups. No SQL backup/restore is needed or supported.

## Security Considerations

### 1. Network Security

```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cortex-mcp-network-policy
  namespace: cortex-mcp
spec:
  podSelector:
    matchLabels:
      app: cortex-mcp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 3000
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: cortex-mcp
    ports:
    - protocol: TCP
      port: 6333  # Qdrant
    # NO POSTGRESQL - QDRANT ONLY
  - to: []
    ports:
    - protocol: TCP
      port: 443   # HTTPS for external APIs
    - protocol: TCP
      port: 53    # DNS
```

### 2. Pod Security Policy

```yaml
# k8s/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: cortex-mcp-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

This comprehensive deployment guide provides all the necessary configurations and best practices for deploying the Cortex Memory MCP Server in production environments with proper monitoring, security, and scalability considerations.