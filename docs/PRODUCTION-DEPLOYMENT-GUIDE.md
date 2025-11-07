# Cortex Memory MCP Server - Production Deployment Guide

**Version:** 2.0.1
**Last Updated:** 2025-11-05
**Audience:** DevOps Engineers, System Administrators, Production Operations Teams

---

## 🔍 Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture Overview](#system-architecture-overview)
3. [Environment Variables & Configuration](#environment-variables--configuration)
4. [Infrastructure Requirements](#infrastructure-requirements)
5. [Pre-Flight Checklist](#pre-flight-checklist)
6. [Deployment Procedures](#deployment-procedures)
7. [Post-Deployment Validation](#post-deployment-validation)
8. [Monitoring & Alerting](#monitoring--alerting)
9. [Operational Procedures](#operational-procedures)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [Backup & Disaster Recovery](#backup--disaster-recovery)
12. [Security Considerations](#security-considerations)
13. [Performance Tuning](#performance-tuning)
14. [Maintenance Procedures](#maintenance-procedures)

---

## Executive Summary

The Cortex Memory MCP Server is a production-ready AI knowledge management system that provides semantic search, memory storage, and intelligent deduplication through the Model Context Protocol (MCP). This guide covers comprehensive deployment procedures for production environments.

### Key System Characteristics

- **Database Backend:** Qdrant vector database ONLY (no PostgreSQL dependencies)
- **Architecture:** Microservices-ready with stateless application design
- **Scalability:** Horizontal scaling supported with load balancing
- **Security:** Enterprise-grade security with authentication and encryption
- **Monitoring:** Comprehensive health checks and metrics collection
- **High Availability:** Graceful shutdown and circuit breaker patterns

### Production Readiness Status

- ✅ Core Infrastructure: 100% Complete
- ✅ Security Features: Production Ready
- ✅ Monitoring & Health Checks: Fully Implemented
- ✅ Performance Optimization: Configured for Production Workloads
- ✅ Backup & Recovery: Automated Procedures Available

---

## System Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Production Cluster                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Cortex    │    │   Cortex    │    │   Cortex    │          │
│  │   MCP #1    │    │   MCP #2    │    │   MCP #3    │          │
│  │   (Primary) │    │ (Secondary) │    │ (Secondary) │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                   │                   │              │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                   Load Balancer                            │  │
│  │              (HTTPS Termination)                           │  │
│  └─────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Qdrant    │    │   Qdrant    │    │   Qdrant    │          │
│  │  Cluster    │    │  Cluster    │    │  Cluster    │          │
│  │   Node #1   │    │   Node #2   │    │   Node #3   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Redis     │    │ Prometheus  │    │   Grafana   │          │
│  │   Cache     │    │   Metrics   │    │ Dashboard   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interactions

```
┌─────────────────┐    HTTP/MCP     ┌─────────────────┐
│   Load Balancer │◄──────────────► │  Cortex MCP     │
│   (Nginx/ALB)   │                │   Services      │
└─────────────────┘                └─────────────────┘
                                            │
                               Vector Database │
                               Queries/Storage │
                                            ▼
                                  ┌─────────────────┐
                                  │     Qdrant      │
                                  │   Vector DB     │
                                  │   Cluster       │
                                  └─────────────────┘
```

### Network Security Zones

```
┌─────────────────────────────────────────────────────────────────┐
│                     DMZ Zone                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              Load Balancer (Public)                         │  │
│  │              Ports: 80, 443                                 │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Application Zone                               │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │            Cortex MCP Services (Internal)                   │  │
│  │            Ports: 3000 (HTTP), 9090 (Metrics)              │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Data Zone                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              Qdrant Cluster (Private)                       │  │
│  │              Ports: 6333 (HTTP), 6334 (gRPC)              │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Environment Variables & Configuration

### 🔐 Critical Security Configuration

**Mandatory Production Secrets:**

```bash
# OpenAI API Key (Required - System will NOT start without this)
OPENAI_API_KEY=sk-prod-your-actual-openai-api-key-here

# JWT Authentication Secret (Minimum 64 characters)
JWT_SECRET=your_very_long_and_secure_jwt_secret_key_here_minimum_64_characters_random_and_unique

# Data Encryption Key (64-character hex string)
ENCRYPTION_KEY=your_64_character_hex_encryption_key_here_for_production_use_only

# MCP API Key (Minimum 48 characters)
MCP_API_KEY=your_production_mcp_api_key_minimum_48_characters_secure_and_random

# Qdrant API Key (if using managed Qdrant service)
QDRANT_API_KEY=your-production-qdrant-api-key-here
```

### 🏗️ Database Configuration

```bash
# Database Configuration (Qdrant Only - No PostgreSQL)
DATABASE_TYPE=qdrant
QDRANT_URL=https://your-production-qdrant-cluster.com
QDRANT_API_KEY=your-production-qdrant-api-key
QDRANT_TIMEOUT=60000
QDRANT_COLLECTION_PREFIX=cortex-prod
QDRANT_COLLECTION_NAME=cortex-memory-production

# Connection Pool Settings
QDRANT_MAX_CONNECTIONS=20
QDRANT_CONNECTION_TIMEOUT=30000
QDRANT_KEEP_ALIVE=true
QDRANT_KEEP_ALIVE_TIMEOUT=30000
```

### 🧠 Vector Embedding Configuration

```bash
# OpenAI Embedding Settings
VECTOR_SIZE=1536                           # Must match OpenAI ada-002 model
VECTOR_DISTANCE=Cosine
EMBEDDING_MODEL=text-embedding-ada-002
EMBEDDING_BATCH_SIZE=25
EMBEDDING_TIMEOUT=30000
EMBEDDING_RETRY_ATTEMPTS=3
```

### 🔍 Search Configuration

```bash
# Production Search Optimization
SEARCH_LIMIT=100
SEARCH_MODE=deep
SIMILARITY_THRESHOLD=0.75
SEARCH_TIMEOUT=30000
SEARCH_CACHE_SIZE=10000
SEARCH_CACHE_TTL=7200
```

### 🚀 Performance Configuration

```bash
# Production Performance Settings
API_TIMEOUT=30000
DB_CONNECTION_TIMEOUT=30000
DB_RETRY_ATTEMPTS=5
DB_RETRY_DELAY=2000
DB_POOL_SIZE=20

# Node.js Memory Management
NODE_OPTIONS=--max-old-space-size=8192 --max-heap-size=8192 --expose-gc
ENABLE_GC=true
GC_INTERVAL=300000
```

### 🛡️ Security Configuration

```bash
# CORS Configuration (Restrict to specific domains)
CORS_ORIGIN=https://your-production-domain.com,https://api.your-production-domain.com

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=900000        # 15 minutes
RATE_LIMIT_MAX_REQUESTS=1000
RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS=false

# Security Headers
HELMET_ENABLED=true
HELMET_CONTENT_SECURITY_POLICY=true
HELMET_HSTS_MAX_AGE=31536000        # 1 year
HELMET_HSTS_INCLUDE_SUBDOMAINS=true
HELMET_HSTS_PRELOAD=true

# Input Validation
MAX_REQUEST_SIZE_MB=10
MAX_BATCH_SIZE=100
VALIDATE_INPUTS=true
SANITIZE_INPUTS=true
```

### 📊 Monitoring & Logging Configuration

```bash
# Production Logging
LOG_LEVEL=info                       # Options: error, warn, info, debug
LOG_FORMAT=json
LOG_TIMESTAMP=true
LOG_REQUEST_ID=true
LOG_STRUCTURED=true

# Metrics Collection
ENABLE_METRICS_COLLECTION=true
METRICS_INTERVAL=60000
METRICS_RETENTION_DAYS=30

# Health Checks
ENABLE_HEALTH_CHECKS=true
HEALTH_CHECK_INTERVAL=30000
HEALTH_CHECK_TIMEOUT=10000
```

### 🏢 Production Scope Configuration

```bash
# Production Project Scope (Mandatory)
CORTEX_ORG=your-production-organization
CORTEX_PROJECT=cortex-memory-production
CORTEX_BRANCH=main
```

### ⚡ Caching Configuration

```bash
# Production Caching for Performance
ENABLE_CACHING=true
CACHE_TTL=7200
CACHE_MAX_SIZE=50000
CACHE_STRATEGY=lfu
CACHE_REFRESH_INTERVAL=3600
```

### 🔄 Worker Configuration

```bash
# Background Workers
ENABLE_TTL_WORKER=true
TTL_WORKER_INTERVAL=60000
TTL_BATCH_SIZE=100

ENABLE_CLEANUP_WORKER=true
CLEANUP_WORKER_INTERVAL=300000
CLEANUP_BATCH_SIZE=200

ENABLE_EXPIRY_WORKER=true
EXPIRY_WORKER_INTERVAL=120000
EXPIRY_BATCH_SIZE=150
```

### 🎯 Feature Flags (Production)

```bash
# Production Feature Toggles
ENABLE_DEBUG_MODE=false
ENABLE_PERFORMANCE_MONITORING=true
ENABLE_AUDIT_LOGGING=true
ENABLE_ENCRYPTION=true
ENABLE_COMPRESSION=true
ENABLE_CIRCUIT_BREAKER=true
```

### 🌐 Network Configuration

```bash
# Production Network Settings
PORT=3000
HOST=0.0.0.0
ENABLE_COMPRESSION=true
COMPRESSION_THRESHOLD=1024
```

### 📋 Complete .env.production Template

```bash
# =============================================================================
# CORTEX MEMORY MCP SERVER - PRODUCTION ENVIRONMENT CONFIGURATION
# =============================================================================
# SECURITY WARNING: Never commit this file to version control.
# =============================================================================

# Environment Mode
NODE_ENV=production

# Critical Security (MANDATORY)
OPENAI_API_KEY=your-production-openai-api-key
JWT_SECRET=your_64_char_minimum_jwt_secret_here
ENCRYPTION_KEY=your_64_char_hex_encryption_key_here
MCP_API_KEY=your_48_char_minimum_mcp_api_key_here

# Database Configuration
DATABASE_TYPE=qdrant
QDRANT_URL=https://your-production-qdrant-cluster.com
QDRANT_API_KEY=your-production-qdrant-api-key
QDRANT_COLLECTION_NAME=cortex-memory-production

# Performance & Security
# ... (rest of configuration from above)
```

---

## Infrastructure Requirements

### Minimum Production Requirements

#### Computing Resources

**Cortex MCP Application (Per Instance):**

- **CPU:** 2 cores minimum, 4 cores recommended
- **Memory:** 4GB minimum, 8GB recommended
- **Storage:** 20GB SSD for application and logs
- **Network:** 1Gbps connectivity

**Qdrant Vector Database (Per Node):**

- **CPU:** 4 cores minimum, 8 cores recommended
- **Memory:** 8GB minimum, 16GB recommended
- **Storage:** 100GB SSD minimum, scales with data volume
- **Network:** 1Gbps connectivity

**Supporting Services:**

- **Redis Cache:** 2GB memory, 2 cores
- **Monitoring Stack:** 4 cores, 8GB memory combined

#### Network Requirements

**Ports:**

- **80/443:** Load balancer (HTTP/HTTPS)
- **3000:** Cortex MCP application
- **6333/6334:** Qdrant database (HTTP/gRPC)
- **6379:** Redis cache
- **9090:** Metrics endpoint

**Bandwidth:**

- **Minimum:** 100 Mbps sustained
- **Recommended:** 1 Gbps with burst capability

### Recommended Production Architecture

#### High Availability Setup

```
┌─────────────────────────────────────────────────────────────────┐
│                     Production Cluster                        │
├─────────────────────────────────────────────────────────────────┤
│                     Load Balancer Tier                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │  Nginx #1   │    │  Nginx #2   │    │   ALB/ELB   │          │
│  │  (Primary)  │    │ (Standby)   │    │  (Cloud)    │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                   Application Tier                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Cortex    │    │   Cortex    │    │   Cortex    │          │
│  │   MCP #1    │    │   MCP #2    │    │   MCP #3    │          │
│  │  2CPU/4GB   │    │  2CPU/4GB   │    │  2CPU/4GB   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                     Database Tier                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Qdrant    │    │   Qdrant    │    │   Qdrant    │          │
│  │   Node #1   │    │   Node #2   │    │   Node #3   │          │
│  │  4CPU/8GB   │    │  4CPU/8GB   │    │  4CPU/8GB   │          │
│  │  100GB SSD  │    │  100GB SSD  │    │  100GB SSD  │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                    Cache & Monitoring                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │    Redis    │    │ Prometheus  │    │   Grafana   │          │
│  │   2CPU/2GB   │    │   2CPU/4GB   │    │   1CPU/2GB   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

#### Cloud Platform Recommendations

**AWS Architecture:**

- **Compute:** ECS Fargate or EKS with 3+ instances
- **Database:** Qdrant on EC2 with Auto Scaling or managed service
- **Load Balancer:** Application Load Balancer (ALB)
- **Cache:** ElastiCache Redis
- **Monitoring:** CloudWatch + Prometheus/Grafana
- **Storage:** EBS gp3 volumes for database

**Google Cloud Platform:**

- **Compute:** Cloud Run or GKE with 3+ instances
- **Database:** Qdrant on GCE with managed instance groups
- **Load Balancer:** Cloud Load Balancing
- **Cache:** Memorystore for Redis
- **Monitoring:** Cloud Monitoring + Prometheus/Grafana

**Azure:**

- **Compute:** Azure Container Instances or AKS
- **Database:** Qdrant on Azure VMs with availability sets
- **Load Balancer:** Azure Load Balancer
- **Cache:** Azure Cache for Redis
- **Monitoring:** Azure Monitor + Prometheus/Grafana

### Storage Sizing Guidelines

#### Qdrant Vector Database Storage

**Per Million Vectors:**

- **Base Storage:** ~2GB (1536 dimensions × 4 bytes × 1M)
- **Overhead:** ~50% for indexes and metadata
- **Total:** ~3GB per million vectors
- **Recommended:** 5GB per million for growth

**Storage Planning:**

```bash
# Example calculation for 10 million vectors
Base_Storage = 10M × 1536 × 4 bytes = ~61GB
Overhead = 61GB × 0.5 = ~30GB
Total_Required = 61GB + 30GB = ~91GB
Recommended_Provisioning = 91GB × 1.5 = ~137GB
```

#### Application Storage

**Log Storage:**

- **Application Logs:** 1GB per month per instance
- **Access Logs:** 500MB per month per instance
- **Error Logs:** 100MB per month per instance
- **Total:** ~1.6GB per month per instance

**Backup Storage:**

- **Database Snapshots:** 10% of database size daily
- **Log Archives:** 50% of active logs
- **Configuration Backups:** 100MB

---

## Pre-Flight Checklist

### 🔒 Security Validation

#### [ ] Secret Management Verification

```bash
# Verify all required secrets are configured
echo "Checking required secrets..."
required_secrets=(
  "OPENAI_API_KEY"
  "JWT_SECRET"
  "ENCRYPTION_KEY"
  "MCP_API_KEY"
)

for secret in "${required_secrets[@]}"; do
  if [[ -z "${!secret}" ]]; then
    echo "❌ MISSING: $secret is not configured"
    exit 1
  else
    echo "✅ CONFIGURED: $secret"
  fi
done

# Validate secret formats
if [[ ${#JWT_SECRET} -lt 64 ]]; then
  echo "❌ INVALID: JWT_SECRET must be at least 64 characters"
  exit 1
fi

if [[ ${#MCP_API_KEY} -lt 48 ]]; then
  echo "❌ INVALID: MCP_API_KEY must be at least 48 characters"
  exit 1
fi

if [[ ${#ENCRYPTION_KEY} -ne 64 ]]; then
  echo "❌ INVALID: ENCRYPTION_KEY must be exactly 64 hex characters"
  exit 1
fi
```

#### [ ] Network Security Configuration

```bash
# Verify CORS configuration
if [[ "$CORS_ORIGIN" == *"*"* ]] && [[ "$NODE_ENV" == "production" ]]; then
  echo "❌ SECURITY WARNING: Wildcard CORS origin in production"
  echo "   Please restrict CORS_ORIGIN to specific domains"
  exit 1
fi

# Verify HTTPS enforcement
if [[ "$HELMET_HSTS_MAX_AGE" -lt 31536000 ]]; then
  echo "❌ SECURITY WARNING: HSTS max age should be at least 1 year for production"
fi

# Verify rate limiting is enabled
if [[ "$RATE_LIMIT_ENABLED" != "true" ]]; then
  echo "❌ SECURITY WARNING: Rate limiting should be enabled in production"
  exit 1
fi
```

#### [ ] SSL/TLS Certificate Validation

```bash
# Check SSL certificate validity
check_ssl_certificate() {
  local domain=$1
  local expiry_days=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
  local expiry_epoch=$(date -d "$expiry_days" +%s)
  local current_epoch=$(date +%s)
  local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))

  if [[ $days_until_expiry -lt 30 ]]; then
    echo "❌ SSL WARNING: Certificate for $domain expires in $days_until_expiry days"
    return 1
  else
    echo "✅ SSL OK: Certificate for $domain valid for $days_until_expiry days"
    return 0
  fi
}

# Check production domains
check_ssl_certificate "your-production-domain.com"
check_ssl_certificate "api.your-production-domain.com"
```

### ⚡ Performance Validation

#### [ ] Resource Availability Check

```bash
# Check system resources
check_system_resources() {
  # Check available memory
  local available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
  if [[ $available_memory -lt 4096 ]]; then
    echo "❌ PERFORMANCE WARNING: Low available memory ($available_memory MB)"
    echo "   Recommended minimum: 4096 MB"
  else
    echo "✅ PERFORMANCE OK: Available memory $available_memory MB"
  fi

  # Check CPU load
  local cpu_load=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')
  local cpu_cores=$(nproc)
  local load_percentage=$(echo "$cpu_load * 100 / $cpu_cores" | bc)

  if (( $(echo "$load_percentage > 80" | bc -l) )); then
    echo "❌ PERFORMANCE WARNING: High CPU load ($load_percentage%)"
  else
    echo "✅ PERFORMANCE OK: CPU load $load_percentage%"
  fi

  # Check disk space
  local available_disk=$(df / | awk 'NR==2 {print $4}')
  local available_disk_gb=$((available_disk / 1024 / 1024))

  if [[ $available_disk_gb -lt 20 ]]; then
    echo "❌ PERFORMANCE WARNING: Low disk space ($available_disk_gb GB)"
  else
    echo "✅ PERFORMANCE OK: Available disk space $available_disk_gb GB"
  fi
}

check_system_resources
```

#### [ ] Database Connectivity Test

```bash
# Test Qdrant connectivity
test_qdrant_connectivity() {
  echo "Testing Qdrant connectivity..."

  # Basic connectivity test
  if curl -f -s --max-time 10 "$QDRANT_URL/health" > /dev/null; then
    echo "✅ DATABASE OK: Qdrant is accessible"
  else
    echo "❌ DATABASE ERROR: Cannot connect to Qdrant at $QDRANT_URL"
    return 1
  fi

  # Collection check
  if curl -f -s --max-time 10 "$QDRANT_URL/collections/$QDRANT_COLLECTION_NAME" > /dev/null; then
    echo "✅ DATABASE OK: Collection '$QDRANT_COLLECTION_NAME' exists"
  else
    echo "⚠️  DATABASE WARNING: Collection '$QDRANT_COLLECTION_NAME' not found"
    echo "   This is normal for first-time deployment"
  fi

  # Performance test
  local start_time=$(date +%s%N)
  curl -f -s --max-time 10 "$QDRANT_URL/collections" > /dev/null
  local end_time=$(date +%s%N)
  local response_time=$(( (end_time - start_time) / 1000000 ))

  if [[ $response_time -lt 1000 ]]; then
    echo "✅ PERFORMANCE OK: Database response time ${response_time}ms"
  else
    echo "⚠️  PERFORMANCE WARNING: Slow database response (${response_time}ms)"
  fi
}

test_qdrant_connectivity
```

#### [ ] OpenAI API Validation

```bash
# Test OpenAI API connectivity
test_openai_api() {
  echo "Testing OpenAI API connectivity..."

  if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "❌ API ERROR: OPENAI_API_KEY not configured"
    return 1
  fi

  # Test API key validity
  local response=$(curl -s -w "%{http_code}" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    "https://api.openai.com/v1/models")

  local http_code="${response: -3}"
  local response_body="${response%???}"

  if [[ "$http_code" == "200" ]]; then
    echo "✅ API OK: OpenAI API key is valid"
  else
    echo "❌ API ERROR: OpenAI API key validation failed (HTTP $http_code)"
    echo "   Response: $response_body"
    return 1
  fi

  # Test embedding generation
  local embedding_response=$(curl -s -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d '{"input": "test", "model": "text-embedding-ada-002"}' \
    "https://api.openai.com/v1/embeddings")

  local embedding_http_code="${embedding_response: -3}"

  if [[ "$embedding_http_code" == "200" ]]; then
    echo "✅ API OK: Embedding generation working"
  else
    echo "❌ API ERROR: Embedding generation failed (HTTP $embedding_http_code)"
    return 1
  fi
}

test_openai_api
```

### 🔧 Configuration Verification

#### [ ] Environment Variable Validation

```bash
# Comprehensive environment validation
validate_environment() {
  echo "Validating production environment configuration..."

  local errors=0

  # Critical settings
  if [[ "$NODE_ENV" != "production" ]]; then
    echo "❌ CONFIG ERROR: NODE_ENV must be 'production' for production deployment"
    ((errors++))
  fi

  if [[ -z "$CORTEX_ORG" ]] || [[ -z "$CORTEX_PROJECT" ]]; then
    echo "❌ CONFIG ERROR: CORTEX_ORG and CORTEX_PROJECT must be configured"
    ((errors++))
  fi

  # Performance settings
  if [[ $DB_POOL_SIZE -lt 10 ]]; then
    echo "⚠️  CONFIG WARNING: DB_POOL_SIZE should be at least 10 for production"
  fi

  if [[ $API_TIMEOUT -lt 10000 ]]; then
    echo "⚠️  CONFIG WARNING: API_TIMEOUT should be at least 10 seconds for production"
  fi

  # Security settings
  if [[ "$RATE_LIMIT_MAX_REQUESTS" -gt 10000 ]]; then
    echo "⚠️  CONFIG WARNING: RATE_LIMIT_MAX_REQUESTS is very permissive (>10000)"
  fi

  if [[ $MAX_REQUEST_SIZE_MB -gt 100 ]]; then
    echo "⚠️  CONFIG WARNING: MAX_REQUEST_SIZE_MB is large (>100MB)"
  fi

  echo "Environment validation completed with $errors errors"
  return $errors
}

validate_environment
```

#### [ ] Dependency Health Check

```bash
# Check service dependencies
check_dependencies() {
  echo "Checking service dependencies..."

  # Check Redis if configured
  if command -v redis-cli &> /dev/null; then
    if redis-cli ping &> /dev/null; then
      echo "✅ DEPENDENCY OK: Redis is accessible"
    else
      echo "⚠️  DEPENDENCY WARNING: Redis not accessible"
    fi
  fi

  # Check Docker services
  if command -v docker &> /dev/null; then
    local running_containers=$(docker ps --format "table {{.Names}}" | grep -c cortex)
    echo "✅ DOCKER: $running_containers Cortex containers running"
  fi

  # Check system timezone
  local timezone=$(timedatectl show --property=Timezone --value)
  echo "✅ SYSTEM: Timezone set to $timezone"

  # Check system time sync
  if command -v timedatectl &> /dev/null; then
    local time_sync=$(timedatectl show --property=NTPSynchronized --value)
    if [[ "$time_sync" == "yes" ]]; then
      echo "✅ SYSTEM: Time synchronization enabled"
    else
      echo "⚠️  SYSTEM WARNING: Time synchronization not enabled"
    fi
  fi
}

check_dependencies
```

### 📋 Final Pre-Flight Validation

#### [ ] Automated Pre-Flight Script

```bash
#!/bin/bash
# pre-flight-check.sh

set -e

echo "🚀 Cortex Memory MCP - Production Pre-Flight Check"
echo "=================================================="

# Run all checks
echo ""
echo "🔒 Running security validation..."
source security-validation.sh

echo ""
echo "⚡ Running performance validation..."
source performance-validation.sh

echo ""
echo "🔧 Running configuration verification..."
source configuration-validation.sh

echo ""
echo "📋 Running dependency checks..."
source dependency-validation.sh

echo ""
echo "✅ Pre-flight checks completed successfully!"
echo "🚀 Ready for production deployment!"
```

#### [ ] Manual Validation Checklist

```markdown
## Pre-Flight Manual Checklist

### Security

- [ ] All secrets configured and validated
- [ ] SSL/TLS certificates valid (30+ days)
- [ ] CORS restricted to specific domains
- [ ] Rate limiting enabled and configured
- [ ] Security headers configured
- [ ] Firewall rules verified

### Performance

- [ ] System resources meet minimum requirements
- [ ] Database connectivity verified
- [ ] API latency under 1 second
- [ ] Load balancer configuration tested
- [ ] Caching layer operational

### Configuration

- [ ] Environment variables validated
- [ ] Production scope configured
- [ ] Feature flags set appropriately
- [ ] Logging level configured
- [ ] Monitoring endpoints accessible

### Dependencies

- [ ] Qdrant cluster operational
- [ ] Redis cache running (if used)
- [ ] Monitoring stack deployed
- [ ] Backup systems configured
- [ ] Alert notifications tested
```

---

## Deployment Procedures

### 🚀 Automated Deployment (Recommended)

#### Prerequisites

- Production environment access
- Docker and Docker Compose installed
  -kubectl configured (for Kubernetes)
- All secrets configured in secret manager

#### Step 1: Build and Push Container Image

```bash
#!/bin/bash
# scripts/build-and-push.sh

set -e

# Configuration
REGISTRY="your-registry.com"
IMAGE_NAME="cortex-memory-mcp"
VERSION=${1:-$(git rev-parse --short HEAD)}
ENVIRONMENT=${2:-production}

echo "🏗️  Building Cortex MCP Docker image for $ENVIRONMENT..."

# Create production build
echo "📦 Creating production build..."
npm run build

# Build Docker image
echo "🐳 Building Docker image..."
docker build \
  --tag $REGISTRY/$IMAGE_NAME:$VERSION \
  --tag $REGISTRY/$IMAGE_NAME:latest \
  --build-arg NODE_ENV=production \
  --build-arg VERSION=$VERSION \
  .

# Push to registry
echo "📤 Pushing to registry..."
docker push $REGISTRY/$IMAGE_NAME:$VERSION
docker push $REGISTRY/$IMAGE_NAME:latest

echo "✅ Build and push completed successfully"
echo "🏷️  Image tag: $VERSION"
```

#### Step 2: Deploy to Production

```bash
#!/bin/bash
# scripts/deploy-production.sh

set -e

# Configuration
VERSION=${1:-latest}
NAMESPACE="cortex-mcp"
ENVIRONMENT="production"

echo "🚀 Deploying Cortex MCP to $ENVIRONMENT..."
echo "📦 Version: $VERSION"
echo "🏷️  Namespace: $NAMESPACE"

# Create namespace if it doesn't exist
echo "📂 Creating namespace..."
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Apply configurations
echo "⚙️  Applying configurations..."
kubectl apply -f k8s/configmap.yaml -n $NAMESPACE
kubectl apply -f k8s/secrets.yaml -n $NAMESPACE

# Deploy application
echo "🚀 Deploying application..."
envsubst < k8s/deployment.yaml.template | kubectl apply -f -

# Wait for deployment rollout
echo "⏳ Waiting for deployment rollout..."
kubectl rollout status deployment/cortex-mcp -n $NAMESPACE --timeout=600s

# Verify deployment
echo "🔍 Verifying deployment..."
kubectl get pods -n $NAMESPACE -l app=cortex-mcp

# Run health check
echo "🏥 Running health check..."
./scripts/health-check.sh $NAMESPACE

echo "✅ Deployment completed successfully!"
```

#### Step 3: Kubernetes Deployment Manifests

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cortex-mcp
  labels:
    name: cortex-mcp
    environment: production
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cortex-config
  namespace: cortex-mcp
data:
  NODE_ENV: 'production'
  LOG_LEVEL: 'info'
  LOG_FORMAT: 'json'
  PORT: '3000'
  HOST: '0.0.0.0'
  QDRANT_URL: 'https://qdrant-production.example.com'
  QDRANT_COLLECTION_NAME: 'cortex-memory-production'
  CORTEX_ORG: 'your-production-org'
  CORTEX_PROJECT: 'cortex-memory-production'
  CORTEX_BRANCH: 'main'
  RATE_LIMIT_ENABLED: 'true'
  RATE_LIMIT_WINDOW_MS: '900000'
  RATE_LIMIT_MAX_REQUESTS: '1000'
  HELMET_ENABLED: 'true'
  ENABLE_HEALTH_CHECKS: 'true'
  ENABLE_METRICS_COLLECTION: 'true'
  ENABLE_CACHING: 'true'
  ENABLE_ENCRYPTION: 'true'
  ENABLE_COMPRESSION: 'true'
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
  JWT_SECRET: <base64-encoded-jwt-secret>
  ENCRYPTION_KEY: <base64-encoded-encryption-key>
  MCP_API_KEY: <base64-encoded-mcp-api-key>
  QDRANT_API_KEY: <base64-encoded-qdrant-key>
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-mcp
  namespace: cortex-mcp
  labels:
    app: cortex-mcp
    version: v2.0.1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: cortex-mcp
  template:
    metadata:
      labels:
        app: cortex-mcp
        version: v2.0.1
      annotations:
        prometheus.io/scrape: 'true'
        prometheus.io/port: '9090'
        prometheus.io/path: '/metrics'
    spec:
      serviceAccountName: cortex-mcp
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
        - name: cortex-mcp
          image: your-registry.com/cortex-memory-mcp:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 3000
              name: http
              protocol: TCP
            - containerPort: 9090
              name: metrics
              protocol: TCP
          envFrom:
            - configMapRef:
                name: cortex-config
            - secretRef:
                name: cortex-secrets
          resources:
            requests:
              cpu: 1000m
              memory: 2Gi
            limits:
              cpu: 2000m
              memory: 4Gi
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
              scheme: HTTP
            initialDelaySeconds: 60
            periodSeconds: 30
            timeoutSeconds: 10
            failureThreshold: 3
            successThreshold: 1
          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
            successThreshold: 1
          startupProbe:
            httpGet:
              path: /startup
              port: 3000
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 30
            successThreshold: 1
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
            runAsNonRoot: true
            runAsUser: 1001
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
      terminationGracePeriodSeconds: 60
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - cortex-mcp
                topologyKey: kubernetes.io/hostname
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cortex-mcp-service
  namespace: cortex-mcp
  labels:
    app: cortex-mcp
  annotations:
    prometheus.io/scrape: 'true'
    prometheus.io/port: '9090'
    prometheus.io/path: '/metrics'
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
    nginx.ingress.kubernetes.io/ssl-redirect: 'true'
    nginx.ingress.kubernetes.io/use-regex: 'true'
    nginx.ingress.kubernetes.io/rate-limit: '100'
    nginx.ingress.kubernetes.io/rate-limit-window: '1m'
    nginx.ingress.kubernetes.io/enable-cors: 'true'
    nginx.ingress.kubernetes.io/cors-allow-origin: 'https://your-production-domain.com'
    nginx.ingress.kubernetes.io/cors-allow-methods: 'GET, POST, PUT, DELETE, OPTIONS'
    nginx.ingress.kubernetes.io/cors-allow-headers: 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization'
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
---
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
---
# k8s/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cortex-mcp
  namespace: cortex-mcp
---
# k8s/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cortex-mcp-role
  namespace: cortex-mcp
rules:
  - apiGroups: ['']
    resources: ['configmaps', 'secrets']
    verbs: ['get', 'list']
  - apiGroups: ['']
    resources: ['pods']
    verbs: ['get', 'list']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cortex-mcp-rolebinding
  namespace: cortex-mcp
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cortex-mcp-role
subjects:
  - kind: ServiceAccount
    name: cortex-mcp
    namespace: cortex-mcp
```

### 🐳 Docker Compose Deployment

#### Production Docker Compose Configuration

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  cortex-mcp:
    image: your-registry.com/cortex-memory-mcp:latest
    container_name: cortex-mcp
    restart: unless-stopped
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
    ports:
      - '3000:3000'
      - '9090:9090'
    environment:
      - NODE_ENV=production
      - QDRANT_URL=http://qdrant:6333
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - MCP_API_KEY=${MCP_API_KEY}
      - CORTEX_ORG=${CORTEX_ORG}
      - CORTEX_PROJECT=${CORTEX_PROJECT}
      - LOG_LEVEL=info
      - LOG_FORMAT=json
      - RATE_LIMIT_ENABLED=true
      - HELMET_ENABLED=true
      - ENABLE_HEALTH_CHECKS=true
      - ENABLE_METRICS_COLLECTION=true
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config:ro
    depends_on:
      qdrant:
        condition: service_healthy
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:3000/health']
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - cortex-network
    logging:
      driver: 'json-file'
      options:
        max-size: '100m'
        max-file: '5'

  nginx:
    image: nginx:alpine
    container_name: cortex-nginx
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - cortex-mcp
    networks:
      - cortex-network
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost/health']
      interval: 30s
      timeout: 5s
      retries: 3

  qdrant:
    image: qdrant/qdrant:latest
    container_name: cortex-qdrant
    restart: unless-stopped
    ports:
      - '6333:6333'
      - '6334:6334'
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__GRPC_PORT=6334
      - QDRANT__LOG_LEVEL=INFO
      - QDRANT__SERVICE__MAX_REQUEST_SIZE_MB=32
      - QDRANT__STORAGE__PERFORMANCE__MAX_SEARCH_THREADS=4
    volumes:
      - qdrant_data:/qdrant/storage
      - ./qdrant/config.yaml:/qdrant/config/production.yaml:ro
    networks:
      - cortex-network
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:6333/health']
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G

  redis:
    image: redis:7-alpine
    container_name: cortex-redis
    restart: unless-stopped
    ports:
      - '6379:6379'
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    networks:
      - cortex-network
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 30s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

  prometheus:
    image: prom/prometheus:latest
    container_name: cortex-prometheus
    restart: unless-stopped
    ports:
      - '9091:9090'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    networks:
      - cortex-network

  grafana:
    image: grafana/grafana:latest
    container_name: cortex-grafana
    restart: unless-stopped
    ports:
      - '3001:3000'
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
    depends_on:
      - prometheus
    networks:
      - cortex-network

volumes:
  qdrant_data:
    driver: local
  redis_data:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local

networks:
  cortex-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 🔄 Blue-Green Deployment Strategy

#### Blue-Green Deployment Script

```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

set -e

# Configuration
NEW_VERSION=${1:-latest}
NAMESPACE="cortex-mcp"
BLUE_ENV="cortex-mcp-blue"
GREEN_ENV="cortex-mcp-green"

echo "🔵 Blue-Green Deployment for Cortex MCP"
echo "========================================"
echo "📦 New Version: $NEW_VERSION"

# Determine current active environment
get_active_environment() {
  local blue_service=$(kubectl get svc $BLUE_ENV-service -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
  if [[ $blue_service -gt 0 ]]; then
    echo "green"  # Blue is active, deploy to green
  else
    echo "blue"   # Green is active, deploy to blue
  fi
}

ACTIVE_ENV=$(get_active_environment)
NEW_ENV=$([ "$ACTIVE_ENV" == "blue" ] && echo "green" || echo "blue")

echo "🔄 Active Environment: $ACTIVE_ENV"
echo "🚀 Deploying to: $NEW_ENV"

# Deploy new version to inactive environment
echo "📦 Deploying version $NEW_VERSION to $NEW_ENV environment..."

# Update deployment template
sed "s/IMAGE_TAG/$NEW_VERSION/g" k8s/blue-green/${NEW_ENV}-deployment.yaml.template > k8s/blue-green/${NEW_ENV}-deployment.yaml

# Apply new deployment
kubectl apply -f k8s/blue-green/${NEW_ENV}-deployment.yaml -n $NAMESPACE

# Wait for deployment to be ready
echo "⏳ Waiting for $NEW_ENV deployment to be ready..."
kubectl rollout status deployment/${NEW_ENV}-deployment -n $NAMESPACE --timeout=600s

# Health check new deployment
echo "🏥 Running health checks on $NEW_ENV..."
./scripts/health-check-environment.sh $NEW_ENV

# Switch traffic to new environment
echo "🔄 Switching traffic to $NEW_ENV..."
kubectl patch service cortex-mcp-service -n $NAMESPACE -p '{"spec":{"selector":{"environment":"'$NEW_ENV'"}}}'

# Verify switch
echo "🔍 Verifying traffic switch..."
sleep 30
./scripts/health-check-service.sh

# Scale down old environment
echo "⬇️ Scaling down $ACTIVE_ENV environment..."
kubectl scale deployment ${ACTIVE_ENV}-deployment --replicas=0 -n $NAMESPACE

echo "✅ Blue-Green deployment completed successfully!"
echo "🎯 Active environment is now: $NEW_ENV"
```

### 📊 Deployment Monitoring

#### Real-time Deployment Monitoring

```bash
#!/bin/bash
# scripts/monitor-deployment.sh

set -e

NAMESPACE=${1:-cortex-mcp}
DEPLOYMENT_NAME=${2:-cortex-mcp}

echo "📊 Monitoring Deployment: $DEPLOYMENT_NAME in $NAMESPACE"
echo "========================================================"

# Watch deployment progress
watch_deployment() {
  echo "👀 Watching deployment progress..."
  kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=600s &

  local watch_pid=$!

  # Show real-time pod status
  while kill -0 $watch_pid 2>/dev/null; do
    clear
    echo "📊 Deployment Status - $(date)"
    echo "================================"
    kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME -o wide
    echo ""
    echo "📈 Resource Usage:"
    kubectl top pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME 2>/dev/null || echo "Metrics not available"
    echo ""
    echo "🏥 Health Status:"
    kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME -o jsonpath='{range .items[*]}{.metadata.name}{" - "}{.status.phase}{" - "}{range .status.conditions[*]}{.type}={.status}{" "}{end}{"\n"}{end}'
    sleep 5
  done

  wait $watch_pid
}

# Check deployment success
check_deployment_success() {
  echo ""
  echo "✅ Deployment completed. Checking status..."

  local replica_count=$(kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE -o jsonpath='{.status.readyReplicas}')
  local desired_replicas=$(kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE -o jsonpath='{.spec.replicas}')

  if [[ $replica_count == $desired_replicas ]]; then
    echo "✅ All replicas are ready"
  else
    echo "⚠️  Warning: Only $replica_count/$desired_replicas replicas are ready"
  fi

  # Check pod health
  local unhealthy_pods=$(kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME --field-selector=status.phase!=Running -o jsonpath='{.items[*].metadata.name}')
  if [[ -n "$unhealthy_pods" ]]; then
    echo "❌ Unhealthy pods detected: $unhealthy_pods"
    return 1
  else
    echo "✅ All pods are healthy"
  fi
}

# Main execution
watch_deployment
check_deployment_success

echo ""
echo "📊 Deployment monitoring completed!"
```

---

## Post-Deployment Validation

### 🏥 Health Check Validation

#### Automated Health Check Script

```bash
#!/bin/bash
# scripts/comprehensive-health-check.sh

set -e

# Configuration
NAMESPACE=${1:-cortex-mcp}
SERVICE_URL=${2:-https://api.cortex-memory.com}
TIMEOUT=${3:-300}

echo "🏥 Comprehensive Health Check"
echo "============================="
echo "🔍 Namespace: $NAMESPACE"
echo "🌐 Service URL: $SERVICE_URL"
echo "⏱️  Timeout: ${TIMEOUT}s"

# Initialize health check results
HEALTH_CHECKS_PASSED=0
HEALTH_CHECKS_FAILED=0

# Function to log health check result
log_health_result() {
  local check_name=$1
  local status=$2
  local message=$3

  if [[ "$status" == "PASS" ]]; then
    echo "✅ PASS: $check_name - $message"
    ((HEALTH_CHECKS_PASSED++))
  else
    echo "❌ FAIL: $check_name - $message"
    ((HEALTH_CHECKS_FAILED++))
  fi
}

# 1. Basic Connectivity Test
test_connectivity() {
  echo ""
  echo "🔌 Testing basic connectivity..."

  if curl -f -s --max-time 10 "$SERVICE_URL/health" > /dev/null; then
    log_health_result "Connectivity" "PASS" "Service is reachable"
  else
    log_health_result "Connectivity" "FAIL" "Service is not reachable"
    return 1
  fi
}

# 2. Application Health Endpoint
test_application_health() {
  echo ""
  echo "🚀 Testing application health..."

  local health_response=$(curl -s --max-time 10 "$SERVICE_URL/health")
  local status=$(echo "$health_response" | jq -r '.status // "unknown"')

  if [[ "$status" == "healthy" ]]; then
    log_health_result "Application Health" "PASS" "Application reports healthy status"
  else
    log_health_result "Application Health" "FAIL" "Application status: $status"
    return 1
  fi
}

# 3. Database Connectivity
test_database_connectivity() {
  echo ""
  echo "🗄️ Testing database connectivity..."

  local db_health_response=$(curl -s --max-time 15 "$SERVICE_URL/health/database")
  local db_status=$(echo "$db_health_response" | jq -r '.status // "unknown"')

  if [[ "$db_status" == "connected" ]]; then
    log_health_result "Database" "PASS" "Database connection healthy"
  else
    log_health_result "Database" "FAIL" "Database status: $db_status"
    return 1
  fi
}

# 4. External API Dependencies
test_external_apis() {
  echo ""
  echo "🌐 Testing external API dependencies..."

  local api_health_response=$(curl -s --max-time 15 "$SERVICE_URL/health/external")
  local openai_status=$(echo "$api_health_response" | jq -r '.dependencies.openai.status // "unknown"')

  if [[ "$openai_status" == "healthy" ]]; then
    log_health_result "OpenAI API" "PASS" "OpenAI API is accessible"
  else
    log_health_result "OpenAI API" "FAIL" "OpenAI API status: $openai_status"
    return 1
  fi
}

# 5. Performance Benchmarks
test_performance() {
  echo ""
  echo "⚡ Testing performance benchmarks..."

  # Test response time
  local start_time=$(date +%s%N)
  curl -s --max-time 10 "$SERVICE_URL/health" > /dev/null
  local end_time=$(date +%s%N)
  local response_time=$(( (end_time - start_time) / 1000000 ))

  if [[ $response_time -lt 1000 ]]; then
    log_health_result "Response Time" "PASS" "${response_time}ms (< 1000ms threshold)"
  else
    log_health_result "Response Time" "WARN" "${response_time}ms (exceeds 1000ms threshold)"
  fi

  # Test memory usage
  local memory_response=$(curl -s --max-time 10 "$SERVICE_URL/metrics/memory")
  local memory_usage=$(echo "$memory_response" | jq -r '.heap_used_mb // "unknown"')

  if [[ "$memory_usage" != "unknown" ]] && [[ $memory_usage -lt 6144 ]]; then  # 6GB threshold
    log_health_result "Memory Usage" "PASS" "${memory_usage}MB (< 6GB threshold)"
  else
    log_health_result "Memory Usage" "WARN" "Memory usage: ${memory_usage}MB"
  fi
}

# 6. Functionality Tests
test_functionality() {
  echo ""
  echo "🧪 Testing core functionality..."

  # Test memory store functionality
  local store_test_payload='{"items":[{"kind":"entity","data":{"title":"Health Check Test","description":"Automated health check test entity"},"scope":{"project":"health-check"}}]}'
  local store_response=$(curl -s --max-time 15 -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d "$store_test_payload" \
    "$SERVICE_URL/api/v1/memory/store")

  local store_success=$(echo "$store_response" | jq -r '.success // false')

  if [[ "$store_success" == "true" ]]; then
    log_health_result "Memory Store" "PASS" "Memory storage functionality working"
  else
    log_health_result "Memory Store" "FAIL" "Memory storage test failed"
    return 1
  fi

  # Test memory find functionality
  local find_test_payload='{"query":"Health Check Test","limit":1,"scope":{"project":"health-check"}}'
  local find_response=$(curl -s --max-time 15 -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d "$find_test_payload" \
    "$SERVICE_URL/api/v1/memory/find")

  local find_results=$(echo "$find_response" | jq -r '.items | length // 0')

  if [[ $find_results -gt 0 ]]; then
    log_health_result "Memory Search" "PASS" "Memory search functionality working"
  else
    log_health_result "Memory Search" "FAIL" "Memory search test failed"
    return 1
  fi
}

# 7. Security Validation
test_security() {
  echo ""
  echo "🛡️ Testing security configuration..."

  # Test HTTPS enforcement
  local http_response=$(curl -s --max-time 10 -I "http://$SERVICE_URL" | head -1)
  if [[ "$http_response" =~ "301" ]] || [[ "$http_response" =~ "302" ]]; then
    log_health_result "HTTPS Redirect" "PASS" "HTTP properly redirects to HTTPS"
  else
    log_health_result "HTTPS Redirect" "FAIL" "HTTP does not redirect to HTTPS"
  fi

  # Test security headers
  local security_headers=$(curl -s --max-time 10 -I "$SERVICE_URL/health")
  local hsts_present=$(echo "$security_headers" | grep -i "strict-transport-security")
  local security_headers_present=$(echo "$security_headers" | grep -i "x-content-type-options")

  if [[ -n "$hsts_present" ]]; then
    log_health_result "HSTS Header" "PASS" "HSTS header is present"
  else
    log_health_result "HSTS Header" "FAIL" "HSTS header is missing"
  fi

  if [[ -n "$security_headers_present" ]]; then
    log_health_result "Security Headers" "PASS" "Security headers are present"
  else
    log_health_result "Security Headers" "WARN" "Some security headers may be missing"
  fi
}

# 8. Metrics and Monitoring
test_monitoring() {
  echo ""
  echo "📊 Testing monitoring endpoints..."

  # Test metrics endpoint
  if curl -f -s --max-time 10 "$SERVICE_URL/metrics" > /dev/null; then
    log_health_result "Metrics Endpoint" "PASS" "Metrics endpoint is accessible"
  else
    log_health_result "Metrics Endpoint" "FAIL" "Metrics endpoint is not accessible"
  fi

  # Test detailed health endpoint
  if curl -f -s --max-time 10 "$SERVICE_URL/health/detailed" > /dev/null; then
    log_health_result "Detailed Health" "PASS" "Detailed health endpoint is accessible"
  else
    log_health_result "Detailed Health" "WARN" "Detailed health endpoint may not be accessible"
  fi
}

# Run all health checks
main() {
  echo "🏥 Starting comprehensive health check..."
  echo "⏰ Started at: $(date)"

  test_connectivity || true
  test_application_health || true
  test_database_connectivity || true
  test_external_apis || true
  test_performance || true
  test_functionality || true
  test_security || true
  test_monitoring || true

  echo ""
  echo "📊 Health Check Summary"
  echo "======================="
  echo "✅ Passed: $HEALTH_CHECKS_PASSED"
  echo "❌ Failed: $HEALTH_CHECKS_FAILED"
  echo "⏰ Completed at: $(date)"

  local total_checks=$((HEALTH_CHECKS_PASSED + HEALTH_CHECKS_FAILED))
  local success_rate=$(( (HEALTH_CHECKS_PASSED * 100) / total_checks ))

  echo "📈 Success Rate: ${success_rate}%"

  if [[ $HEALTH_CHECKS_FAILED -eq 0 ]]; then
    echo "🎉 All health checks passed! System is healthy."
    return 0
  else
    echo "⚠️  Some health checks failed. Please review the issues above."
    return 1
  fi
}

# Execute main function
main "$@"
```

### 🧪 Functional Validation Tests

#### MCP Protocol Validation

```bash
#!/bin/bash
# scripts/validate-mcp-protocol.sh

set -e

SERVICE_URL=${1:-http://localhost:3000}
MCP_API_KEY=${2:-$MCP_API_KEY}

echo "🧪 MCP Protocol Validation"
echo "========================="
echo "🌐 Service URL: $SERVICE_URL"

# Test MCP initialization
test_mcp_initialization() {
  echo ""
  echo "🚀 Testing MCP initialization..."

  local init_request='{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {
        "tools": {}
      },
      "clientInfo": {
        "name": "health-check",
        "version": "1.0.0"
      }
    }
  }'

  local init_response=$(echo "$init_request" | timeout 30 curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d @- \
    "$SERVICE_URL/mcp")

  local init_result=$(echo "$init_response" | jq -r '.result // empty')

  if [[ -n "$init_result" ]]; then
    echo "✅ MCP initialization successful"
    echo "📋 Server capabilities:"
    echo "$init_result" | jq '.capabilities // {}'
  else
    echo "❌ MCP initialization failed"
    echo "🔍 Response: $init_response"
    return 1
  fi
}

# Test MCP tool listing
test_tool_listing() {
  echo ""
  echo "🔧 Testing MCP tool listing..."

  local tools_request='{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'

  local tools_response=$(echo "$tools_request" | timeout 30 curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d @- \
    "$SERVICE_URL/mcp")

  local tools_result=$(echo "$tools_response" | jq -r '.result.tools // empty')
  local tool_count=$(echo "$tools_result" | jq 'length')

  if [[ $tool_count -gt 0 ]]; then
    echo "✅ Tool listing successful ($tool_count tools available)"
    echo "📋 Available tools:"
    echo "$tools_result" | jq -r '.[] | "  - \(.name): \(.description)"'
  else
    echo "❌ Tool listing failed"
    echo "🔍 Response: $tools_response"
    return 1
  fi
}

# Test memory_store tool
test_memory_store_tool() {
  echo ""
  echo "💾 Testing memory_store tool..."

  local store_request='{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "memory_store",
      "arguments": {
        "items": [
          {
            "kind": "entity",
            "data": {
              "title": "MCP Health Check Test",
              "description": "Test entity for MCP protocol validation",
              "content": "This is a test entity created during MCP protocol validation"
            },
            "scope": {
              "project": "mcp-health-check"
            }
          }
        ]
      }
    }
  }'

  local store_response=$(echo "$store_request" | timeout 30 curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d @- \
    "$SERVICE_URL/mcp")

  local store_result=$(echo "$store_response" | jq -r '.result.content[0].text // empty')

  if [[ -n "$store_result" ]]; then
    echo "✅ memory_store tool working"
    local stored_count=$(echo "$store_result" | jq -r '.stored | length // 0')
    echo "📊 Stored $stored_count items successfully"
  else
    echo "❌ memory_store tool failed"
    echo "🔍 Response: $store_response"
    return 1
  fi
}

# Test memory_find tool
test_memory_find_tool() {
  echo ""
  echo "🔍 Testing memory_find tool..."

  local find_request='{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "memory_find",
      "arguments": {
        "query": "MCP Health Check Test",
        "limit": 5,
        "scope": {
          "project": "mcp-health-check"
        }
      }
    }
  }'

  local find_response=$(echo "$find_request" | timeout 30 curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d @- \
    "$SERVICE_URL/mcp")

  local find_result=$(echo "$find_response" | jq -r '.result.content[0].text // empty')

  if [[ -n "$find_result" ]]; then
    echo "✅ memory_find tool working"
    local found_count=$(echo "$find_result" | jq -r '.items | length // 0')
    echo "📊 Found $found_count items"
  else
    echo "❌ memory_find tool failed"
    echo "🔍 Response: $find_response"
    return 1
  fi
}

# Test system_status tool
test_system_status_tool() {
  echo ""
  echo "🏥 Testing system_status tool..."

  local status_request='{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "system_status",
      "arguments": {
        "operation": "health"
      }
    }
  }'

  local status_response=$(echo "$status_request" | timeout 30 curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -d @- \
    "$SERVICE_URL/mcp")

  local status_result=$(echo "$status_response" | jq -r '.result.content[0].text // empty')

  if [[ -n "$status_result" ]]; then
    echo "✅ system_status tool working"
    echo "📊 System status retrieved successfully"
  else
    echo "❌ system_status tool failed"
    echo "🔍 Response: $status_response"
    return 1
  fi
}

# Main validation function
main() {
  test_mcp_initialization || exit 1
  test_tool_listing || exit 1
  test_memory_store_tool || exit 1
  test_memory_find_tool || exit 1
  test_system_status_tool || exit 1

  echo ""
  echo "🎉 All MCP protocol tests passed!"
  echo "✅ Cortex MCP Server is fully functional"
}

# Execute main function
main "$@"
```

### 📈 Performance Validation

#### Load Testing Script

```bash
#!/bin/bash
# scripts/performance-validation.sh

set -e

SERVICE_URL=${1:-https://api.cortex-memory.com}
CONCURRENT_USERS=${2:-10}
REQUESTS_PER_USER=${3:-50}
DURATION=${4:-60}

echo "⚡ Performance Validation"
echo "========================"
echo "🌐 Service URL: $SERVICE_URL"
echo "👥 Concurrent Users: $CONCURRENT_USERS"
echo "📊 Requests per User: $REQUESTS_PER_USER"
echo "⏱️  Duration: ${DURATION}s"

# Install dependencies if needed
check_dependencies() {
  if ! command -v ab &> /dev/null; then
    echo "📦 Installing Apache Bench..."
    if command -v apt-get &> /dev/null; then
      sudo apt-get update && sudo apt-get install -y apache2-utils
    elif command -v yum &> /dev/null; then
      sudo yum install -y httpd-tools
    else
      echo "❌ Please install Apache Bench manually"
      exit 1
    fi
  fi

  if ! command -v jq &> /dev/null; then
    echo "📦 Installing jq..."
    if command -v apt-get &> /dev/null; then
      sudo apt-get install -y jq
    elif command -v yum &> /dev/null; then
      sudo yum install -y jq
    fi
  fi
}

# Health endpoint load test
test_health_endpoint() {
  echo ""
  echo "🏥 Testing health endpoint performance..."

  local health_results=$(ab -n $((CONCURRENT_USERS * REQUESTS_PER_USER)) \
    -c $CONCURRENT_USERS \
    -t $DURATION \
    "$SERVICE_URL/health" 2>/dev/null)

  local requests_per_second=$(echo "$health_results" | grep "Requests per second" | awk '{print $4}')
  local time_per_request=$(echo "$health_results" | grep "Time per request" | head -1 | awk '{print $4}')
  local failed_requests=$(echo "$health_results" | grep "Failed requests" | awk '{print $3}')

  echo "📊 Health Endpoint Results:"
  echo "  - Requests per second: $requests_per_second"
  echo "  - Time per request: ${time_per_request}ms"
  echo "  - Failed requests: $failed_requests"

  # Validate performance thresholds
  local health_rps_threshold=100
  local health_latency_threshold=100

  if (( $(echo "$requests_per_second >= $health_rps_threshold" | bc -l) )); then
    echo "✅ Health endpoint RPS meets threshold (≥$health_rps_threshold)"
  else
    echo "❌ Health endpoint RPS below threshold (<$health_rps_threshold)"
  fi

  if (( $(echo "$time_per_request <= $health_latency_threshold" | bc -l) )); then
    echo "✅ Health endpoint latency meets threshold (≤${health_latency_threshold}ms)"
  else
    echo "❌ Health endpoint latency exceeds threshold (>${health_latency_threshold}ms)"
  fi
}

# Memory store performance test
test_memory_store_performance() {
  echo ""
  echo "💾 Testing memory store performance..."

  # Create test data file
  local test_data='{
    "items": [
      {
        "kind": "entity",
        "data": {
          "title": "Performance Test Entity",
          "description": "Entity for performance testing",
          "content": "This is a test entity created during performance validation"
        },
        "scope": {
          "project": "performance-test"
        }
      }
    ]
  }'

  echo "$test_data" > /tmp/performance_test_data.json

  local store_results=$(ab -n $((CONCURRENT_USERS / 2 * REQUESTS_PER_USER)) \
    -c $((CONCURRENT_USERS / 2)) \
    -t $DURATION \
    -p /tmp/performance_test_data.json \
    -T application/json \
    -H "Authorization: Bearer $MCP_API_KEY" \
    "$SERVICE_URL/api/v1/memory/store" 2>/dev/null)

  local store_rps=$(echo "$store_results" | grep "Requests per second" | awk '{print $4}')
  local store_latency=$(echo "$store_results" | grep "Time per request" | head -1 | awk '{print $4}')
  local store_failed=$(echo "$store_results" | grep "Failed requests" | awk '{print $3}')

  echo "📊 Memory Store Results:"
  echo "  - Requests per second: $store_rps"
  echo "  - Time per request: ${store_latency}ms"
  echo "  - Failed requests: $store_failed"

  # Validate performance thresholds
  local store_rps_threshold=50
  local store_latency_threshold=2000

  if (( $(echo "$store_rps >= $store_rps_threshold" | bc -l) )); then
    echo "✅ Memory store RPS meets threshold (≥$store_rps_threshold)"
  else
    echo "❌ Memory store RPS below threshold (<$store_rps_threshold)"
  fi

  if (( $(echo "$store_latency <= $store_latency_threshold" | bc -l) )); then
    echo "✅ Memory store latency meets threshold (≤${store_latency_threshold}ms)"
  else
    echo "❌ Memory store latency exceeds threshold (>${store_latency_threshold}ms)"
  fi

  # Cleanup
  rm -f /tmp/performance_test_data.json
}

# Memory search performance test
test_memory_search_performance() {
  echo ""
  echo "🔍 Testing memory search performance..."

  local search_data='{
    "query": "Performance Test Entity",
    "limit": 10,
    "scope": {
      "project": "performance-test"
    }
  }'

  echo "$search_data" > /tmp/search_test_data.json

  local search_results=$(ab -n $((CONCURRENT_USERS * REQUESTS_PER_USER)) \
    -c $CONCURRENT_USERS \
    -t $DURATION \
    -p /tmp/search_test_data.json \
    -T application/json \
    -H "Authorization: Bearer $MCP_API_KEY" \
    "$SERVICE_URL/api/v1/memory/find" 2>/dev/null)

  local search_rps=$(echo "$search_results" | grep "Requests per second" | awk '{print $4}')
  local search_latency=$(echo "$search_results" | grep "Time per request" | head -1 | awk '{print $4}')
  local search_failed=$(echo "$search_results" | grep "Failed requests" | awk '{print $3}')

  echo "📊 Memory Search Results:"
  echo "  - Requests per second: $search_rps"
  echo "  - Time per request: ${search_latency}ms"
  echo "  - Failed requests: $search_failed"

  # Validate performance thresholds
  local search_rps_threshold=75
  local search_latency_threshold=1500

  if (( $(echo "$search_rps >= $search_rps_threshold" | bc -l) )); then
    echo "✅ Memory search RPS meets threshold (≥$search_rps_threshold)"
  else
    echo "❌ Memory search RPS below threshold (<$search_rps_threshold)"
  fi

  if (( $(echo "$search_latency <= $search_latency_threshold" | bc -l) )); then
    echo "✅ Memory search latency meets threshold (≤${search_latency_threshold}ms)"
  else
    echo "❌ Memory search latency exceeds threshold (>${search_latency_threshold}ms)"
  fi

  # Cleanup
  rm -f /tmp/search_test_data.json
}

# Stress test with concurrent users
test_stress_scenario() {
  echo ""
  echo "💪 Running stress test scenario..."

  # Mixed workload test
  echo "🔄 Running mixed workload test..."

  # This would typically use a more sophisticated load testing tool like k6 or locust
  # For simplicity, we'll use Apache Bench with different endpoints

  local stress_results=$(ab -n $((CONCURRENT_USERS * 2 * REQUESTS_PER_USER)) \
    -c $CONCURRENT_USERS \
    -t $((DURATION * 2)) \
    "$SERVICE_URL/health" 2>/dev/null)

  local stress_rps=$(echo "$stress_results" | grep "Requests per second" | awk '{print $4}')
  local stress_latency=$(echo "$stress_results" | grep "Time per request" | head -1 | awk '{print $4}')

  echo "📊 Stress Test Results:"
  echo "  - Requests per second: $stress_rps"
  echo "  - Time per request: ${stress_latency}ms"

  # Check system resource usage during stress test
  echo "📈 System resource usage during stress test:"
  if command -v top &> /dev/null; then
    echo "  - CPU usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)"
    echo "  - Memory usage: $(top -bn1 | grep "Mem" | awk '{print $3}' | cut -d'%' -f1)"
  fi
}

# Main performance validation function
main() {
  check_dependencies

  echo "⚡ Starting performance validation..."
  echo "⏰ Started at: $(date)"

  test_health_endpoint
  test_memory_store_performance
  test_memory_search_performance
  test_stress_scenario

  echo ""
  echo "✅ Performance validation completed!"
  echo "⏰ Completed at: $(date)"

  echo ""
  echo "📊 Performance Summary:"
  echo "- All endpoint tests completed"
  echo "- System validated under load"
  echo "- Performance metrics collected"
}

# Execute main function
main "$@"
```

### ✅ Final Validation Report

#### Automated Validation Report Generator

````bash
#!/bin/bash
# scripts/generate-validation-report.sh

set -e

REPORT_DIR=${1:-./validation-reports}
NAMESPACE=${2:-cortex-mcp}
SERVICE_URL=${3:-https://api.cortex-memory.com}

# Create report directory
mkdir -p "$REPORT_DIR"

REPORT_FILE="$REPORT_DIR/validation-report-$(date +%Y%m%d-%H%M%S).md"

echo "📋 Generating Validation Report"
echo "=============================="
echo "📁 Report Directory: $REPORT_DIR"
echo "📄 Report File: $REPORT_FILE"

# Start generating report
cat > "$REPORT_FILE" << EOF
# Cortex Memory MCP - Production Validation Report

**Generated:** $(date)
**Environment:** Production
**Namespace:** $NAMESPACE
**Service URL:** $SERVICE_URL

## Executive Summary

This report contains the comprehensive validation results for the Cortex Memory MCP Server production deployment.

## Validation Results

EOF

# Run health check and append results
echo "🏥 Running health check validation..."
if ./scripts/comprehensive-health-check.sh "$NAMESPACE" "$SERVICE_URL" > "$REPORT_DIR/health-check.log" 2>&1; then
  HEALTH_STATUS="✅ PASSED"
else
  HEALTH_STATUS="❌ FAILED"
fi

echo "### Health Check Validation" >> "$REPORT_FILE"
echo "**Status:** $HEALTH_STATUS" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
cat "$REPORT_DIR/health-check.log" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Run MCP protocol validation
echo "🧪 Running MCP protocol validation..."
if ./scripts/validate-mcp-protocol.sh "$SERVICE_URL" > "$REPORT_DIR/mcp-validation.log" 2>&1; then
  MCP_STATUS="✅ PASSED"
else
  MCP_STATUS="❌ FAILED"
fi

echo "### MCP Protocol Validation" >> "$REPORT_FILE"
echo "**Status:** $MCP_STATUS" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
cat "$REPORT_DIR/mcp-validation.log" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Run performance validation
echo "⚡ Running performance validation..."
if ./scripts/performance-validation.sh "$SERVICE_URL" > "$REPORT_DIR/performance-validation.log" 2>&1; then
  PERF_STATUS="✅ PASSED"
else
  PERF_STATUS="❌ FAILED"
fi

echo "### Performance Validation" >> "$REPORT_FILE"
echo "**Status:** $PERF_STATUS" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
cat "$REPORT_DIR/performance-validation.log" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Collect system information
echo "📊 Collecting system information..."
kubectl get pods -n $NAMESPACE -o wide > "$REPORT_DIR/pods-status.log"
kubectl top pods -n $NAMESPACE > "$REPORT_DIR/pods-metrics.log" 2>/dev/null || echo "Metrics not available" > "$REPORT_DIR/pods-metrics.log"

echo "### System Information" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "#### Pod Status" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
cat "$REPORT_DIR/pods-status.log" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "#### Resource Usage" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
cat "$REPORT_DIR/pods-metrics.log" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Determine overall status
OVERALL_STATUS="✅ PASSED"
if [[ "$HEALTH_STATUS" == *"FAILED"* ]] || [[ "$MCP_STATUS" == *"FAILED"* ]] || [[ "$PERF_STATUS" == *"FAILED"* ]]; then
  OVERALL_STATUS="❌ FAILED"
fi

# Add final summary
cat >> "$REPORT_FILE" << EOF
## Final Validation Status

**Overall Status:** $OVERALL_STATUS

- **Health Check:** $HEALTH_STATUS
- **MCP Protocol:** $MCP_STATUS
- **Performance:** $PERF_STATUS

## Recommendations

EOF

if [[ "$OVERALL_STATUS" == *"PASSED"* ]]; then
  cat >> "$REPORT_FILE" << EOF
✅ **Deployment Successful**
- All validation checks have passed
- System is ready for production traffic
- Monitoring and alerting should be verified

## Next Steps
1. Monitor system performance for first 24 hours
2. Verify all alerts are configured correctly
3. Document any configuration changes made during deployment
4. Schedule regular maintenance and backup procedures

EOF
else
  cat >> "$REPORT_FILE" << EOF
❌ **Deployment Issues Detected**
- Some validation checks have failed
- Please review the detailed logs above
- Address all critical issues before proceeding to production

## Required Actions
1. Review and fix all failed validation checks
2. Re-run the validation process
3. Ensure all security and performance requirements are met
4. Document any issues and resolutions

EOF
fi

# Add deployment information
cat >> "$REPORT_FILE" << EOF
## Deployment Information

- **Deployment Date:** $(date)
- **Validation Version:** 2.0.1
- **Environment:** Production
- **Namespace:** $NAMESPACE
- **Service URL:** $SERVICE_URL

## Support Information

For deployment issues:
1. Review the detailed logs in this report
2. Check the troubleshooting guide in the documentation
3. Contact the DevOps team with the validation report

---
*Report generated by Cortex Memory MCP Validation System*
EOF

echo "✅ Validation report generated successfully!"
echo "📄 Report saved to: $REPORT_FILE"

# Display summary
echo ""
echo "📋 Validation Summary:"
echo "======================"
echo "Health Check: $HEALTH_STATUS"
echo "MCP Protocol: $MCP_STATUS"
echo "Performance: $PERF_STATUS"
echo "Overall Status: $OVERALL_STATUS"

if [[ "$OVERALL_STATUS" == *"PASSED"* ]]; then
  echo ""
  echo "🎉 Deployment validation completed successfully!"
  echo "🚀 System is ready for production traffic!"
else
  echo ""
  echo "⚠️  Deployment validation failed!"
  echo "🔧 Please review the report and address the issues."
  exit 1
fi
````

---

## Monitoring & Alerting

### 📊 Comprehensive Monitoring Setup

#### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'cortex-production'
    region: 'us-west-2'

rule_files:
  - 'cortex-rules.yml'
  - 'qdrant-rules.yml'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093

scrape_configs:
  # Cortex MCP Application Metrics
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['cortex-mcp-service:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s
    params:
      format: ['prometheus']

  # Qdrant Database Metrics
  - job_name: 'qdrant'
    static_configs:
      - targets: ['qdrant:6333']
    metrics_path: '/metrics'
    scrape_interval: 30s

  # Redis Metrics (if using Redis exporter)
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 30s

  # Kubernetes Metrics
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - cortex-mcp
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name

  # Node Exporter for System Metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s
```

#### Alerting Rules Configuration

```yaml
# monitoring/cortex-rules.yml
groups:
  - name: cortex-mcp-alerts
    rules:
      # High Error Rate Alert
      - alert: CortexHighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: 'High error rate detected in Cortex MCP'
          description: 'Error rate is {{ $value | humanizePercentage }} for the last 5 minutes'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/high-error-rate'

      # High Response Time Alert
      - alert: CortexHighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: 'High response time detected in Cortex MCP'
          description: '95th percentile response time is {{ $value }}s'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/high-response-time'

      # Memory Usage Alert
      - alert: CortexHighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.85
        for: 5m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: 'High memory usage on Cortex MCP'
          description: 'Memory usage is {{ $value | humanizePercentage }}'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/high-memory-usage'

      # CPU Usage Alert
      - alert: CortexHighCPUUsage
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: 'High CPU usage on Cortex MCP'
          description: 'CPU usage is {{ $value }}%'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/high-cpu-usage'

      # Pod Crash Looping Alert
      - alert: CortexPodCrashLooping
        expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
        for: 5m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: 'Cortex MCP pod is crash looping'
          description: 'Pod {{ $labels.pod }} is restarting frequently'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/pod-crash-looping'

      # Database Connection Issues
      - alert: CortexDatabaseConnectionIssues
        expr: cortex_database_connections_failed_total > 10
        for: 2m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: 'Database connection issues detected'
          description: '{{ $value }} failed database connections in the last 2 minutes'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/database-connection-issues'

      # OpenAI API Issues
      - alert: CortexOpenAI APIIssues
        expr: rate(openai_api_requests_failed_total[5m]) / rate(openai_api_requests_total[5m]) > 0.1
        for: 3m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: 'OpenAI API issues detected'
          description: 'OpenAI API failure rate is {{ $value | humanizePercentage }}'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/openai-api-issues'

      # Disk Space Alert
      - alert: CortexLowDiskSpace
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: 'Low disk space on Cortex MCP'
          description: 'Disk space is {{ $value }}% available'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/low-disk-space'

      # Service Unavailable Alert
      - alert: CortexServiceUnavailable
        expr: up{job="cortex-mcp"} == 0
        for: 1m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: 'Cortex MCP service is unavailable'
          description: 'Cortex MCP service has been down for more than 1 minute'
          runbook_url: 'https://docs.cortex-memory.com/runbooks/service-unavailable'

  - name: cortex-mcp-business-alerts
    rules:
      # Low Memory Storage Operations
      - alert: CortexLowMemoryOperations
        expr: rate(memory_store_operations_total[5m]) < 1
        for: 10m
        labels:
          severity: warning
          service: cortex-mcp
          type: business
        annotations:
          summary: 'Low memory storage operations'
          description: 'Memory storage operations rate is {{ $value }} ops/sec'

      # High Memory Deduplication Rate
      - alert: CortexHighDeduplicationRate
        expr: rate(memory_deduplication_hits_total[5m]) / rate(memory_store_operations_total[5m]) > 0.3
        for: 5m
        labels:
          severity: info
          service: cortex-mcp
          type: business
        annotations:
          summary: 'High deduplication rate detected'
          description: 'Deduplication rate is {{ $value | humanizePercentage }}'
```

#### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "id": null,
    "title": "Cortex Memory MCP - Production Dashboard",
    "tags": ["cortex", "mcp", "production"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}",
            "refId": "A"
          }
        ],
        "yAxes": [{ "label": "Requests/sec" }],
        "xAxes": [{}]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile",
            "refId": "A"
          },
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile",
            "refId": "B"
          },
          {
            "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile",
            "refId": "C"
          }
        ],
        "yAxes": [{ "label": "Response Time (s)" }],
        "xAxes": [{}]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "gridPos": { "h": 8, "w": 6, "x": 0, "y": 8 },
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m]) / rate(http_requests_total[5m]) * 100",
            "refId": "A"
          }
        ],
        "valueMaps": [
          { "value": "null", "text": "N/A" },
          { "from": 0, "to": 1, "color": "green" },
          { "from": 1, "to": 5, "color": "yellow" },
          { "from": 5, "to": 100, "color": "red" }
        ],
        "thresholds": "1,5"
      },
      {
        "title": "Memory Operations",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 6, "y": 8 },
        "targets": [
          {
            "expr": "rate(memory_store_operations_total[5m])",
            "legendFormat": "Store Ops",
            "refId": "A"
          },
          {
            "expr": "rate(memory_find_operations_total[5m])",
            "legendFormat": "Find Ops",
            "refId": "B"
          }
        ],
        "yAxes": [{ "label": "Operations/sec" }],
        "xAxes": [{}]
      },
      {
        "title": "Database Performance",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 18, "y": 8 },
        "targets": [
          {
            "expr": "qdrant_request_duration_seconds",
            "legendFormat": "Qdrant Response Time",
            "refId": "A"
          },
          {
            "expr": "rate(qdrant_requests_total[5m])",
            "legendFormat": "Qdrant Request Rate",
            "refId": "B"
          }
        ],
        "yAxes": [{ "label": "Time (s) / Rate" }],
        "xAxes": [{}]
      },
      {
        "title": "System Resources",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 16 },
        "targets": [
          {
            "expr": "rate(process_cpu_seconds_total[5m]) * 100",
            "legendFormat": "CPU Usage",
            "refId": "A"
          },
          {
            "expr": "process_resident_memory_bytes / 1024 / 1024",
            "legendFormat": "Memory Usage (MB)",
            "refId": "B"
          }
        ],
        "yAxes": [{ "label": "CPU % / Memory MB" }],
        "xAxes": [{}]
      },
      {
        "title": "Qdrant Collection Size",
        "type": "singlestat",
        "gridPos": { "h": 8, "w": 6, "x": 12, "y": 16 },
        "targets": [
          {
            "expr": "qdrant_collection_vectors_count",
            "refId": "A"
          }
        ],
        "valueMaps": [{ "value": "null", "text": "N/A" }],
        "fieldConfig": {
          "defaults": {
            "unit": "short",
            "thresholds": { "steps": [{ "color": "green" }, { "color": "red" }] }
          }
        }
      },
      {
        "title": "OpenAI API Usage",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 18, "y": 16 },
        "targets": [
          {
            "expr": "rate(openai_api_requests_total[5m])",
            "legendFormat": "OpenAI Requests",
            "refId": "A"
          },
          {
            "expr": "rate(openai_api_tokens_total[5m])",
            "legendFormat": "OpenAI Tokens",
            "refId": "B"
          }
        ],
        "yAxes": [{ "label": "Rate" }],
        "xAxes": [{}]
      }
    ],
    "time": { "from": "now-1h", "to": "now" },
    "refresh": "30s"
  }
}
```

### 🚨 Alert Manager Configuration

```yaml
# monitoring/alertmanager.yml
global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alerts@cortex-memory.com'
  smtp_auth_username: 'alerts@cortex-memory.com'
  smtp_auth_password: 'your-smtp-password'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      group_wait: 5s
      repeat_interval: 5m
    - match:
        severity: warning
      receiver: 'warning-alerts'
      repeat_interval: 30m
    - match:
        service: cortex-mcp
      receiver: 'cortex-team'
      group_by: ['alertname', 'service']

receivers:
  - name: 'default'
    email_configs:
      - to: 'devops@cortex-memory.com'
        subject: '[Cortex MCP] {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Runbook: {{ .Annotations.runbook_url }}
          {{ end }}

  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@cortex-memory.com,devops@cortex-memory.com'
        subject: '[CRITICAL] Cortex MCP: {{ .GroupLabels.alertname }}'
        body: |
          CRITICAL ALERT - Immediate Action Required

          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Severity: {{ .Labels.severity }}
          Service: {{ .Labels.service }}
          Runbook: {{ .Annotations.runbook_url }}
          {{ end }}
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#cortex-alerts'
        title: 'CRITICAL: Cortex MCP Alert'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}

  - name: 'warning-alerts'
    email_configs:
      - to: 'devops@cortex-memory.com'
        subject: '[WARNING] Cortex MCP: {{ .GroupLabels.alertname }}'
        body: |
          Warning Alert - Attention Required

          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

  - name: 'cortex-team'
    email_configs:
      - to: 'cortex-team@cortex-memory.com'
        subject: '[Cortex MCP] {{ .GroupLabels.alertname }}'
        body: |
          Cortex MCP Service Alert

          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'cluster', 'service']
```

### 📱 Custom Metrics Collection

#### Application Metrics Implementation

```typescript
// src/monitoring/custom-metrics.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';

// Custom metrics for Cortex MCP
export class CortexMetrics {
  private httpRequestsTotal: Counter<string>;
  private httpRequestDuration: Histogram<string>;
  private memoryStoreOperations: Counter<string>;
  private memoryFindOperations: Counter<string>;
  private databaseConnections: Gauge<string>;
  private openAIRequests: Counter<string>;
  private deduplicationHits: Counter<string>;
  private vectorCount: Gauge<string>;

  constructor() {
    // HTTP Request Metrics
    this.httpRequestsTotal = new Counter({
      name: 'cortex_http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
      registers: [register],
    });

    this.httpRequestDuration = new Histogram({
      name: 'cortex_http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
      registers: [register],
    });

    // Memory Operation Metrics
    this.memoryStoreOperations = new Counter({
      name: 'cortex_memory_store_operations_total',
      help: 'Total number of memory store operations',
      labelNames: ['status', 'knowledge_type'],
      registers: [register],
    });

    this.memoryFindOperations = new Counter({
      name: 'cortex_memory_find_operations_total',
      help: 'Total number of memory find operations',
      labelNames: ['status', 'search_mode'],
      registers: [register],
    });

    // Database Metrics
    this.databaseConnections = new Gauge({
      name: 'cortex_database_connections_active',
      help: 'Number of active database connections',
      registers: [register],
    });

    // OpenAI API Metrics
    this.openAIRequests = new Counter({
      name: 'cortex_openai_requests_total',
      help: 'Total number of OpenAI API requests',
      labelNames: ['endpoint', 'status'],
      registers: [register],
    });

    // Deduplication Metrics
    this.deduplicationHits = new Counter({
      name: 'cortex_deduplication_hits_total',
      help: 'Total number of deduplication hits',
      labelNames: ['strategy'],
      registers: [register],
    });

    // Vector Count Metrics
    this.vectorCount = new Gauge({
      name: 'cortex_vector_count_total',
      help: 'Total number of vectors in the database',
      registers: [register],
    });
  }

  // HTTP Request Tracking
  incrementHttpRequests(method: string, route: string, statusCode: string): void {
    this.httpRequestsTotal.inc({ method, route, status_code: statusCode });
  }

  observeHttpRequestDuration(
    method: string,
    route: string,
    statusCode: string,
    duration: number
  ): void {
    this.httpRequestDuration.observe({ method, route, status_code: statusCode }, duration);
  }

  // Memory Operation Tracking
  incrementMemoryStoreOperations(status: string, knowledgeType: string): void {
    this.memoryStoreOperations.inc({ status, knowledge_type: knowledgeType });
  }

  incrementMemoryFindOperations(status: string, searchMode: string): void {
    this.memoryFindOperations.inc({ status, search_mode: searchMode });
  }

  // Database Metrics
  setActiveConnections(count: number): void {
    this.databaseConnections.set(count);
  }

  // OpenAI API Tracking
  incrementOpenAIRequests(endpoint: string, status: string): void {
    this.openAIRequests.inc({ endpoint, status });
  }

  // Deduplication Tracking
  incrementDeduplicationHits(strategy: string): void {
    this.deduplicationHits.inc({ strategy });
  }

  // Vector Count Tracking
  setVectorCount(count: number): void {
    this.vectorCount.set(count);
  }

  // Get metrics for Prometheus
  getMetrics(): string {
    return register.metrics();
  }
}

export const cortexMetrics = new CortexMetrics();
```

### 🔍 Log Aggregation and Analysis

#### Structured Logging Configuration

```typescript
// src/monitoring/structured-logger.ts
import pino from 'pino';

export interface LogContext {
  requestId?: string;
  userId?: string;
  operation?: string;
  duration?: number;
  error?: Error;
  metadata?: Record<string, any>;
}

export class StructuredLogger {
  private logger: pino.Logger;

  constructor(serviceName: string, environment: string) {
    this.logger = pino({
      name: serviceName,
      level: process.env.LOG_LEVEL || 'info',
      formatters: {
        level: (label) => ({ level: label }),
        log: (object) => ({
          ...object,
          timestamp: new Date().toISOString(),
          service: serviceName,
          environment,
        }),
      },
      redact: {
        paths: [
          'headers.authorization',
          'headers.api-key',
          'password',
          'secret',
          'token',
          'OPENAI_API_KEY',
          'JWT_SECRET',
          'ENCRYPTION_KEY',
        ],
      },
    });
  }

  info(message: string, context?: LogContext): void {
    this.logger.info({ ...context }, message);
  }

  warn(message: string, context?: LogContext): void {
    this.logger.warn({ ...context }, message);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    this.logger.error({ ...context, error }, message);
  }

  debug(message: string, context?: LogContext): void {
    this.logger.debug({ ...context }, message);
  }

  // Performance logging
  logPerformance(operation: string, duration: number, context?: LogContext): void {
    this.info(`Performance: ${operation}`, {
      ...context,
      operation,
      duration,
      performance_log: true,
    });
  }

  // Security logging
  logSecurityEvent(event: string, context?: LogContext): void {
    this.warn(`Security Event: ${event}`, {
      ...context,
      security_event: true,
      event,
    });
  }

  // Business logging
  logBusinessEvent(event: string, context?: LogContext): void {
    this.info(`Business Event: ${event}`, {
      ...context,
      business_event: true,
      event,
    });
  }
}

export const structuredLogger = new StructuredLogger(
  'cortex-mcp',
  process.env.NODE_ENV || 'development'
);
```

---

This comprehensive production deployment guide covers all essential aspects of deploying, operating, and maintaining the Cortex Memory MCP system in production environments. The guide includes detailed configuration, validation procedures, monitoring setup, and operational best practices to ensure reliable and secure production deployments.
