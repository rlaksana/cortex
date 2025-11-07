# Qdrant Health & Tunables Guide

This comprehensive guide covers Qdrant vector database health monitoring, configuration parameters, performance tuning, and operational procedures for the MCP Cortex system.

## Table of Contents

1. [Health Check System Architecture](#health-check-system-architecture)
2. [Health Check Endpoints](#health-check-endpoints)
3. [Configuration Parameters](#configuration-parameters)
4. [Environment-Specific Settings](#environment-specific-settings)
5. [Performance Tuning Guidelines](#performance-tuning-guidelines)
6. [Operational Runbook](#operational-runbook)
7. [Troubleshooting Procedures](#troubleshooting-procedures)
8. [Best Practices](#best-practices)

---

## Health Check System Architecture

### Overview

The Qdrant health monitoring system provides comprehensive monitoring of the vector database with multiple layers of health checks, performance metrics, and automated recovery detection.

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                   Qdrant Health Monitoring                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Health Probe    │  │ Circuit         │  │ Performance │ │
│  │ Service         │  │ Breaker         │  │ Collector   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│           │                     │                     │     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Connection      │  │ Metrics         │  │ Alert       │ │
│  │ Pool Monitor    │  │ Aggregator      │  │ Manager     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│           │                     │                     │     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Health Dashboard API                       │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Classes

- **QdrantHealthMonitor**: Main health monitoring orchestrator
- **QdrantHealthProbe**: Core health check service with circuit breaker patterns
- **QdrantAdapter**: Database adapter with built-in monitoring and retry logic
- **CircuitBreaker**: Fault tolerance with automatic recovery detection

---

## Health Check Endpoints

### Primary Health Check Endpoint

**Location**: `src/monitoring/qdrant-health-monitor.ts`

**Endpoints Available**:

1. **Basic Health Check**

   ```typescript
   // Perform basic connectivity check
   const health = await qdrantMonitor.performHealthCheck();
   // Returns: QdrantHealthCheckResult
   ```

2. **Comprehensive Health Check**

   ```typescript
   // Full system health with metrics
   const comprehensive = await qdrantMonitor.performComprehensiveHealthCheck();
   // Returns: Detailed system status with performance metrics
   ```

3. **Real-time Health Status**
   ```typescript
   // Get current health status
   const status = qdrantMonitor.getHealthStatus();
   // Returns: Current status, last check time, metrics
   ```

### Health Status Values

| Status  | Description          | Action Required         |
| ------- | -------------------- | ----------------------- |
| `green` | Healthy              | None                    |
| `amber` | Degraded performance | Monitor closely         |
| `red`   | Critical issues      | Immediate investigation |

### Health Check Components

1. **Connectivity Checks**
   - TCP connection test
   - HTTP API response validation
   - Authentication verification
   - Cluster connectivity (if applicable)

2. **Performance Metrics**
   - Response time measurement
   - Request rate monitoring
   - Error rate tracking
   - Resource usage statistics

3. **Database Health**
   - Collection availability
   - Index status verification
   - Vector count accuracy
   - Storage space monitoring

### Monitoring Integration Points

```typescript
// Health check integration in main application
// src/monitoring/health-check-service.ts

export interface HealthCheckConfig {
  // Check intervals
  healthCheckIntervalMs: number;
  metricsCollectionIntervalMs: number;
  connectionTestIntervalMs: number;

  // Performance thresholds
  thresholds: {
    responseTimeWarning: number; // Default: 1000ms
    responseTimeCritical: number; // Default: 5000ms
    errorRateWarning: number; // Default: 5%
    errorRateCritical: number; // Default: 15%
    connectionTimeWarning: number; // Default: 500ms
    connectionTimeCritical: number; // Default: 2000ms
  };
}
```

---

## Configuration Parameters

### Core Qdrant Configuration

| Parameter                  | Type   | Default                 | Description                       |
| -------------------------- | ------ | ----------------------- | --------------------------------- |
| `QDRANT_URL`               | string | `http://localhost:6333` | Qdrant server URL                 |
| `QDRANT_API_KEY`           | string | -                       | API authentication key (optional) |
| `QDRANT_TIMEOUT`           | number | `30000`                 | Request timeout in milliseconds   |
| `QDRANT_COLLECTION_PREFIX` | string | `cortex`                | Collection name prefix            |

### Connection Pool Configuration

| Parameter                   | Type   | Default              | Description                      |
| --------------------------- | ------ | -------------------- | -------------------------------- |
| `QDRANT_POOL_MIN`           | number | Environment-specific | Minimum connection pool size     |
| `QDRANT_POOL_MAX`           | number | Environment-specific | Maximum connection pool size     |
| `QDRANT_IDLE_TIMEOUT_MS`    | number | `30000`              | Connection idle timeout          |
| `QDRANT_CONNECTION_TIMEOUT` | number | `10000`              | Connection establishment timeout |
| `QDRANT_MAX_CONNECTIONS`    | number | `10`                 | Maximum concurrent connections   |

### Vector Configuration

| Parameter              | Type   | Default                  | Description                                      |
| ---------------------- | ------ | ------------------------ | ------------------------------------------------ |
| `VECTOR_SIZE`          | number | `1536`                   | Vector dimension size                            |
| `VECTOR_DISTANCE`      | string | `Cosine`                 | Distance metric (Cosine, Euclid, Dot, Manhattan) |
| `EMBEDDING_MODEL`      | string | `text-embedding-ada-002` | OpenAI embedding model                           |
| `EMBEDDING_BATCH_SIZE` | number | `10`                     | Batch size for embedding operations              |

### Circuit Breaker Configuration

| Parameter                             | Type    | Default | Description                           |
| ------------------------------------- | ------- | ------- | ------------------------------------- |
| `CIRCUIT_BREAKER_ENABLED`             | boolean | `true`  | Enable circuit breaker                |
| `CIRCUIT_BREAKER_THRESHOLD`           | number  | `5`     | Failure threshold for opening circuit |
| `CIRCUIT_BREAKER_TIMEOUT`             | number  | `60000` | Recovery timeout in milliseconds      |
| `CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS` | number  | `3`     | Max calls in half-open state          |

### Health Check Configuration

| Parameter                        | Type    | Default | Description                 |
| -------------------------------- | ------- | ------- | --------------------------- |
| `HEALTH_CHECK_INTERVAL_MS`       | number  | `30000` | Health check interval       |
| `METRICS_COLLECTION_INTERVAL_MS` | number  | `60000` | Metrics collection interval |
| `ENABLE_HEALTH_CHECKS`           | boolean | `true`  | Enable health checks        |
| `ENABLE_METRICS_COLLECTION`      | boolean | `true`  | Enable metrics collection   |

---

## Environment-Specific Settings

### Development Environment

```typescript
// Development configuration
{
  QDRANT_POOL_MIN: 2,
  QDRANT_POOL_MAX: 10,
  QDRANT_TIMEOUT: 30000,
  BATCH_SIZE: 50,
  ENABLE_HEALTH_CHECKS: true,
  ENABLE_METRICS_COLLECTION: true,
  LOG_LEVEL: 'debug'
}
```

**Development Characteristics**:

- Smaller connection pools for resource efficiency
- Detailed logging for debugging
- Frequent health checks for immediate feedback
- Lower batch sizes for faster iteration

### Test Environment

```typescript
// Test configuration
{
  QDRANT_POOL_MIN: 1,
  QDRANT_POOL_MAX: 5,
  QDRANT_TIMEOUT: 10000,
  BATCH_SIZE: 10,
  ENABLE_HEALTH_CHECKS: false,
  ENABLE_METRICS_COLLECTION: false,
  LOG_LEVEL: 'error'
}
```

**Test Characteristics**:

- Minimal resource usage
- Disabled health checks for faster test execution
- Minimal logging for cleaner test output
- Small batch sizes for predictable test behavior

### Staging Environment

```typescript
// Staging configuration
{
  QDRANT_POOL_MIN: 3,
  QDRANT_POOL_MAX: 15,
  QDRANT_TIMEOUT: 30000,
  BATCH_SIZE: 75,
  ENABLE_HEALTH_CHECKS: true,
  ENABLE_METRICS_COLLECTION: true,
  LOG_LEVEL: 'info'
}
```

**Staging Characteristics**:

- Production-like configuration for validation
- Full monitoring enabled for performance testing
- Moderate connection pools for resource balance
- Production-like timeouts and batch sizes

### Production Environment

```typescript
// Production configuration
{
  QDRANT_POOL_MIN: 5,
  QDRANT_POOL_MAX: 20,
  QDRANT_TIMEOUT: 30000,
  BATCH_SIZE: 100,
  ENABLE_HEALTH_CHECKS: true,
  ENABLE_METRICS_COLLECTION: true,
  LOG_LEVEL: 'warn'
}
```

**Production Characteristics**:

- Optimized for performance and reliability
- Larger connection pools for high throughput
- Comprehensive monitoring and alerting
- Conservative logging to reduce noise

---

## Performance Tuning Guidelines

### Connection Pool Optimization

#### Pool Size Calculation

```typescript
// Formula for optimal pool size
optimalPoolSize = (cpu_cores * 2) + effective_spindle_count

// Example for 8-core system with SSD storage
optimalPoolSize = (8 * 2) + 1 = 17
// Recommended range: 15-20 connections
```

#### Pool Tuning Recommendations

| Environment | CPU Cores | Storage Type | Min Pool | Max Pool | Rationale             |
| ----------- | --------- | ------------ | -------- | -------- | --------------------- |
| Development | 4-8       | SSD          | 2        | 10       | Resource conservation |
| Testing     | 2-4       | SSD          | 1        | 5        | Minimal footprint     |
| Staging     | 8-16      | SSD/NVMe     | 3        | 15       | Production simulation |
| Production  | 16+       | NVMe         | 5        | 20+      | High throughput       |

### Timeout Configuration

#### Request Timeouts

```typescript
// Recommended timeout hierarchy
{
  connectionTimeout: 10000,    // 10 seconds for TCP connection
  requestTimeout: 30000,       // 30 seconds for API requests
  healthCheckTimeout: 5000,    // 5 seconds for health checks
  circuitBreakerTimeout: 60000 // 60 seconds for circuit recovery
}
```

#### Timeout Tuning by Operation

| Operation Type        | Recommended Timeout | Rationale                   |
| --------------------- | ------------------- | --------------------------- |
| Health Check          | 5-10 seconds        | Quick status verification   |
| Vector Search         | 10-30 seconds       | Depends on query complexity |
| Vector Upsert         | 30-60 seconds       | Depends on batch size       |
| Collection Operations | 60-120 seconds      | Administrative operations   |

### Circuit Breaker Tuning

#### Threshold Configuration

```typescript
// Production circuit breaker settings
{
  failureThreshold: 5,           // Open after 5 consecutive failures
  recoveryTimeout: 60000,        // Wait 60 seconds before retry
  halfOpenMaxCalls: 3,           // Test with 3 calls in half-open
  monitoringWindowMs: 300000,    // 5-minute monitoring window
  successThreshold: 3            // Close after 3 consecutive successes
}
```

#### Circuit Breaker Strategy

| Scenario              | Failure Threshold | Recovery Timeout | Strategy              |
| --------------------- | ----------------- | ---------------- | --------------------- |
| High Latency          | 3                 | 30 seconds       | Fast recovery         |
| Intermittent Failures | 5                 | 60 seconds       | Balanced approach     |
| Persistent Outages    | 10                | 300 seconds      | Conservative recovery |

### Memory Optimization

#### Vector Batch Sizing

```typescript
// Optimal batch size calculation
optimalBatchSize = min(
  memory_limit / vector_size * memory_overhead_factor,
  api_rate_limit,
  processing_capacity
)

// Example calculation
memory_limit = 1GB
vector_size = 1536 dimensions * 4 bytes = 6KB
memory_overhead_factor = 4 (for processing)
optimalBatchSize = min(1073741824 / (6144 * 4), 1000, 500) = min(43690, 1000, 500) = 500
```

#### Memory Configuration

| Configuration     | Memory Usage            | Recommended Settings          |
| ----------------- | ----------------------- | ----------------------------- |
| Vector Cache      | 30-50% of available RAM | `VECTOR_CACHE_SIZE=0.3`       |
| Connection Pool   | 10-20% of available RAM | `QDRANT_POOL_MAX=20`          |
| Processing Buffer | 20-30% of available RAM | `PROCESSING_BUFFER_SIZE=0.25` |

---

## Operational Runbook

### Daily Operations

#### Health Check Verification

```bash
# Check Qdrant health status
curl -s http://localhost:3000/health/qdrant | jq '.'

# Check system health summary
curl -s http://localhost:3000/health/summary | jq '.'

# Verify monitoring dashboard
curl -s http://localhost:3000/metrics | grep qdrant
```

#### Performance Monitoring

```bash
# Monitor response times
curl -s http://localhost:3000/metrics | grep qdrant_response_time

# Check error rates
curl -s http://localhost:3000/metrics | grep qdrant_error_rate

# Monitor connection pool status
curl -s http://localhost:3000/metrics | grep qdrant_pool
```

#### Log Analysis

```bash
# Check for Qdrant-related errors
grep "qdrant" /var/log/cortex-mcp/app.log | tail -50

# Monitor circuit breaker events
grep "circuit_breaker" /var/log/cortex-mcp/app.log | tail -50

# Check performance degradation
grep "performance.*degradation" /var/log/cortex-mcp/app.log | tail -50
```

### Weekly Operations

#### Performance Review

```typescript
// Generate weekly performance report
const performanceReport = await qdrantMonitor.generatePerformanceReport({
  timeframe: '7d',
  metrics: ['response_time', 'error_rate', 'throughput', 'resource_usage'],
});

console.log('Weekly Qdrant Performance Report:', performanceReport);
```

#### Configuration Validation

```bash
# Validate current configuration
curl -s -X POST http://localhost:3000/admin/config/validate \
  -H "Content-Type: application/json" \
  -d '{"service": "qdrant"}'

# Check for configuration drift
curl -s http://localhost:3000/admin/config/diff | jq '.qdrant'
```

#### Maintenance Tasks

```bash
# Rotate Qdrant collection snapshots
curl -s -X POST http://localhost:3000/admin/qdrant/maintenance/snapshot

# Clean up expired vectors
curl -s -X POST http://localhost:3000/admin/qdrant/maintenance/cleanup

# Optimize collection indexes
curl -s -X POST http://localhost:3000/admin/qdrant/maintenance/optimize
```

### Monthly Operations

#### Capacity Planning

```typescript
// Analyze growth trends
const capacityAnalysis = await qdrantMonitor.analyzeCapacityTrends({
  timeframe: '30d',
  metrics: ['vector_count', 'storage_usage', 'memory_usage', 'query_volume'],
});

// Generate capacity recommendations
const recommendations = await qdrantMonitor.generateCapacityRecommendations(capacityAnalysis);
```

#### Security Audit

```bash
# Verify API key rotation
curl -s -X GET http://localhost:3000/admin/security/api-keys | jq '.qdrant'

# Check access logs
grep "qdrant.*auth" /var/log/cortex-mcp/access.log | tail -100

# Validate TLS configuration
openssl s_client -connect $(echo $QDRANT_URL | sed 's|http://||'):443 -servername $(echo $QDRANT_URL | sed 's|http://||')
```

---

## Troubleshooting Procedures

### Common Issues and Solutions

#### 1. Connection Failures

**Symptoms**:

- Health checks showing `red` status
- Connection timeout errors
- Circuit breaker in open state

**Diagnostic Steps**:

```bash
# Check Qdrant server status
curl -s $QDRANT_URL/health || echo "Qdrant unreachable"

# Test network connectivity
telnet $(echo $QDRANT_URL | sed 's|https\?://||' | cut -d: -f1) \
        $(echo $QDRANT_URL | sed 's|https\?://||' | cut -d: -f2)

# Check DNS resolution
nslookup $(echo $QDRANT_URL | sed 's|https\?://||' | cut -d: -f1)

# Verify API key validity
curl -s -H "api-key: $QDRANT_API_KEY" $QDRANT_URL/collections
```

**Solutions**:

1. **Network Issues**:

   ```bash
   # Restart network services
   systemctl restart networking

   # Check firewall rules
   iptables -L | grep 6333
   ufw status | grep 6333
   ```

2. **Qdrant Server Issues**:

   ```bash
   # Restart Qdrant service
   systemctl restart qdrant

   # Check Qdrant logs
   journalctl -u qdrant -f --lines=100

   # Verify Qdrant configuration
   cat /etc/qdrant/config.yaml
   ```

3. **Authentication Issues**:
   ```bash
   # Regenerate API key
   curl -s -X POST $QDRANT_URL/api-key \
     -H "Content-Type: application/json" \
     -d '{"description": "cortex-mcp-api-key"}'
   ```

#### 2. Performance Degradation

**Symptoms**:

- Response times > 5 seconds
- Health checks showing `amber` status
- High CPU/memory usage

**Diagnostic Steps**:

```bash
# Check Qdrant performance metrics
curl -s $QDRANT_URL/telemetry | jq '.'

# Monitor system resources
top -p $(pgrep qdrant)
htop -p $(pgrep qdrant)

# Check disk I/O
iostat -x 1 10 | grep qdrant

# Analyze query performance
curl -s -X POST $QDRANT_URL/collections/cortex/search \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, ...], "limit": 10}'
```

**Solutions**:

1. **Index Optimization**:

   ```bash
   # Rebuild collection indexes
   curl -s -X POST $QDRANT_URL/collections/cortex/index

   # Update HNSW parameters
   curl -s -X PATCH $QDRANT_URL/collections/cortex \
     -H "Content-Type: application/json" \
     -d '{"hnsw_config": {"m": 32, "ef_construct": 400}}'
   ```

2. **Resource Scaling**:

   ```bash
   # Increase memory allocation
   systemctl edit qdrant
   # Add: Environment="QDRANT__SERVICE__MAX_MEMORY_SIZE=4GB"

   # Scale horizontally (if using cluster)
   qdrantctl node add --cluster my-cluster
   ```

3. **Query Optimization**:
   ```typescript
   // Use more efficient search parameters
   const optimizedSearch = {
     vector: embedding,
     limit: 10,
     search_params: {
       hnsw_ef: 128, // Increase for better recall
       exact: false, // Use approximate search
     },
   };
   ```

#### 3. Memory Issues

**Symptoms**:

- Out-of-memory errors
- System swapping
- Process crashes

**Diagnostic Steps**:

```bash
# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable)"

# Monitor Qdrant memory
cat /proc/$(pgrep qdrant)/status | grep -E "(VmRSS|VmSize)"

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full qdrant

# Analyze memory allocation patterns
curl -s $QDRANT_URL/collections/cortex | jq '.points_count'
```

**Solutions**:

1. **Memory Configuration**:

   ```bash
   # Increase Qdrant memory limit
   systemctl edit qdrant
   # Add: Environment="QDRANT__SERVICE__MAX_MEMORY_SIZE=8GB"

   # Configure vector cache
   curl -s -X PATCH $QDRANT_URL/collections/cortex \
     -H "Content-Type: application/json" \
     -d '{"quantization_config": {"scalar": {"type": "int8"}}}'
   ```

2. **Collection Optimization**:

   ```bash
   # Implement vector pagination
   curl -s -X POST $QDRANT_URL/collections/cortex/scroll \
     -H "Content-Type: application/json" \
     -d '{"limit": 1000, "offset": 0}'

   # Use sparse vectors for metadata
   curl -s -X PATCH $QDRANT_URL/collections/cortex \
     -H "Content-Type: application/json" \
     -d '{"sparse_vectors": {"metadata": {"index": {"type": "keyword"}}}}'
   ```

#### 4. Circuit Breaker Issues

**Symptoms**:

- Circuit breaker stuck in open state
- No automatic recovery
- High failure rates

**Diagnostic Steps**:

```bash
# Check circuit breaker status
curl -s http://localhost:3000/metrics | grep circuit_breaker

# Analyze failure patterns
grep "circuit_breaker.*open" /var/log/cortex-mcp/app.log | tail -20

# Monitor recent errors
grep "qdrant.*error" /var/log/cortex-mcp/app.log | tail -50
```

**Solutions**:

1. **Manual Circuit Reset**:

   ```bash
   # Reset circuit breaker via API
   curl -s -X POST http://localhost:3000/admin/circuit-breaker/reset \
     -H "Content-Type: application/json" \
     -d '{"service": "qdrant"}'

   # Force circuit breaker closed
   curl -s -X PATCH http://localhost:3000/admin/circuit-breaker/qdrant \
     -H "Content-Type: application/json" \
     -d '{"state": "closed"}'
   ```

2. **Threshold Adjustment**:

   ```typescript
   // Temporarily increase failure threshold
   const newConfig = {
     failureThreshold: 10, // Increase from 5
     recoveryTimeout: 30000, // Reduce from 60s
     halfOpenMaxCalls: 5, // Increase from 3
   };

   await circuitBreaker.updateConfig(newConfig);
   ```

### Emergency Procedures

#### Complete Outage Response

1. **Immediate Assessment** (5 minutes):

   ```bash
   # Check all health endpoints
   for endpoint in /health /health/qdrant /health/summary; do
     curl -s http://localhost:3000$endpoint | jq '.status'
   done

   # Verify Qdrant server status
   systemctl status qdrant
   curl -s $QDRANT_URL/health
   ```

2. **Service Recovery** (10 minutes):

   ```bash
   # Restart services in order
   systemctl restart qdrant
   sleep 30
   systemctl restart cortex-mcp

   # Verify recovery
   curl -s http://localhost:3000/health/qdrant | jq '.status'
   ```

3. **Fallback Activation** (15 minutes):

   ```bash
   # Activate degraded mode
   curl -s -X POST http://localhost:3000/admin/degradation/activate \
     -H "Content-Type: application/json" \
     -d '{"mode": "qdrant_fallback", "duration": 3600}'

   # Notify operations team
   curl -s -X POST https://hooks.slack.com/WEBHOOK_URL \
     -H "Content-Type: application/json" \
     -d '{"text": "Qdrant outage detected, fallback mode activated"}'
   ```

#### Performance Degradation Response

1. **Performance Assessment** (5 minutes):

   ```bash
   # Check current metrics
   curl -s http://localhost:3000/metrics | grep qdrant_response_time

   # Identify bottlenecks
   curl -s $QDRANT_URL/telemetry | jq '.performance'
   ```

2. **Performance Optimization** (10 minutes):

   ```bash
   # Increase circuit breaker threshold
   curl -s -X PATCH http://localhost:3000/admin/circuit-breaker/qdrant \
     -H "Content-Type: application/json" \
     -d '{"failureThreshold": 15, "recoveryTimeout": 120000}'

   # Enable performance mode
   curl -s -X POST http://localhost:3000/admin/performance/boost \
     -H "Content-Type: application/json" \
     -d '{"boost_factor": 1.5, "duration": 1800}'
   ```

---

## Best Practices

### Configuration Management

1. **Environment-Specific Configuration**:
   - Use different configuration files for each environment
   - Implement configuration validation at startup
   - Monitor for configuration drift

2. **Security Configuration**:
   - Rotate API keys regularly
   - Use TLS for all Qdrant connections
   - Implement network access controls

3. **Performance Configuration**:
   - Tune connection pools based on available resources
   - Configure appropriate timeouts for each operation type
   - Set realistic circuit breaker thresholds

### Monitoring and Alerting

1. **Health Monitoring**:
   - Monitor all health check endpoints
   - Set up alerts for status changes
   - Track performance degradation trends

2. **Performance Monitoring**:
   - Monitor response times and error rates
   - Track resource utilization
   - Set up capacity planning alerts

3. **Log Management**:
   - Use structured logging with correlation IDs
   - Implement log aggregation and analysis
   - Set up alerts for critical error patterns

### Operational Excellence

1. **Regular Maintenance**:
   - Perform regular health checks
   - Rotate API keys and certificates
   - Update Qdrant and client libraries

2. **Capacity Planning**:
   - Monitor growth trends
   - Plan for capacity expansion
   - Test scaling procedures regularly

3. **Disaster Recovery**:
   - Implement backup and recovery procedures
   - Test failover scenarios regularly
   - Document recovery procedures

### Performance Optimization

1. **Query Optimization**:
   - Use appropriate search parameters
   - Implement query result caching
   - Monitor and optimize search patterns

2. **Resource Management**:
   - Optimize connection pool sizes
   - Monitor memory usage patterns
   - Implement resource limits and quotas

3. **Index Management**:
   - Choose appropriate HNSW parameters
   - Monitor index build progress
   - Rebuild indexes when necessary

---

## Appendix

### Configuration Template

```yaml
# qdrant-config.yaml
production:
  qdrant:
    url: 'https://qdrant-prod.example.com'
    timeout: 30000
    pool:
      min: 5
      max: 20
      idle_timeout: 30000
    circuit_breaker:
      enabled: true
      failure_threshold: 5
      recovery_timeout: 60000
    health_check:
      interval: 30000
      timeout: 5000
    thresholds:
      response_time_warning: 1000
      response_time_critical: 5000
      error_rate_warning: 5
      error_rate_critical: 15

staging:
  qdrant:
    url: 'https://qdrant-staging.example.com'
    timeout: 30000
    pool:
      min: 3
      max: 15
      idle_timeout: 30000
    circuit_breaker:
      enabled: true
      failure_threshold: 3
      recovery_timeout: 30000
    health_check:
      interval: 30000
      timeout: 5000
```

### Monitoring Dashboard

```typescript
// Grafana panel configuration for Qdrant monitoring
const qdrantDashboard = {
  panels: [
    {
      title: 'Qdrant Health Status',
      type: 'stat',
      targets: [
        {
          expr: 'qdrant_health_status',
          legendFormat: '{{status}}',
        },
      ],
    },
    {
      title: 'Response Time',
      type: 'graph',
      targets: [
        {
          expr: 'histogram_quantile(0.95, rate(qdrant_response_time_seconds_bucket[5m]))',
          legendFormat: '95th percentile',
        },
        {
          expr: 'histogram_quantile(0.50, rate(qdrant_response_time_seconds_bucket[5m]))',
          legendFormat: '50th percentile',
        },
      ],
    },
    {
      title: 'Error Rate',
      type: 'graph',
      targets: [
        {
          expr: 'rate(qdrant_errors_total[5m])',
          legendFormat: 'Error Rate',
        },
      ],
    },
  ],
};
```

### Alert Rules

```yaml
# Prometheus alert rules for Qdrant
groups:
  - name: qdrant
    rules:
      - alert: QdrantDown
        expr: qdrant_health_status != 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: 'Qdrant is down'
          description: 'Qdrant health check has been failing for more than 1 minute'

      - alert: QdrantHighLatency
        expr: histogram_quantile(0.95, rate(qdrant_response_time_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'Qdrant high latency detected'
          description: '95th percentile response time is above 5 seconds'

      - alert: QdrantHighErrorRate
        expr: rate(qdrant_errors_total[5m]) / rate(qdrant_requests_total[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: 'Qdrant high error rate detected'
          description: 'Error rate is above 10% for more than 2 minutes'
```

This comprehensive guide provides all the necessary information for monitoring, configuring, and maintaining the Qdrant vector database in the MCP Cortex system. Regular reference to this guide will help ensure optimal performance and reliability of the Qdrant integration.
