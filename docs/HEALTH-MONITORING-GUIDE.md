# Comprehensive Health Monitoring System

This guide covers the complete health monitoring system implemented for the MCP Cortex server, providing production-ready monitoring, alerting, and observability.

## Overview

The health monitoring system includes:

- **MCP Server Health Monitoring**: Real-time monitoring of server health, connections, and operations
- **Qdrant Database Monitoring**: Enhanced connectivity and performance monitoring for Qdrant vector database
- **Circuit Breaker Monitoring**: Detailed state tracking and alerting for circuit breakers
- **Performance Metrics Collection**: Comprehensive system and application performance metrics
- **Container Probes**: Kubernetes/Docker-ready readiness and liveness probes
- **Structured Logging**: Comprehensive logging with correlation IDs and proper severity levels
- **Health Dashboard API**: RESTful API for real-time status and historical data

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Health Monitoring System                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ MCP Server      │  │ Qdrant Health    │  │ Circuit         │  │
│  │ Health Monitor  │  │ Monitor          │  │ Breaker Monitor │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│           │                     │                     │           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Performance     │  │ Container        │  │ Structured      │  │
│  │ Collector       │  │ Probes           │  │ Logger          │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│           │                     │                     │           │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                Health Dashboard API                        │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Usage

```typescript
import { healthMonitoringManager } from './src/monitoring/index.js';

// Start all monitoring components
await healthMonitoringManager.start();

// Get health status summary
const summary = healthMonitoringManager.getHealthSummary();
console.log('Overall health:', summary.overall);

// Perform comprehensive health check
const healthCheck = await healthMonitoringManager.performHealthCheck();
console.log('Health check results:', healthCheck);

// Get active alerts
const alerts = healthMonitoringManager.getActiveAlerts();
console.log('Active alerts:', alerts);
```

### Starting Individual Components

```typescript
import {
  mcpServerHealthMonitor,
  circuitBreakerMonitor,
  enhancedPerformanceCollector,
  qdrantHealthMonitor,
} from './src/monitoring/index.js';

// Start MCP server monitoring
mcpServerHealthMonitor.start();

// Start circuit breaker monitoring
circuitBreakerMonitor.start();

// Start performance collection
enhancedPerformanceCollector.start();

// Start Qdrant monitoring (if configured)
const qdrantMonitor = new QdrantHealthMonitor({
  url: 'http://localhost:6333',
  apiKey: process.env.QDRANT_API_KEY,
});
qdrantMonitor.start();
```

## Configuration

### Environment Variables

```bash
# General Configuration
NODE_ENV=production
SERVICE_NAME=cortex-mcp
LOG_LEVEL=info

# Qdrant Configuration
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key

# Health Check Configuration
HEALTH_CHECK_INTERVAL_MS=30000
HEALTH_CHECK_TIMEOUT_MS=10000

# Performance Monitoring
ENABLE_PERFORMANCE_COLLECTION=true
METRICS_COLLECTION_INTERVAL_MS=10000

# Container Probes
ENABLE_CONTAINER_PROBES=true
READINESS_CHECK_INTERVAL_MS=15000
LIVENESS_CHECK_INTERVAL_MS=30000

# Dashboard API
ENABLE_DASHBOARD_API=true
DASHBOARD_API_KEY=your-dashboard-api-key

# Auto-start (optional)
AUTO_START_HEALTH_MONITORING=true
```

### Component Configuration

#### MCP Server Health Monitor

```typescript
import { mcpServerHealthMonitor } from './src/monitoring/mcp-server-health-monitor.js';

const config = {
  healthCheckIntervalMs: 30000,
  metricsCollectionIntervalMs: 10000,
  thresholds: {
    errorRateWarning: 5,      // percentage
    errorRateCritical: 15,     // percentage
    responseTimeWarning: 1000, // milliseconds
    responseTimeCritical: 5000,// milliseconds
    memoryUsageWarning: 80,    // percentage
    memoryUsageCritical: 95,   // percentage
  },
  circuitBreakerMonitoring: {
    enabled: true,
    alertOnOpen: true,
    alertOnHalfOpen: true,
  },
};

mcpServerHealthMonitor.start(config);
```

#### Qdrant Health Monitor

```typescript
import { QdrantHealthMonitor } from './src/monitoring/qdrant-health-monitor.js';

const config = {
  url: 'http://localhost:6333',
  apiKey: 'your-api-key',
  timeoutMs: 10000,
  healthCheckIntervalMs: 30000,
  thresholds: {
    responseTimeWarning: 1000,
    responseTimeCritical: 5000,
    errorRateWarning: 5,
    errorRateCritical: 15,
    memoryUsageWarning: 80,
    memoryUsageCritical: 95,
  },
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    recoveryTimeoutMs: 60000,
  },
  alerts: {
    enabled: true,
    consecutiveFailuresThreshold: 3,
  },
};

const qdrantMonitor = new QdrantHealthMonitor(config);
qdrantMonitor.start();
```

#### Circuit Breaker Monitor

```typescript
import { circuitBreakerMonitor } from './src/monitoring/circuit-breaker-monitor.js';

const config = {
  healthCheckIntervalMs: 15000,
  metricsCollectionIntervalMs: 10000,
  alerts: {
    enabled: true,
    failureRateWarning: 10,
    failureRateCritical: 25,
    consecutiveFailuresWarning: 3,
    consecutiveFailuresCritical: 5,
    openCircuitAlert: true,
    recoveryAlert: true,
  },
  performance: {
    enabled: true,
    responseTimeHistorySize: 100,
    throughputWindowSeconds: 60,
  },
  reporting: {
    enabled: true,
    generateHealthReports: true,
    healthReportIntervalMinutes: 5,
  },
};

circuitBreakerMonitor.start(config);
```

## API Endpoints

### Health Dashboard API

The health dashboard API provides comprehensive monitoring data through REST endpoints:

#### Base Path: `/api/health-dashboard/v1`

##### Get Dashboard Summary
```http
GET /api/health-dashboard/v1/summary
```

Response:
```json
{
  "success": true,
  "data": {
    "overview": {
      "overallHealth": "healthy",
      "uptime": 3600000,
      "version": "2.0.1",
      "environment": "production",
      "lastHealthCheck": "2025-01-01T12:00:00.000Z"
    },
    "components": {
      "total": 5,
      "healthy": 4,
      "degraded": 1,
      "unhealthy": 0
    },
    "performance": {
      "requestsPerSecond": 25.5,
      "averageResponseTime": 150,
      "errorRate": 2.1,
      "throughput": 25.5
    },
    "resources": {
      "memoryUsagePercent": 65.2,
      "cpuUsagePercent": 35.8,
      "diskUsagePercent": 45.1,
      "activeConnections": 12
    },
    "alerts": {
      "active": 1,
      "critical": 0,
      "warning": 1,
      "info": 0
    },
    "trends": {
      "healthTrend": "stable",
      "performanceTrend": "improving",
      "errorRateTrend": "improving"
    }
  }
}
```

##### Get Real-time Health Data
```http
GET /api/health-dashboard/v1/realtime
```

##### Get Historical Health Data
```http
GET /api/health-dashboard/v1/historical?timeRange=1h&interval=5m
```

##### Get Active Alerts
```http
GET /api/health-dashboard/v1/alerts?severity=warning&status=active&limit=50
```

##### Export Health Data
```http
GET /api/health-dashboard/v1/export?format=json&timeRange=24h
GET /api/health-dashboard/v1/export?format=csv&timeRange=24h
GET /api/health-dashboard/v1/export?format=prometheus
```

### Container Probes

#### Readiness Probe
```http
GET /ready
```

Response:
```json
{
  "status": "ready",
  "timestamp": "2025-01-01T12:00:00.000Z",
  "duration": 45,
  "uptime": 3600000,
  "checks": {
    "mcp-server": { "status": "healthy", "responseTime": 25 },
    "qdrant": { "status": "healthy", "responseTime": 15 }
  },
  "message": "Service is ready"
}
```

#### Liveness Probe
```http
GET /health/live
```

Response:
```json
{
  "status": "alive",
  "timestamp": "2025-01-01T12:00:00.000Z",
  "duration": 35,
  "uptime": 3600000,
  "memoryUsage": 65.2,
  "responseTime": 35,
  "message": "Service is alive"
}
```

#### Startup Probe
```http
GET /startup
```

## Kubernetes/Docker Integration

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-mcp
spec:
  template:
    spec:
      containers:
      - name: cortex-mcp
        image: cortex-mcp:latest
        ports:
        - containerPort: 3000
        env:
        - name: QDRANT_URL
          value: "http://qdrant:6333"
        - name: ENABLE_CONTAINER_PROBES
          value: "true"
        - name: AUTO_START_HEALTH_MONITORING
          value: "true"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /startup
            port: 3000
          initialDelaySeconds: 0
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### Docker Compose

```yaml
version: '3.8'
services:
  cortex-mcp:
    image: cortex-mcp:latest
    ports:
      - "3000:3000"
    environment:
      - QDRANT_URL=http://qdrant:6333
      - ENABLE_CONTAINER_PROBES=true
      - AUTO_START_HEALTH_MONITORING=true
      - LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    depends_on:
      - qdrant

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
```

## Monitoring and Alerting

### Prometheus Integration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/api/health-dashboard/v1/export'
    params:
      format: ['prometheus']
    scrape_interval: 10s
```

### Grafana Dashboard

Key metrics to monitor:

- `cortex_cpu_usage_percent`
- `cortex_memory_heap_usage_bytes`
- `cortex_memory_heap_usage_percent`
- `cortex_requests_per_second`
- `cortex_request_duration_seconds`
- `cortex_active_sessions`
- `cortex_tool_executions_total`
- `cortex_circuit_breaker_state`
- `cortex_qdrant_connection_status`
- `cortex_qdrant_response_time_milliseconds`

### Alerting Rules

```yaml
# cortex-alerts.yml
groups:
  - name: cortex-mcp
    rules:
      - alert: HighErrorRate
        expr: cortex_requests_total{status="error"} / cortex_requests_total > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }}"

      - alert: HighMemoryUsage
        expr: cortex_memory_heap_usage_percent > 90
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}%"

      - alert: CircuitBreakerOpen
        expr: cortex_circuit_breaker_state == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Circuit breaker is open"
          description: "Circuit breaker {{ $labels.service }} is open"

      - alert: QdrantDown
        expr: cortex_qdrant_connection_status == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Qdrant is down"
          description: "Qdrant connection is lost"
```

## Structured Logging

### Log Formats

The system supports multiple log formats:

#### JSON Format (Default)
```json
{
  "timestamp": "2025-01-01T12:00:00.000Z",
  "level": "info",
  "message": "System health check: healthy",
  "category": "system_health",
  "service": "cortex-mcp",
  "version": "2.0.1",
  "environment": "production",
  "correlationId": "corr_1234567890_abc123",
  "healthStatus": "healthy",
  "context": {
    "metrics": {
      "requestsPerSecond": 25.5,
      "memoryUsagePercent": 65.2
    }
  }
}
```

#### Pretty Format
```
2025-01-01T12:00:00.000Z INFO  system_health          [mcp-server] System health check: healthy | status: healthy | duration: 45ms
```

### Using the Structured Logger

```typescript
import { healthStructuredLogger } from './src/monitoring/index.js';

// Log system health check
healthStructuredLogger.logSystemHealthCheck(
  HealthStatus.HEALTHY,
  HealthStatus.DEGRADED,
  mcpMetrics,
  'correlation-id-123'
);

// Log component health check
healthStructuredLogger.logComponentHealthCheck(
  'qdrant',
  DependencyType.VECTOR_DB,
  HealthStatus.HEALTHY,
  HealthStatus.DEGRADED,
  150,
  undefined,
  'correlation-id-123'
);

// Log circuit breaker event
healthStructuredLogger.logCircuitBreakerEvent({
  serviceName: 'qdrant',
  eventType: 'recovery',
  timestamp: new Date(),
  currentState: 'closed',
  previousState: 'open'
});

// Log performance alert
healthStructuredLogger.logPerformanceAlert(
  'high_response_time',
  'warning',
  'mcp-server',
  1000,  // threshold
  1500,  // actual value
  'correlation-id-123'
);
```

## Troubleshooting

### Common Issues

#### Health Check Failures

1. **Qdrant Connection Issues**
   ```bash
   curl -f http://localhost:6333/health
   ```

2. **Memory Pressure**
   ```bash
   # Check memory usage
   node --inspect index.js
   # In Chrome DevTools: Memory tab
   ```

3. **Circuit Breaker Issues**
   ```javascript
   // Check circuit breaker status
   const stats = circuitBreakerManager.getAllStats();
   console.log('Circuit breaker states:', stats);
   ```

#### Performance Issues

1. **High Response Times**
   ```javascript
   // Check performance metrics
   const metrics = enhancedPerformanceCollector.getMCPMetrics();
   console.log('Performance metrics:', metrics);
   ```

2. **Memory Leaks**
   ```javascript
   // Monitor memory usage over time
   const monitorMemory = () => {
     const usage = process.memoryUsage();
     console.log('Memory usage:', usage);
   };
   setInterval(monitorMemory, 10000);
   ```

#### API Issues

1. **Rate Limiting**
   - Check API key configuration
   - Verify rate limit settings

2. **CORS Issues**
   - Verify CORS configuration
   - Check allowed origins

### Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=debug npm start
```

Enable detailed monitoring:
```bash
ENABLE_DETAILED_HEALTH_CHECKS=true
ENABLE_PERFORMANCE_COLLECTION=true
HEALTH_CHECK_INTERVAL_MS=10000
```

## Best Practices

### Production Deployment

1. **Configure appropriate thresholds** based on your service requirements
2. **Set up proper alerting** with appropriate severity levels
3. **Monitor all components** including dependencies
4. **Use structured logging** for better debugging
5. **Implement proper circuit breakers** for external dependencies
6. **Configure container probes** for orchestration platforms
7. **Set up monitoring dashboards** for operational visibility

### Performance Optimization

1. **Adjust monitoring intervals** to balance overhead and visibility
2. **Use sampling** for high-frequency metrics
3. **Implement proper caching** for dashboard data
4. **Monitor the monitoring system** itself
5. **Regular cleanup** of historical data

### Security Considerations

1. **Secure API endpoints** with authentication
2. **Validate input parameters** for all API endpoints
3. **Rate limit API calls** to prevent abuse
4. **Sanitize log outputs** to prevent information leakage
5. **Use HTTPS** for all external communications

## Contributing

When adding new monitoring components:

1. Follow the existing patterns and interfaces
2. Add comprehensive tests
3. Update documentation
4. Include proper error handling
5. Add structured logging events
6. Update the health dashboard API if needed

## Support

For issues and questions:

1. Check the logs for detailed error messages
2. Review the health dashboard for current status
3. Verify configuration settings
4. Check the troubleshooting section above
5. Open an issue with detailed information about the problem