# Service Level Objectives (SLOs) for MCP Cortex

## Overview

This document defines the minimal SLO set for MCP Cortex to ensure production-ready observability and reliability. The SLOs are designed to be measurable, actionable, and aligned with user experience.

## SLO Framework

### Target SLOs

| SLO ID | Name | Target | Period | Error Budget |
|--------|------|--------|--------|--------------|
| SLO-001 | API Availability | 99.9% | Rolling 30 days | 43.2 minutes |
| SLO-002 | API Latency (P95) | 500ms | Rolling 30 days | 43.2 minutes |
| SLO-003 | API Latency (P99) | 2000ms | Rolling 30 days | 43.2 minutes |
| SLO-004 | Error Rate | 1% | Rolling 30 days | 43.2 minutes |
| SLO-005 | Qdrant Operation Latency | 1000ms | Rolling 30 days | 43.2 minutes |
| SLO-006 | Memory Store Throughput | 1000 QPS | Rolling 30 days | 43.2 minutes |

## Detailed SLO Definitions

### SLO-001: API Availability

**Objective**: Ensure the MCP Cortex API is available and responsive to user requests.

- **Metric**: `cortex_availability_success_rate`
- **Measurement**: Successful HTTP responses / Total HTTP responses
- **Target**: 99.9% success rate
- **Error Budget**: 0.1% (43.2 minutes per 30 days)
- **Alerting Thresholds**:
  - Warning: Burn rate > 2x for 2 hours
  - Critical: Burn rate > 10x for 15 minutes
- **Data Source**: HTTP access logs, health check endpoints
- **Labels**: `endpoint`, `method`, `status_code`

### SLO-002: API Latency (P95)

**Objective**: Ensure 95% of API requests complete within acceptable timeframes.

- **Metric**: `cortex_request_duration_seconds`
- **Measurement**: 95th percentile of request duration
- **Target**: ≤ 500ms (0.5 seconds)
- **Error Budget**: Requests exceeding 500ms
- **Alerting Thresholds**:
  - Warning: P95 > 400ms for 1 hour
  - Critical: P95 > 750ms for 15 minutes
- **Data Source**: Request timing metrics
- **Labels**: `endpoint`, `method`, `status_code`

### SLO-003: API Latency (P99)

**Objective**: Ensure 99% of API requests complete within extended timeframes for tail latency management.

- **Metric**: `cortex_request_duration_seconds`
- **Measurement**: 99th percentile of request duration
- **Target**: ≤ 2000ms (2 seconds)
- **Error Budget**: Requests exceeding 2000ms
- **Alerting Thresholds**:
  - Warning: P99 > 1500ms for 1 hour
  - Critical: P99 > 3000ms for 15 minutes
- **Data Source**: Request timing metrics
- **Labels**: `endpoint`, `method`, `status_code`

### SLO-004: Error Rate

**Objective**: Maintain low error rates across all API operations.

- **Metric**: `cortex_error_rate`
- **Measurement**: Error responses (5xx, 4xx) / Total responses
- **Target**: ≤ 1% error rate
- **Error Budget**: 1% of total requests
- **Alerting Thresholds**:
  - Warning: Error rate > 0.5% for 30 minutes
  - Critical: Error rate > 2% for 5 minutes
- **Data Source**: HTTP status codes, exception tracking
- **Labels**: `endpoint`, `method`, `error_type`

### SLO-005: Qdrant Operation Latency

**Objective**: Ensure database operations complete within acceptable timeframes.

- **Metric**: `cortex_qdrant_operation_duration_seconds`
- **Measurement**: P95 of Qdrant operation duration
- **Target**: ≤ 1000ms (1 second)
- **Error Budget**: Operations exceeding 1000ms
- **Alerting Thresholds**:
  - Warning: P95 > 800ms for 30 minutes
  - Critical: P95 > 1500ms for 10 minutes
- **Data Source**: Qdrant client timing metrics
- **Labels**: `operation_type` (search, insert, update, delete), `collection`

### SLO-006: Memory Store Throughput

**Objective**: Maintain sufficient throughput for memory store operations.

- **Metric**: `cortex_memory_store_qps`
- **Measurement**: Queries per second for memory store operations
- **Target**: ≥ 1000 QPS sustained
- **Error Budget**: Periods where QPS < 1000
- **Alerting Thresholds**:
  - Warning: QPS < 800 for 5 minutes
  - Critical: QPS < 500 for 2 minutes
- **Data Source**: Operation counters and timing
- **Labels**: `operation_type` (store, find, delete)

## Metrics Implementation

### Stable Metric Names

The following metric names are used consistently across the system:

```typescript
// Core availability metrics
const METRIC_NAMES = {
  AVAILABILITY_SUCCESS_RATE: 'cortex_availability_success_rate',
  REQUEST_DURATION: 'cortex_request_duration_seconds',
  ERROR_RATE: 'cortex_error_rate',
  QDRANT_OPERATION_DURATION: 'cortex_qdrant_operation_duration_seconds',
  MEMORY_STORE_QPS: 'cortex_memory_store_qps',
  MEMORY_FIND_QPS: 'cortex_memory_find_qps',
  TOTAL_QPS: 'cortex_total_qps'
} as const;
```

### Consistent Labels

All metrics include these standard labels:

- `service`: "cortex-mcp"
- `version`: Application version
- `environment`: "production" | "staging" | "development"
- `component`: Service component (api, qdrant, memory-store)
- `operation_type`: Type of operation (search, store, find)
- `status`: Success/failure status

## Alerting Rules

### SLO Breach Alerts

```yaml
groups:
  - name: cortex-slos
    rules:
      # Availability alerts
      - alert: CortexAvailabilityHighBurnRate
        expr: burn_rate_slo_001 > 2
        for: 2h
        labels:
          severity: warning
          slo: SLO-001
        annotations:
          summary: "High availability error burn rate detected"
          description: "SLO-001 (API Availability) burn rate is {{ $value }}x"

      - alert: CortexAvailabilityCriticalBurnRate
        expr: burn_rate_slo_001 > 10
        for: 15m
        labels:
          severity: critical
          slo: SLO-001
        annotations:
          summary: "Critical availability error burn rate detected"
          description: "SLO-001 (API Availability) burn rate is {{ $value }}x"

      # Latency alerts
      - alert: CortexLatencyP95High
        expr: histogram_quantile(0.95, cortex_request_duration_seconds) > 0.75
        for: 15m
        labels:
          severity: critical
          slo: SLO-002
        annotations:
          summary: "P95 latency exceeds critical threshold"
          description: "P95 latency is {{ $value }}s (target: 0.5s)"

      # Qdrant latency alerts
      - alert: CortexQdrantLatencyHigh
        expr: histogram_quantile(0.95, cortex_qdrant_operation_duration_seconds) > 1.5
        for: 10m
        labels:
          severity: critical
          slo: SLO-005
        annotations:
          summary: "Qdrant operation latency high"
          description: "P95 Qdrant latency is {{ $value }}s (target: 1s)"
```

## Monitoring Implementation

### Metrics Collection

The system uses the `MetricsService` from `src/monitoring/metrics-service.ts` to:

1. **Collect metrics** with stable names and consistent labels
2. **Calculate percentiles** (P95, P99) for latency measurements
3. **Track error rates** across different operation types
4. **Monitor Qdrant performance** with dedicated metrics
5. **Aggregate throughput** measurements for capacity planning

### Dashboard Components

Key dashboard widgets include:

1. **SLO Status Overview**: Current compliance status for all SLOs
2. **Error Budget Burn Rate**: Real-time burn rate visualization
3. **Latency Heatmap**: Request latency distribution over time
4. **Qdrant Performance**: Database operation metrics and health
5. **Throughput Trends**: QPS trends and capacity utilization
6. **Error Analysis**: Error breakdown by type and component

### Tracing Implementation

Distributed tracing covers:

1. **MCP Entry Points**: All MCP tool executions
2. **Core Services**: Memory store, find, and Qdrant operations
3. **Database Interactions**: All Qdrant client calls
4. **AI Services**: Embedding and AI orchestrator calls

## Incident Response

### Error Budget Management

1. **Deployment Halt**: Automatic halt when error budget < 20%
2. **Incident Creation**: Automatic creation when SLO breach detected
3. **Escalation**: Tiered escalation based on burn rate and severity
4. **Communication**: Stakeholder notifications for critical breaches

### Post-Incident Analysis

1. **RCA Documentation**: Root cause analysis for all SLO breaches
2. **Preventive Measures**: Action items to prevent recurrence
3. **SLO Adjustment**: Review and adjust targets if needed

## Review and Maintenance

### Monthly SLO Review

- SLO achievement rates
- Error budget utilization
- Alert tuning effectiveness
- Dashboard usability improvements

### Quarterly Target Adjustment

- Business requirement changes
- System capability evolution
- User experience expectations
- Industry benchmark comparisons

## Implementation Status

- [x] SLO definitions documented
- [x] Metric names standardized
- [x] Alert rules defined
- [x] Dashboard specifications created
- [ ] Metrics collection implementation
- [ ] Alert routing configuration
- [ ] Dashboard deployment
- [ ] Load testing validation
- [ ] Incident response procedures

## Related Documentation

- [Alerting System Guide](./ALERTING-SYSTEM-GUIDE.md)
- [AI Operations Runbook](./AI_OPERATIONS_RUNBOOK.md)
- [Advanced Technical Guide](./ADVANCED-TECHNICAL-GUIDE.md)
- [API Reference](./API-REFERENCE.md)