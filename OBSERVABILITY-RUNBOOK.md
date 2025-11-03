# Cortex MCP Observability Runbook

**Version:** 1.0
**Last Updated:** 2025-11-03
**Maintainers:** Observability Team

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Monitoring Components](#monitoring-components)
4. [Procedures](#procedures)
   - [Daily Operations](#daily-operations)
   - [Incident Response](#incident-response)
   - [Performance Troubleshooting](#performance-troubleshooting)
   - [Chaos Testing](#chaos-testing)
   - [Capacity Planning](#capacity-planning)
5. [Alert Management](#alert-management)
6. [Escalation Procedures](#escalation-procedures)
7. [Recovery Procedures](#recovery-procedures)
8. [Maintenance Procedures](#maintenance-procedures)
9. [Metrics and KPIs](#metrics-and-kpis)
10. [Tools and Access](#tools-and-access)

## Overview

This runbook provides comprehensive procedures for monitoring, troubleshooting, and maintaining the Cortex MCP observability infrastructure. It covers all aspects of system observability including SLI/SLO monitoring, performance benchmarking, chaos testing, and incident response.

### System Objectives

- **Availability:** ≥99.9% uptime
- **Performance:** P95 latency ≤1000ms
- **Error Rate:** ≤0.1%
- **Data Quality:** ≥99.5% accuracy

## System Architecture

### Observability Stack

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SLI/SLO       │    │  Performance     │    │   R/A/G         │
│   Monitor        │◄──►│   Benchmarking   │◄──►│   Dashboard     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   System        │    │   Trend          │    │   Chaos         │
│   Metrics        │◄──►│   Charts         │◄──►│   Testing       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Cortex MCP Core Services                      │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Data Collection:** System metrics collected every 30 seconds
2. **Aggregation:** Data aggregated at multiple time granularities
3. **Analysis:** Real-time analysis for SLI/SLO compliance
4. **Alerting:** Threshold-based alerts with escalation
5. **Visualization:** Real-time dashboards and trend charts
6. **Storage:** Time-series data with configurable retention

## Monitoring Components

### 1. SLI/SLO Monitor (`sli-slo-monitor.ts`)

**Purpose:** Track service level indicators and objectives

**Key Metrics:**
- Availability percentage
- P95 latency
- Error rate
- Throughput
- Resource utilization

**Configuration:**
```typescript
const sloConfig = {
  availability_target_percentage: 99.9,
  latency_p95_target_ms: 1000,
  error_rate_target_percentage: 0.1,
  throughput_target_rps: 10,
  error_budget_window_hours: 24,
  alerting_burn_rate_threshold: 2.0,
};
```

**Procedures:**
- [Monitor SLI/SLO compliance](#monitor-slislo-compliance)
- [Handle SLO breaches](#handle-slo-breaches)
- [Manage error budgets](#manage-error-budgets)

### 2. R/A/G Dashboard (`rag-dashboard.ts`)

**Purpose:** Real-time visualization with cardinality management

**Key Features:**
- Real-time status updates
- Configurable widgets
- Cardinality limits
- Data export capabilities

**Dashboard Layouts:**
- **Overview:** Service health and key metrics
- **Performance:** Latency and throughput trends
- **Reliability:** Error rates and availability
- **Resources:** CPU, memory, disk utilization

### 3. Performance Benchmarking (`performance-benchmark.ts`)

**Purpose:** Validate performance under load

**Benchmark Types:**
- **1K Store:** 1,000 store operations
- **1K Find:** 1,000 find operations
- **10K Mixed:** 10,000 mixed operations

**Resource Budgets:**
- CPU: ≤70%
- Memory: ≤512MB
- Response Time P95: ≤500ms
- Error Rate: ≤1%

### 4. Chaos Testing (`chaos-testing.service.ts`)

**Purpose:** Validate system resilience

**Test Types:**
- Network latency injection
- Database error simulation
- Memory pressure testing
- Circuit breaker validation

### 5. Trend Charts (`trend-charts.ts`)

**Purpose:** Historical analysis and forecasting

**Chart Types:**
- Line charts for time series
- Heatmaps for error patterns
- Histograms for distributions
- Scatter plots for correlations

## Procedures

### Daily Operations

#### Morning Checklist (08:00 UTC)

1. **System Health Check**
   ```bash
   # Check system status
   curl -X GET http://localhost:3000/api/system/status

   # Verify all services are running
   systemctl status cortex-mcp
   ```

2. **Review Overnight Metrics**
   ```typescript
   // Check SLO compliance
   const compliance = sliSloMonitorService.getSLOComplianceReport(24);

   // Review active alerts
   const alerts = sliSloMonitorService.getActiveSLOAlerts();

   // Check dashboard health
   const dashboardStatus = ragDashboardService.getSystemStatus();
   ```

3. **Capacity Check**
   ```typescript
   // Monitor resource utilization
   const budgets = performanceBenchmarkService.getPerformanceBudgets();

   // Check cardinality limits
   const cardinality = ragDashboardService.getCardinalityLimits();
   ```

4. **Backup Verification**
   ```bash
   # Verify backup completion
   ls -la /backup/cortex-mcp/

   # Check backup integrity
   sha256sum /backup/cortex-mcp/latest/*.json
   ```

#### Evening Checklist (18:00 UTC)

1. **Performance Summary**
   ```typescript
   // Generate daily performance report
   const report = performanceTrendingService.getTrendAnalysis(24);
   ```

2. **Alert Review**
   - Review all alerts from the day
   - Ensure all critical alerts were addressed
   - Update runbook with any new procedures

3. **Capacity Planning**
   - Review growth trends
   - Update capacity forecasts
   - Plan scaling activities

### Monitor SLI/SLO Compliance

#### Continuous Monitoring

1. **Real-time Dashboard Monitoring**
   - Watch R/A/G dashboard for status changes
   - Monitor error budget consumption
   - Track performance trends

2. **Automated Alerts**
   ```typescript
   // Configure alert thresholds
   const alerts = [
     {
       type: 'availability',
       threshold: 99.5,
       operator: 'lt',
       action: 'escalate'
     },
     {
       type: 'latency',
       threshold: 1000,
       operator: 'gt',
       action: 'notify'
     }
   ];
   ```

3. **Daily SLO Reports**
   ```typescript
   // Generate daily SLO compliance report
   const dailyReport = sliSloMonitorService.getSLOComplianceReport(24);

   // Check error budget status
   const errorBudget = dailyReport.error_budget;
   if (errorBudget.status === 'warning') {
     // Trigger investigation procedure
   }
   ```

#### Investigation Procedures

1. **SLO Breach Detection**
   ```bash
   # Check current SLI metrics
   curl -X GET http://localhost:3000/api/sli/current

   # Get recent alerts
   curl -X GET http://localhost:3000/api/alerts/active
   ```

2. **Root Cause Analysis**
   ```typescript
   // Analyze recent performance trends
   const trends = performanceTrendingService.getTrendAnalysis(1);

   // Check for system anomalies
   const anomalies = trendChartsService.analyzeTrends('availability_chart', 24);
   ```

3. **Impact Assessment**
   - Number of affected users
   - Duration of impact
   - Business impact severity

### Handle SLO Breaches

#### Severity Classification

| Severity | Availability Impact | Response Time |
|----------|-------------------|---------------|
| Critical | <95% | Immediate |
| High | 95-99% | Within 15 minutes |
| Medium | 99-99.5% | Within 1 hour |
| Low | 99.5-99.9% | Within 4 hours |

#### Response Procedures

1. **Immediate Response (First 5 minutes)**
   ```bash
   # Verify system status
   ./scripts/health-check.sh

   # Check active incidents
   ./scripts/incident-check.sh

   # Notify on-call team
   ./scripts/notify-oncall.sh "SLO breach detected"
   ```

2. **Investigation (First 30 minutes)**
   ```typescript
   // Collect diagnostic data
   const diagnostics = {
     systemMetrics: systemMetricsService.getMetrics(),
     recentErrors: getRecentErrors(60), // Last 60 minutes
     activeConnections: getActiveConnections(),
     resourceUtilization: getResourceUtilization()
   };

   // Store for incident analysis
   cortexMemoryStore({
     kind: 'incident',
     content: diagnostics,
     scope: { project: 'cortex-mcp' }
   });
   ```

3. **Mitigation (First 2 hours)**
   - Implement temporary fixes
   - Scale resources if needed
   - Enable circuit breakers
   - Communicate with stakeholders

4. **Recovery (Up to 24 hours)**
   - Implement permanent fixes
   - Update monitoring thresholds
   - Document root cause
   - Review and improve procedures

### Performance Troubleshooting

#### Performance Degradation

1. **Symptoms Identification**
   - Increased latency
   - Reduced throughput
   - Higher error rates
   - Resource exhaustion

2. **Diagnostic Commands**
   ```bash
   # Check system resources
   top -p $(pgrep cortex-mcp)
   iostat -x 1
   netstat -i

   # Check application metrics
   curl -s http://localhost:3000/api/metrics/current | jq .
   ```

3. **Performance Analysis**
   ```typescript
   // Run performance benchmark
   const benchmark = await performanceBenchmarkService.executeBenchmark({
     name: 'Performance Diagnosis',
     workload: { operation_count: 1000, operation_type: 'mixed' }
   });

   // Analyze results
   if (benchmark.performance_analysis.efficiency_score < 70) {
     // Identify bottlenecks
     const bottlenecks = benchmark.performance_analysis.bottlenecks;
     bottlenecks.forEach(bottleneck => {
       logger.warn('Performance bottleneck detected', bottleneck);
     });
   }
   ```

4. **Common Solutions**
   - **High CPU:** Optimize algorithms, scale horizontally
   - **High Memory:** Implement memory pooling, optimize data structures
   - **High I/O:** Add caching, optimize database queries
   - **Network Issues:** Load balancing, connection pooling

#### Resource Exhaustion

1. **Memory Issues**
   ```bash
   # Check memory usage
   free -h
   pmap -x $(pgrep cortex-mcp)

   # Force garbage collection if needed
   curl -X POST http://localhost:3000/api/admin/gc
   ```

2. **Disk Space Issues**
   ```bash
   # Check disk usage
   df -h

   # Clean old logs
   find /var/log/cortex-mcp -name "*.log" -mtime +7 -delete

   # Clean up cache
   curl -X POST http://localhost:3000/api/admin/clear-cache
   ```

3. **Connection Issues**
   ```bash
   # Check connection limits
   ulimit -n

   # Monitor active connections
   netstat -an | grep :3000 | wc -l

   # Reset connection pools
   curl -X POST http://localhost:3000/api/admin/reset-connections
   ```

### Chaos Testing

#### Test Execution

1. **Pre-test Checklist**
   - [ ] Backup current system state
   - [ ] Notify stakeholders
   - [ ] Verify rollback procedures
   - [ ] Prepare monitoring

2. **Running Tests**
   ```typescript
   // Enable chaos testing
   chaosTestingService.enableChaosTesting();

   // Execute network latency test
   const networkTest = await chaosTestingService.executeDefaultExperiment('Network Blip Test');

   // Execute database error test
   const dbTest = await chaosTestingService.executeDefaultExperiment('Qdrant 5xx Error Injection');
   ```

3. **Test Validation**
   ```typescript
   // Verify system recovery
   const postTestMetrics = systemMetricsService.getMetrics();

   // Check for regressions
   const regression = await performanceBenchmarkService.executeBenchmark({
     name: 'Post-Chaos Validation',
     workload: { operation_count: 1000, operation_type: 'mixed' }
   });
   ```

4. **Post-test Procedures**
   - Analyze test results
   - Document findings
   - Update procedures
   - Share lessons learned

#### Test Types and Scenarios

| Test Type | Duration | Intensity | Success Criteria |
|-----------|----------|-----------|------------------|
| Network Latency | 2 minutes | 50-100ms | <10% error rate |
| Packet Loss | 1 minute | 5-10% | Automatic recovery |
| Connection Failure | 30 seconds | 100% fail | Circuit breaker activates |
| Database Errors | 1 minute | 25% errors | Retry success >80% |
| Memory Pressure | 2 minutes | 512MB | No OOM errors |
| CPU Exhaustion | 1 minute | 80% load | Response time <5x normal |

### Capacity Planning

#### Monitoring Growth Trends

1. **Weekly Capacity Review**
   ```typescript
   // Get growth trends
   const trends = await trendChartsService.analyzeTrends('throughput_chart', 168); // 7 days

   // Forecast capacity needs
   const forecast = trends.forecast;
   if (forecast.some(point => point.value > 0.8 * current_capacity)) {
     // Plan scaling activities
   }
   ```

2. **Resource Planning**
   ```typescript
   // Calculate resource requirements
   const requirements = {
     cpu: current_cpu * (1 + growth_rate * planning_horizon),
     memory: current_memory * (1 + growth_rate * planning_horizon),
     storage: current_storage * (1 + growth_rate * planning_horizon),
     network: current_bandwidth * (1 + growth_rate * planning_horizon)
   };
   ```

3. **Scaling Triggers**
   - CPU utilization >70% for 1 hour
   - Memory utilization >80% for 30 minutes
   - Error rate >1% for 15 minutes
   - Queue depth >1000 for 10 minutes

## Alert Management

### Alert Classification

| Alert Type | Severity | Response Time | Escalation |
|------------|----------|---------------|------------|
| SLO Breach | Critical | 5 minutes | On-call → Manager |
| System Down | Critical | 1 minute | On-call → Manager → Director |
| Performance Degradation | High | 15 minutes | On-call → Team Lead |
| Resource Exhaustion | High | 30 minutes | Team Lead → Manager |
| Capacity Warning | Medium | 2 hours | Team Lead |
| Configuration Change | Low | 24 hours | Team |

### Alert Response Procedures

1. **Alert Reception**
   ```bash
   # Check alert details
   curl -X GET http://localhost:3000/api/alerts/{alert_id}

   # Acknowledge alert
   curl -X POST http://localhost:3000/api/alerts/{alert_id}/acknowledge \
        -H "Content-Type: application/json" \
        -d '{"acknowledged_by": "operator_name"}'
   ```

2. **Initial Investigation**
   - Verify alert validity
   - Check system status
   - Review recent changes
   - Assess impact scope

3. **Escalation Criteria**
   - Alert not acknowledged within SLA
   - Issue not resolved within timeout
   - Impact increases beyond initial assessment
   - Multiple related alerts triggered

## Escalation Procedures

### Escalation Levels

1. **Level 1: On-call Engineer**
   - Initial response
   - Basic troubleshooting
   - Documentation
   - Duration: 30 minutes

2. **Level 2: Team Lead**
   - Complex issues
   - Coordination
   - Stakeholder communication
   - Duration: 2 hours

3. **Level 3: Engineering Manager**
   - Critical incidents
   - Resource allocation
   - Executive communication
   - Duration: 4 hours

4. **Level 4: Director**
   - Major outages
   - Business impact assessment
   - External communication
   - Duration: Ongoing

### Escalation Triggers

- **Automatic:** SLA breaches, system down
- **Manual:** Complexity increase, resource needs
- **Time-based:** Resolution time limits

## Recovery Procedures

### Service Recovery

1. **Immediate Recovery**
   ```bash
   # Restart services if needed
   systemctl restart cortex-mcp

   # Clear caches
   curl -X POST http://localhost:3000/api/admin/clear-cache

   # Reset circuit breakers
   curl -X POST http://localhost:3000/api/admin/reset-circuit-breakers
   ```

2. **Data Recovery**
   ```bash
   # Verify data integrity
   ./scripts/verify-data-integrity.sh

   # Restore from backup if needed
   ./scripts/restore-backup.sh {backup_timestamp}
   ```

3. **Service Validation**
   ```bash
   # Run health checks
   ./scripts/health-check.sh

   # Run smoke tests
   ./scripts/smoke-tests.sh

   # Verify SLO compliance
   curl -s http://localhost:3000/api/slo/current
   ```

### Database Recovery

1. **Qdrant Recovery**
   ```bash
   # Check Qdrant status
   curl -X GET http://localhost:6333/health

   # Restart Qdrant if needed
   docker restart qdrant

   # Verify data consistency
   curl -X GET http://localhost:6333/collections
   ```

2. **Index Recovery**
   ```bash
   # Rebuild indexes if corrupted
   curl -X PUT http://localhost:6333/collections/{collection_name}/index

   # Verify index health
   curl -X GET http://localhost:6333/collections/{collection_name}/index/info
   ```

## Maintenance Procedures

### Scheduled Maintenance

1. **Maintenance Windows**
   - Every Sunday 02:00-04:00 UTC
   - Monthly patching: First Tuesday 22:00-02:00 UTC
   - Quarterly upgrades: Second Saturday 22:00-06:00 UTC

2. **Maintenance Checklist**
   ```bash
   # Pre-maintenance
   ./scripts/pre-maintenance-check.sh

   # Backup system
   ./scripts/backup-system.sh

   # Notify users
   ./scripts/notify-maintenance.sh

   # Perform maintenance
   ./scripts/perform-maintenance.sh

   # Post-maintenance validation
   ./scripts/post-maintenance-check.sh
   ```

3. **Rollback Procedures**
   ```bash
   # Quick rollback (<5 minutes)
   ./scripts/quick-rollback.sh

   # Full rollback (<30 minutes)
   ./scripts/full-rollback.sh {backup_timestamp}

   # Validate rollback
   ./scripts/validate-rollback.sh
   ```

### Emergency Maintenance

1. **Hotfix Procedures**
   ```bash
   # Create hotfix branch
   git checkout -b hotfix/{issue_id}

   # Apply fix
   # ... development work ...

   # Test hotfix
   ./scripts/test-hotfix.sh

   # Deploy hotfix
   ./scripts/deploy-hotfix.sh

   # Validate deployment
   ./scripts/validate-deployment.sh
   ```

2. **Emergency Patches**
   - Direct server access if needed
   - Manual configuration changes
   - Immediate validation
   - Follow-up documentation

## Metrics and KPIs

### System KPIs

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| Availability | ≥99.9% | <99.5% | <99.0% |
| P95 Latency | ≤1000ms | >1500ms | >2000ms |
| Error Rate | ≤0.1% | >0.5% | >1.0% |
| Throughput | ≥10 rps | <5 rps | <2 rps |
| CPU Usage | ≤70% | >80% | >90% |
| Memory Usage | ≤70% | >80% | >90% |

### Operational KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| MTTR (Mean Time to Repair) | <30 minutes | Incident duration |
| MTBF (Mean Time Between Failures) | >720 hours | System uptime |
| Alert Response Time | <5 minutes | Alert acknowledgment |
| Change Success Rate | >95% | Deployment success |
| Customer Satisfaction | >4.5/5 | User feedback |

### Monitoring KPIs

| Metric | Target | Description |
|--------|--------|-------------|
| Dashboard Refresh Rate | <5 seconds | Real-time updates |
| Alert Accuracy | >95% | False positive rate |
| Data Retention | 30 days raw, 1 year aggregated | Historical analysis |
| Cardinality Utilization | <80% | Dimension limits |
| Query Response Time | <2 seconds | Dashboard performance |

## Tools and Access

### Required Tools

1. **Monitoring Tools**
   - Grafana dashboards
   - Prometheus metrics
   - Custom web UI

2. **CLI Tools**
   - `curl` for API access
   - `jq` for JSON processing
   - `systemctl` for service management

3. **Development Tools**
   - Node.js debugging
   - Performance profiling
   - Log analysis tools

### Access Requirements

| Role | System Access | API Access | Database Access |
|------|--------------|-----------|----------------|
| On-call Engineer | Read/Write | Full | Read |
| Team Lead | Read/Write | Full | Read/Write |
| Manager | Read | Limited | Read |
| Director | Read | Limited | None |

### API Endpoints

```bash
# System Status
GET /api/system/status

# Metrics
GET /api/metrics/current
GET /api/metrics/history

# SLI/SLO
GET /api/slo/current
GET /api/slo/compliance
GET /api/slo/alerts

# Performance
GET /api/performance/benchmarks
POST /api/performance/benchmark

# Chaos Testing
GET /api/chaos/experiments
POST /api/chaos/experiment/{id}/execute

# Administration
POST /api/admin/clear-cache
POST /api/admin/reset-circuit-breakers
POST /api/admin/gc
```

### Contact Information

- **On-call Engineer:** +1-XXX-XXX-XXXX
- **Team Lead:** team.lead@company.com
- **Engineering Manager:** eng.manager@company.com
- **Director:** director@company.com

## Documentation Updates

This runbook should be reviewed and updated:
- Monthly for accuracy
- After major incidents
- When procedures change
- Quarterly for comprehensive review

### Update Process

1. Create change request
2. Review with team
3. Update documentation
4. Train team on changes
5. Archive previous version

---

**This runbook is a living document. All team members are responsible for keeping it current and accurate.**