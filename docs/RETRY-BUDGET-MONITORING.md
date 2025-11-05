# Retry Budget & Circuit Breaker Monitoring System

A comprehensive monitoring system for tracking retry budget consumption, circuit breaker states, and SLO compliance with real-time metrics, alerting, dashboards, and integration capabilities.

## Overview

This system provides complete visibility into retry patterns and circuit breaker behavior across your microservices architecture, enabling proactive monitoring, alerting, and optimization of retry strategies.

## Features

### 🔍 **Real-Time Monitoring**
- Live retry budget consumption tracking
- Circuit breaker state monitoring
- SLO compliance monitoring
- Performance metrics collection
- Service dependency health tracking

### 📊 **Advanced Dashboards**
- Interactive service dependency maps
- Real-time metrics visualization
- SLO overlays and error budget tracking
- Comparative analysis views
- Historical trend analysis

### 🚨 **Intelligent Alerting**
- Configurable alert rules and thresholds
- Multi-channel notifications (Email, Slack, PagerDuty)
- Alert correlation and escalation policies
- Predictive alerting based on trends

### 📈 **Trend Analysis & Predictions**
- Historical pattern detection
- Anomaly detection and correlation
- Predictive failure analysis
- Budget exhaustion predictions
- SLO violation forecasting

### 🔌 **Integration & Export**
- Prometheus metrics export
- Grafana dashboard integration
- JSON/CSV data export
- REST API endpoints
- Server-sent events for real-time updates

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Retry Budget Monitoring                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Retry Budget   │  │  Circuit        │  │  Alert System   │ │
│  │  Monitor        │  │  Breaker        │  │                 │ │
│  │                 │  │  Monitor        │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│           │                     │                     │       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Trend          │  │  Metrics        │  │  Dashboard      │ │
│  │  Analyzer       │  │  Exporter       │  │  System         │ │
│  │                 │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│           │                     │                     │       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Integration Layer                              │ │
│  │  • Service Registration  • API Endpoints  • Health Checks  │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

The monitoring system is integrated into the MCP Cortex project. All components are available in the `src/monitoring/` directory.

### Basic Setup

```typescript
import { setupRetryBudgetMonitoring, registerServiceForMonitoring } from './src/monitoring/retry-budget-index.js';

// Initialize the monitoring system
await setupRetryBudgetMonitoring();

// Register a service for monitoring
registerServiceForMonitoring('user-service', 'user-service-circuit', {
  maxRetriesPerMinute: 100,
  maxRetriesPerHour: 2000,
  warningThresholdPercent: 70,
  criticalThresholdPercent: 85,
  sloTargets: {
    availability: 99.9,
    latency: 300,
    errorRate: 0.05
  },
  dependencies: ['database-service', 'cache-service'],
  team: 'backend-team',
  environment: 'production'
});
```

### Express.js Integration

```typescript
import express from 'express';
import { retryMonitoringIntegration } from './src/monitoring/retry-monitoring-integration.js';

const app = express();

// Set up unified API endpoints
retryMonitoringIntegration.setupExpressRoutes(app);

// Start the monitoring system
await retryMonitoringIntegration.start();
await retryMonitoringIntegration.initialize();

app.listen(3000, () => {
  console.log('Server with retry budget monitoring running on port 3000');
});
```

## Core Components

### 1. Retry Budget Monitor (`retry-budget-monitor.ts`)

Core component that tracks retry budget consumption and provides real-time metrics.

**Key Features:**
- Real-time budget consumption tracking
- Configurable thresholds and limits
- SLO compliance monitoring
- Predictive analysis for budget exhaustion

**Usage:**
```typescript
import { retryBudgetMonitor } from './src/monitoring/retry-budget-monitor.js';

// Get current metrics for all services
const allMetrics = retryBudgetMonitor.getAllMetrics();

// Get metrics for specific service
const serviceMetrics = retryBudgetMonitor.getMetrics('user-service');

// Record retry consumption
retryBudgetMonitor.recordRetryConsumption({
  serviceName: 'user-service',
  timestamp: new Date(),
  retryCount: 3,
  operationType: 'api_call',
  responseTime: 250,
  success: true,
  circuitBreakerState: 'closed'
});
```

### 2. Circuit Breaker Monitor (`circuit-breaker-monitor.ts`)

Monitors circuit breaker states and correlates them with retry budget impacts.

**Key Features:**
- Real-time circuit breaker state tracking
- Performance impact analysis
- Health status calculation
- Alert integration

**Usage:**
```typescript
import { circuitBreakerMonitor } from './src/monitoring/circuit-breaker-monitor.js';

// Get health status for all circuits
const allStatuses = circuitBreakerMonitor.getAllHealthStatuses();

// Get health status for specific circuit
const status = circuitBreakerMonitor.getHealthStatus('user-service-circuit');

// Get active alerts
const alerts = circuitBreakerMonitor.getActiveAlerts();
```

### 3. Alert System (`retry-alert-system.ts`)

Intelligent alerting system with configurable rules, escalation policies, and multi-channel notifications.

**Key Features:**
- Configurable alert rules
- Multi-channel notifications (Email, Slack, PagerDuty)
- Alert correlation and escalation
- Predictive alerting

**Usage:**
```typescript
import { retryAlertSystem } from './src/monitoring/retry-alert-system.js';

// Add custom alert rule
retryAlertSystem.addAlertRule({
  id: 'custom_budget_rule',
  name: 'Custom Budget Warning',
  description: 'Alert when budget exceeds custom threshold',
  type: AlertType.BUDGET_WARNING,
  severity: AlertSeverity.WARNING,
  enabled: true,
  conditions: [{
    metric: 'budget_utilization_percent',
    operator: '>=',
    threshold: 80,
    duration: 300 // 5 minutes
  }],
  notifications: {
    channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
    cooldownMinutes: 15
  }
});

// Get active alerts
const activeAlerts = retryAlertSystem.getActiveAlerts();

// Acknowledge an alert
retryAlertSystem.acknowledgeAlert('alert-id', 'operator-name');
```

### 4. Trend Analyzer (`retry-trend-analyzer.ts`)

Advanced trend analysis and pattern detection with predictive capabilities.

**Key Features:**
- Historical trend analysis
- Anomaly detection
- Pattern recognition
- Predictive analytics

**Usage:**
```typescript
import { retryTrendAnalyzer } from './src/monitoring/retry-trend-analyzer.js';

// Analyze trends for a service
const trends = retryTrendAnalyzer.analyzeTrends('user-service', 'budget_utilization_percent', '24h');

// Detect anomalies
const anomalies = retryTrendAnalyzer.detectAnomalies('user-service', 24);

// Get predictive analysis
const predictions = retryTrendAnalyzer.performPredictiveAnalysis('user-service');

// Generate comprehensive service report
const report = retryTrendAnalyzer.getServiceReport('user-service', '7d');
```

### 5. Comprehensive Dashboard (`comprehensive-retry-dashboard.ts`)

Full-featured dashboard system with multiple views and real-time updates.

**Key Features:**
- Multiple dashboard views (Overview, Service Detail, Dependency Map, Trends, Alerts, Predictions, SLO)
- Real-time updates via Server-Sent Events
- Service dependency visualization
- Interactive charts and graphs

**Usage:**
```typescript
import { comprehensiveRetryDashboard } from './src/monitoring/comprehensive-retry-dashboard.js';

// Get overview data
const overview = await comprehensiveRetryDashboard.getOverviewData();

// Get service detail
const serviceDetail = await comprehensiveRetryDashboard.getServiceDetailData('user-service', '24h');

// Get dependency map
const dependencyMap = await comprehensiveRetryDashboard.getDependencyMapData();

// Export dashboard data
const exportData = await comprehensiveRetryDashboard.exportData('overview', 'json');
```

## API Endpoints

The system provides a comprehensive REST API for accessing monitoring data:

### Base Path: `/api/v1/retry-monitoring`

#### Core Endpoints

- `GET /status` - Get unified monitoring status
- `GET /health` - Get comprehensive health report
- `GET /metrics` - Get unified metrics (supports format parameter: json, prometheus, csv)
- `GET /services` - List registered services
- `GET /services/:serviceName` - Get service details

#### Dashboard Endpoints

- `GET /dashboard/overview` - Overview dashboard data
- `GET /dashboard/dependency-map` - Service dependency map
- `GET /dashboard/trends` - Trend analysis data
- `GET /dashboard/alerts` - Active alerts
- `GET /dashboard/predictions` - Predictive analysis
- `GET /dashboard/slo` - SLO compliance data

#### Real-time Updates

- `GET /dashboard/:view/subscribe` - Subscribe to real-time updates via Server-Sent Events

### Example API Calls

```bash
# Get monitoring status
curl http://localhost:3000/api/v1/retry-monitoring/status

# Get health report
curl http://localhost:3000/api/v1/retry-monitoring/health

# Get Prometheus metrics
curl http://localhost:3000/api/v1/retry-monitoring/metrics?format=prometheus

# Get service details
curl http://localhost:3000/api/v1/retry-monitoring/services/user-service

# Get overview dashboard
curl http://localhost:3000/api/v1/retry-monitoring/dashboard/overview

# Subscribe to real-time updates
curl -N http://localhost:3000/api/v1/retry-monitoring/dashboard/overview/subscribe
```

## Configuration

### Retry Budget Configuration

```typescript
interface RetryBudgetConfig {
  serviceName: string;
  circuitBreakerName: string;

  // Retry limits
  maxRetriesPerMinute: number;
  maxRetriesPerHour: number;
  maxRetryRatePercent: number;

  // Alert thresholds
  warningThresholdPercent: number;
  criticalThresholdPercent: number;

  // SLO targets
  sloTargetSuccessRate: number;
  sloTargetResponseTime: number;

  // Advanced features
  adaptiveBudgeting: boolean;
  minBudgetRetries: number;
  maxBudgetRetries: number;
}
```

### Alert Rule Configuration

```typescript
interface AlertRule {
  id: string;
  name: string;
  type: AlertType;
  severity: AlertSeverity;
  enabled: boolean;

  conditions: [{
    metric: string;
    operator: '>' | '<' | '=' | '>=' | '<=';
    threshold: number;
    duration?: number;
  }];

  notifications: {
    channels: AlertChannel[];
    cooldownMinutes: number;
    escalationPolicy?: string;
  };
}
```

### Integration Configuration

```typescript
interface RetryMonitoringIntegrationConfig {
  system: {
    autoStartServices: boolean;
    enableHealthChecks: boolean;
    metricsCollectionIntervalMs: number;
  };

  services: {
    autoRegisterCircuitBreakers: boolean;
    defaultRetryBudgetConfig: Partial<RetryBudgetConfig>;
    serviceDiscoveryEnabled: boolean;
  };

  monitoring: {
    integrateWithPerformanceCollector: boolean;
    integrateWithHealthChecks: boolean;
    exportToExistingMetrics: boolean;
  };

  api: {
    enableUnifiedEndpoints: boolean;
    basePath: string;
    enableCors: boolean;
    rateLimitingEnabled: boolean;
  };
}
```

## Monitoring Metrics

### Retry Budget Metrics

- `retry_budget_utilization_percent` - Current budget utilization percentage
- `retry_budget_remaining_retries_minute` - Remaining retries in current minute
- `retry_budget_remaining_retries_hour` - Remaining retries in current hour
- `retry_rate_percent` - Current retry rate percentage
- `slo_success_rate_compliance` - SLO success rate compliance (1/0)
- `slo_response_time_compliance` - SLO response time compliance (1/0)
- `retry_budget_risk_level` - Risk level (0=low, 1=medium, 2=high, 3=critical)

### Circuit Breaker Metrics

- `circuit_breaker_state` - Circuit breaker state (0=closed, 1=open, 2=half-open)
- `circuit_breaker_failure_rate` - Circuit breaker failure rate percentage
- `circuit_breaker_success_rate` - Circuit breaker success rate percentage
- `circuit_breaker_consecutive_failures` - Circuit breaker consecutive failures

## Grafana Integration

The system automatically generates Grafana dashboard configurations. Key panels include:

1. **Retry Budget Utilization** - Real-time utilization across services
2. **Circuit Breaker States** - Current circuit breaker states
3. **Retry Rate Over Time** - Historical retry rate trends
4. **SLO Compliance** - SLO compliance status
5. **Service Dependencies** - Dependency health visualization
6. **Error Budget Consumption** - Error budget usage tracking

## Prometheus Integration

Metrics are automatically exported in Prometheus format and can be scraped by Prometheus server:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'retry-budget-monitoring'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/api/v1/retry-monitoring/metrics'
    scrape_interval: 30s
```

## Best Practices

### 1. Service Registration

- Register all services with circuit breakers for monitoring
- Configure appropriate retry budget limits based on service criticality
- Set SLO targets that align with business requirements
- Define service dependencies for impact analysis

### 2. Alert Configuration

- Set warning thresholds at 70-75% utilization
- Set critical thresholds at 85-90% utilization
- Configure escalation policies for critical alerts
- Use multi-channel notifications for critical alerts

### 3. Dashboard Usage

- Monitor the overview dashboard for system-wide health
- Use service detail views for deep-dive analysis
- Check dependency maps for impact analysis
- Review trend analysis for capacity planning

### 4. Performance Optimization

- Enable caching for dashboard data
- Configure appropriate data retention periods
- Use adaptive budgeting for dynamic scaling
- Monitor system performance impact

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Reduce data retention periods
   - Disable unused features
   - Optimize cache settings

2. **Missing Metrics**
   - Verify service registration
   - Check circuit breaker integration
   - Validate retry budget configuration

3. **Alert Fatigue**
   - Adjust alert thresholds
   - Configure appropriate cooldown periods
   - Use alert correlation and escalation

4. **Dashboard Performance**
   - Enable data caching
   - Reduce real-time update frequency
   - Optimize data queries

### Debug Information

Enable debug logging to troubleshoot issues:

```typescript
import { logger } from './src/utils/logger.js';
logger.level = 'debug';
```

Check monitoring status:

```typescript
import { retryMonitoringIntegration } from './src/monitoring/retry-monitoring-integration.js';
const status = retryMonitoringIntegration.getMonitoringStatus();
console.log('Monitoring Status:', status);
```

## Contributing

When contributing to the retry budget monitoring system:

1. Follow the existing code patterns and structure
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure backward compatibility
5. Monitor performance impact of changes

## License

This monitoring system is part of the MCP Cortex project and follows the same license terms.