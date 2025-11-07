# Monitoring and Alerting Setup Guide

## Overview

This guide provides comprehensive instructions for setting up monitoring, alerting, and observability for MCP-Cortex AI services. It covers Prometheus metrics collection, Grafana dashboards, alert configuration, and integration with various monitoring tools.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Monitoring Architecture](#monitoring-architecture)
3. [Prometheus Setup](#prometheus-setup)
4. [Grafana Dashboard Configuration](#grafana-dashboard-configuration)
5. [Alert Manager Setup](#alert-manager-setup)
6. [AI-Specific Monitoring](#ai-specific-monitoring)
7. [Log Management](#log-management)
8. [Distributed Tracing](#distributed-tracing)
9. [Custom Monitoring Tools](#custom-monitoring-tools)
10. [Testing and Validation](#testing-and-validation)

## Prerequisites

### System Requirements

**Minimum:**

- 2 CPU cores
- 4GB RAM
- 20GB storage
- Network access to MCP-Cortex services

**Recommended:**

- 4+ CPU cores
- 8GB+ RAM
- 100GB+ storage
- Dedicated monitoring network segment

### Software Dependencies

- Docker 20.x+
- Docker Compose
- Node.js 18.x+ (for custom tools)
- Kubernetes (optional, for cluster deployment)

### External Services

- Notification channels (Slack, PagerDuty, Email)
- Log aggregation (ELK stack, Loki)
- Time-series database (Prometheus, InfluxDB)

## Monitoring Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   AI Services   │────▶│   Metrics Export │────▶│   Prometheus    │
│  (mcp-cortex)   │    │   (Node Export)  │    │   Collection   │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                                             │
         │                                             ▼
         │                                   ┌─────────────────┐
         │                                   │   Grafana       │
         │                                   │   Dashboards    │
         │                                   └─────────────────┘
         │                                             │
         ▼                                             ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   Application   │────▶│   Alert Manager  │────▶│ Notifications   │
│     Logs        │    │   (Routing &     │    │ (Slack/PagerDuty)│
│                 │    │    Escalation)   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Prometheus Setup

### 1. Docker Compose Configuration

```yaml
# monitoring/docker-compose.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.40.0
    container_name: prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/rules:/etc/prometheus/rules
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:v0.25.0
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager
    restart: unless-stopped

  grafana:
    image: grafana/grafana:9.2.0
    container_name: grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:v1.5.0
    container_name: node-exporter
    ports:
      - "9100:9100"
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    restart: unless-stopped

  cAdvisor:
    image: gcr.io/cadvisor/cadvisor:v0.46.0
    container_name: cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:rw
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    privileged: true
    restart: unless-stopped

volumes:
  prometheus_data:
  alertmanager_data:
  grafana_data:
```

### 2. Prometheus Configuration

```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    region: 'us-west-2'

rule_files:
  - '/etc/prometheus/rules/*.yml'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093

scrape_configs:
  # MCP Cortex AI Services
  - job_name: 'mcp-cortex-ai'
    static_configs:
      - targets: ['mcp-cortex-ai:3000']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s
    honor_labels: true

  # Application health endpoints
  - job_name: 'mcp-cortex-health'
    static_configs:
      - targets: ['mcp-cortex-ai:3000']
    metrics_path: '/health/metrics'
    scrape_interval: 15s
    scrape_timeout: 5s

  # System metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  # Container metrics
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
    metrics_path: '/metrics'

  # Qdrant vector database
  - job_name: 'qdrant'
    static_configs:
      - targets: ['qdrant:6333']
    metrics_path: '/metrics'
    scrape_interval: 30s

  # Redis cache
  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
# Remote write configuration for long-term storage
# remote_write:
#   - url: "http://influxdb:8086/api/v1/prom/write?db=prometheus"
#     queue_config:
#       max_samples_per_send: 1000
#       max_shards: 200
#       capacity: 2500
```

### 3. AI Service Metrics Export

```typescript
// src/monitoring/prometheus-exporter.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';
import { aiMetricsService } from './ai-metrics.service.js';
import { aiHealthMonitor } from './ai-health-monitor.js';

// Define custom metrics
const aiOperationDuration = new Histogram({
  name: 'ai_operation_duration_seconds',
  help: 'Duration of AI operations in seconds',
  labelNames: ['operation_type', 'model', 'status'],
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60],
});

const aiOperationTotal = new Counter({
  name: 'ai_operation_total',
  help: 'Total number of AI operations',
  labelNames: ['operation_type', 'model', 'status'],
});

const aiOperationErrors = new Counter({
  name: 'ai_operation_errors_total',
  help: 'Total number of AI operation errors',
  labelNames: ['operation_type', 'model', 'error_type'],
});

const aiInsightAccuracy = new Gauge({
  name: 'ai_insight_accuracy',
  help: 'Current accuracy of AI insights',
  labelNames: ['strategy'],
});

const aiContradictionDetectionAccuracy = new Gauge({
  name: 'ai_contradiction_detection_accuracy',
  help: 'Current accuracy of contradiction detection',
  labelNames: ['strategy'],
});

const aiQueueDepth = new Gauge({
  name: 'ai_queue_depth',
  help: 'Current depth of AI background processing queue',
});

const aiResourceUsage = new Gauge({
  name: 'ai_resource_usage_percent',
  help: 'Resource usage percentage for AI services',
  labelNames: ['resource_type'],
});

// Register metrics
register.registerMetric(aiOperationDuration);
register.registerMetric(aiOperationTotal);
register.registerMetric(aiOperationErrors);
register.registerMetric(aiInsightAccuracy);
register.registerMetric(aiContradictionDetectionAccuracy);
register.registerMetric(aiQueueDepth);
register.registerMetric(aiResourceUsage);

// Metrics collection
export class PrometheusExporter {
  static async collectMetrics() {
    try {
      const metrics = aiMetricsService.getCurrentMetrics();
      const health = aiHealthMonitor.getOverallHealth();

      // Operation metrics
      aiOperationDuration
        .labels('insight_generation', 'glm-4.6', 'success')
        .observe(metrics.operations.averageLatency / 1000);

      aiOperationTotal
        .labels('insight_generation', 'glm-4.6', 'success')
        .inc(metrics.operations.successful);

      aiOperationTotal
        .labels('insight_generation', 'glm-4.6', 'error')
        .inc(metrics.operations.failed);

      // Accuracy metrics
      Object.entries(metrics.insights.strategies).forEach(([strategy, count]) => {
        aiInsightAccuracy.labels(strategy).set(metrics.insights.accuracy);
      });

      Object.entries(metrics.contradiction.strategies).forEach(([strategy, count]) => {
        aiContradictionDetectionAccuracy.labels(strategy).set(metrics.contradiction.accuracy);
      });

      // Resource metrics
      aiResourceUsage.labels('memory').set(metrics.resources.memoryUsage);
      aiResourceUsage.labels('cpu').set(metrics.resources.cpuUsage);

      // Queue metrics
      aiQueueDepth.set(metrics.operations.pending);
    } catch (error) {
      console.error('Failed to collect Prometheus metrics:', error);
    }
  }

  static recordOperation(
    operationType: string,
    model: string,
    duration: number,
    status: string,
    errorType?: string
  ) {
    aiOperationDuration.labels(operationType, model, status).observe(duration);
    aiOperationTotal.labels(operationType, model, status).inc();

    if (status === 'error' && errorType) {
      aiOperationErrors.labels(operationType, model, errorType).inc();
    }
  }
}

// Start metrics collection
setInterval(() => {
  PrometheusExporter.collectMetrics();
}, 15000); // Every 15 seconds
```

## Grafana Dashboard Configuration

### 1. Grafana Provisioning

```json
// monitoring/grafana/provisioning/datasources/prometheus.yml
{
  "apiVersion": 1,
  "datasources": [
    {
      "id": 1,
      "name": "Prometheus",
      "type": "prometheus",
      "access": "proxy",
      "url": "http://prometheus:9090",
      "isDefault": true,
      "editable": true,
      "jsonData": {
        "timeInterval": "15s",
        "queryTimeout": "60s",
        "httpMethod": "POST"
      }
    }
  ]
}
```

```json
// monitoring/grafana/provisioning/dashboards/ai-dashboard.yml
{
  "apiVersion": 1,
  "providers": [
    {
      "name": "default",
      "orgId": 1,
      "folder": "",
      "type": "file",
      "disableDeletion": false,
      "updateIntervalSeconds": 10,
      "allowUiUpdates": true,
      "options": {
        "path": "/var/lib/grafana/dashboards"
      }
    }
  ]
}
```

### 2. AI Services Overview Dashboard

```json
// monitoring/grafana/dashboards/ai-services-overview.json
{
  "dashboard": {
    "id": null,
    "title": "AI Services Overview",
    "tags": ["ai", "mcp-cortex"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Service Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"mcp-cortex-ai\"}",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {
                "options": {
                  "0": {
                    "text": "DOWN",
                    "color": "red"
                  },
                  "1": {
                    "text": "UP",
                    "color": "green"
                  }
                },
                "type": "value"
              }
            ]
          }
        },
        "gridPos": { "h": 8, "w": 6, "x": 0, "y": 0 }
      },
      {
        "id": 2,
        "title": "AI Operations Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ai_operation_total[5m])",
            "refId": "A",
            "legendFormat": "{{operation_type}}"
          }
        ],
        "yAxes": [
          {
            "label": "Operations/sec"
          }
        ],
        "gridPos": { "h": 8, "w": 12, "x": 6, "y": 0 }
      },
      {
        "id": 3,
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(ai_operation_errors_total[5m]) / rate(ai_operation_total[5m]) * 100",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "thresholds": {
              "steps": [
                { "color": "green", "value": null },
                { "color": "yellow", "value": 5 },
                { "color": "red", "value": 10 }
              ]
            }
          }
        },
        "gridPos": { "h": 8, "w": 6, "x": 18, "y": 0 }
      },
      {
        "id": 4,
        "title": "Response Time P95",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, ai_operation_duration_seconds)",
            "refId": "A",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.50, ai_operation_duration_seconds)",
            "refId": "B",
            "legendFormat": "P50"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds"
          }
        ],
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 8 }
      },
      {
        "id": 5,
        "title": "AI Insight Accuracy",
        "type": "graph",
        "targets": [
          {
            "expr": "ai_insight_accuracy",
            "refId": "A",
            "legendFormat": "{{strategy}}"
          }
        ],
        "yAxes": [
          {
            "label": "Accuracy",
            "min": 0,
            "max": 1
          }
        ],
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": 8 }
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

### 3. Performance Dashboard

```json
// monitoring/grafana/dashboards/ai-performance.json
{
  "dashboard": {
    "id": null,
    "title": "AI Performance Metrics",
    "tags": ["ai", "performance"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Resource Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "ai_resource_usage_percent{resource_type=\"memory\"}",
            "refId": "A",
            "legendFormat": "Memory"
          },
          {
            "expr": "ai_resource_usage_percent{resource_type=\"cpu\"}",
            "refId": "B",
            "legendFormat": "CPU"
          }
        ],
        "yAxes": [
          {
            "label": "Usage %",
            "max": 100
          }
        ],
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 }
      },
      {
        "id": 2,
        "title": "Queue Depth",
        "type": "graph",
        "targets": [
          {
            "expr": "ai_queue_depth",
            "refId": "A"
          }
        ],
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 }
      },
      {
        "id": 3,
        "title": "Operation Latency Distribution",
        "type": "heatmap",
        "targets": [
          {
            "expr": "rate(ai_operation_duration_seconds_bucket[5m])",
            "refId": "A",
            "legendFormat": "{{le}}"
          }
        ],
        "gridPos": { "h": 8, "w": 24, "x": 0, "y": 8 }
      }
    ],
    "time": {
      "from": "now-3h",
      "to": "now"
    },
    "refresh": "15s"
  }
}
```

## Alert Manager Setup

### 1. Alert Manager Configuration

```yaml
# monitoring/alertmanager/alertmanager.yml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@yourcompany.com'
  smtp_auth_username: 'alerts@yourcompany.com'
  smtp_auth_password: 'your_app_password'

# Templates for notifications
templates:
  - '/etc/alertmanager/templates/*.tmpl'

# Routing configuration
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
    # Critical AI service alerts
    - match:
        severity: critical
        service: ai
      receiver: 'ai-critical'
      group_wait: 0s
      repeat_interval: 5m
      routes:
        - match:
            alertname: 'AIServiceDown'
          receiver: 'ai-emergency'
          continue: false

    # Performance alerts
    - match:
        severity: warning
        service: ai
      receiver: 'ai-performance'
      repeat_interval: 30m

    # Cost alerts
    - match:
        category: cost
      receiver: 'ai-cost'
      repeat_interval: 6h

# Inhibition rules
inhibit_rules:
  # If AI service is down, inhibit other AI alerts
  - source_match:
      alertname: 'AIServiceDown'
    target_match:
      service: ai
    equal: ['cluster', 'service']

# Receivers for different alert types
receivers:
  - name: 'default'
    email_configs:
      - to: 'ops-team@yourcompany.com'
        subject: '[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Labels: {{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }} {{ end }}
          {{ end }}

  - name: 'ai-critical'
    email_configs:
      - to: 'ai-team@yourcompany.com,ops-team@yourcompany.com'
        subject: '[CRITICAL] AI Service Alert: {{ .GroupLabels.alertname }}'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#ai-alerts'
        title: '🚨 Critical AI Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
    pagerduty_configs:
      - service_key: 'your-pagerduty-service-key'
        severity: 'critical'

  - name: 'ai-emergency'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#ai-emergency'
        title: '🚨 EMERGENCY: AI Services Down'
        text: |
          {{ range .Alerts }}
          *{{ .Annotations.summary }}*
          {{ .Annotations.description }}
          {{ end }}
    pagerduty_configs:
      - service_key: 'your-pagerduty-emergency-key'
        severity: 'critical'

  - name: 'ai-performance'
    email_configs:
      - to: 'ai-team@yourcompany.com'
        subject: '[WARNING] AI Performance Issue'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#ai-performance'

  - name: 'ai-cost'
    email_configs:
      - to: 'ai-team@yourcompany.com,finance@yourcompany.com'
        subject: '[INFO] AI Cost Alert'

# Timeouts
timeouts:
  resolve: 5m
```

### 2. AI-Specific Alert Rules

```yaml
# monitoring/prometheus/rules/ai-alerts.yml
groups:
  - name: ai_services
    rules:
      # Service availability
      - alert: AIServiceDown
        expr: up{job="mcp-cortex-ai"} == 0
        for: 1m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'AI service is down'
          description: 'AI service {{ $labels.instance }} has been down for more than 1 minute'
          runbook_url: 'https://runbooks.yourcompany.com/ai-service-down'

      # High latency alerts
      - alert: HighAILatency
        expr: histogram_quantile(0.95, rate(ai_operation_duration_seconds_bucket[5m])) > 10
        for: 5m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'High AI operation latency'
          description: '95th percentile latency is {{ $value }}s for {{ $labels.operation_type }}'
          runbook_url: 'https://runbooks.yourcompany.com/high-ai-latency'

      - alert: CriticalAILatency
        expr: histogram_quantile(0.95, rate(ai_operation_duration_seconds_bucket[5m])) > 30
        for: 2m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'Critical AI operation latency'
          description: '95th percentile latency is {{ $value }}s for {{ $labels.operation_type }}'

      # Error rate alerts
      - alert: HighAIErrorRate
        expr: rate(ai_operation_errors_total[5m]) / rate(ai_operation_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'High AI error rate'
          description: 'Error rate is {{ $value | humanizePercentage }} for {{ $labels.operation_type }}'

      - alert: CriticalAIErrorRate
        expr: rate(ai_operation_errors_total[5m]) / rate(ai_operation_total[5m]) > 0.15
        for: 2m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'Critical AI error rate'
          description: 'Error rate is {{ $value | humanizePercentage }} for {{ $labels.operation_type }}'

      # Queue depth alerts
      - alert: AIQueueBacklog
        expr: ai_queue_depth > 1000
        for: 10m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'AI processing queue backlog'
          description: 'Queue depth is {{ $value }} items'

      - alert: AIQueueCritical
        expr: ai_queue_depth > 5000
        for: 5m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'Critical AI processing queue'
          description: 'Queue depth is {{ $value }} items - service may be overwhelmed'

      # Resource usage alerts
      - alert: AIMemoryHigh
        expr: ai_resource_usage_percent{resource_type="memory"} > 85
        for: 10m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'High AI service memory usage'
          description: 'Memory usage is {{ $value }}%'

      - alert: AIMemoryCritical
        expr: ai_resource_usage_percent{resource_type="memory"} > 95
        for: 5m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'Critical AI service memory usage'
          description: 'Memory usage is {{ $value }}% - service may crash'

      # Accuracy degradation alerts
      - alert: AIAccuracyDegraded
        expr: ai_insight_accuracy < 0.8
        for: 15m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'AI insight accuracy degraded'
          description: 'Insight accuracy is {{ $value }} for strategy {{ $labels.strategy }}'

      # Model-specific alerts
      - alert: ZAIServiceUnhealthy
        expr: zai_api_health_status != 1
        for: 2m
        labels:
          severity: critical
          service: ai
          team: ai-team
        annotations:
          summary: 'Z.AI service unhealthy'
          description: 'Z.AI API health check failed - status: {{ $value }}'

  - name: ai_cost
    rules:
      # Cost monitoring alerts
      - alert: AIDailyBudgetExceeded
        expr: ai_daily_cost_total > ai_daily_budget_limit
        for: 0m
        labels:
          severity: critical
          category: cost
          team: ai-team
        annotations:
          summary: 'AI daily budget exceeded'
          description: 'Daily cost ${{ $value }} exceeds budget ${{ $value2 }}'

      - alert: AIMonthlyBudgetWarning
        expr: ai_monthly_cost_total / ai_monthly_budget_limit > 0.8
        for: 1h
        labels:
          severity: warning
          category: cost
          team: ai-team
        annotations:
          summary: 'AI monthly budget warning'
          description: 'Monthly cost is {{ $value | humanizePercentage }} of budget'

  - name: ai_background_jobs
    rules:
      # Background job monitoring
      - alert: AIBackgroundJobsStalled
        expr: time() - ai_background_job_last_success_timestamp > 300
        for: 5m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'AI background jobs stalled'
          description: 'No successful background job completion in 5 minutes'

      - alert: AIBackgroundJobFailures
        expr: rate(ai_background_job_failures_total[10m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: ai
          team: ai-team
        annotations:
          summary: 'High AI background job failure rate'
          description: 'Background job failure rate is {{ $value | humanizePercentage }}'
```

## AI-Specific Monitoring

### 1. Custom Metrics Collection

```typescript
// src/monitoring/ai-metrics-collector.ts
export class AIMetricsCollector {
  private metricsCollector: any;

  constructor() {
    this.setupMetricsCollection();
  }

  private setupMetricsCollection() {
    // Collect AI operation metrics
    setInterval(async () => {
      try {
        await this.collectAIMetrics();
      } catch (error) {
        console.error('Failed to collect AI metrics:', error);
      }
    }, 30000); // Every 30 seconds
  }

  private async collectAIMetrics() {
    // Get current metrics from AI services
    const metrics = aiMetricsService.getCurrentMetrics();
    const health = aiHealthMonitor.getOverallHealth();

    // Business metrics
    this.recordBusinessMetrics(metrics);

    // Technical metrics
    this.recordTechnicalMetrics(metrics);

    // Health metrics
    this.recordHealthMetrics(health);
  }

  private recordBusinessMetrics(metrics: any) {
    // Insight generation metrics
    this.emitMetric('ai.insights.generated', {
      value: metrics.insights.generated,
      tags: { strategy: 'all' },
    });

    this.emitMetric('ai.insights.accuracy', {
      value: metrics.insights.accuracy,
      tags: { metric_type: 'accuracy' },
    });

    // Contradiction detection metrics
    this.emitMetric('ai.contradictions.detected', {
      value: metrics.contradiction.detected,
      tags: { metric_type: 'detection' },
    });

    this.emitMetric('ai.contradictions.accuracy', {
      value: metrics.contradiction.accuracy,
      tags: { metric_type: 'accuracy' },
    });
  }

  private recordTechnicalMetrics(metrics: any) {
    // Performance metrics
    this.emitMetric('ai.operations.latency.avg', {
      value: metrics.operations.averageLatency,
      tags: { metric_type: 'latency', percentile: 'avg' },
    });

    this.emitMetric('ai.operations.latency.p95', {
      value: metrics.operations.latency_p95,
      tags: { metric_type: 'latency', percentile: 'p95' },
    });

    // Throughput metrics
    this.emitMetric('ai.operations.throughput', {
      value: metrics.operations.throughput,
      tags: { metric_type: 'throughput' },
    });

    // Error metrics
    this.emitMetric('ai.operations.error_rate', {
      value: metrics.quality.error_rate,
      tags: { metric_type: 'error_rate' },
    });
  }

  private recordHealthMetrics(health: any) {
    this.emitMetric('ai.health.status', {
      value: health.status === 'healthy' ? 1 : 0,
      tags: { status: health.status },
    });

    this.emitMetric('ai.health.consecutive_failures', {
      value: health.consecutiveFailures,
      tags: { metric_type: 'consecutive_failures' },
    });
  }

  private emitMetric(name: string, data: { value: number; tags: Record<string, string> }) {
    // Emit to your metrics system (Prometheus, DataDog, etc.)
    console.log(`Metric: ${name}`, data);
  }
}
```

### 2. Model Performance Monitoring

```typescript
// src/monitoring/model-performance-monitor.ts
export class ModelPerformanceMonitor {
  private performanceData: Map<string, Array<any>> = new Map();

  recordModelPerformance(
    model: string,
    operation: string,
    metrics: {
      accuracy: number;
      latency: number;
      confidence: number;
      tokensUsed: number;
      timestamp: number;
    }
  ) {
    const key = `${model}_${operation}`;

    if (!this.performanceData.has(key)) {
      this.performanceData.set(key, []);
    }

    const data = this.performanceData.get(key)!;
    data.push(metrics);

    // Keep only last 1000 data points
    if (data.length > 1000) {
      data.splice(0, data.length - 1000);
    }

    // Check for performance degradation
    this.checkPerformanceDegradation(model, operation, data);
  }

  private checkPerformanceDegradation(model: string, operation: string, data: any[]) {
    if (data.length < 50) return; // Need sufficient data

    const recent = data.slice(-20); // Last 20 data points
    const baseline = data.slice(-100, -20); // Previous data points

    const recentAccuracy = recent.reduce((sum, d) => sum + d.accuracy, 0) / recent.length;
    const baselineAccuracy = baseline.reduce((sum, d) => sum + d.accuracy, 0) / baseline.length;

    const recentLatency = recent.reduce((sum, d) => sum + d.latency, 0) / recent.length;
    const baselineLatency = baseline.reduce((sum, d) => sum + d.latency, 0) / baseline.length;

    // Check for significant degradation
    if (recentAccuracy < baselineAccuracy * 0.9) {
      this.triggerAlert('model_accuracy_degradation', {
        model,
        operation,
        currentAccuracy: recentAccuracy,
        baselineAccuracy,
        degradation: ((baselineAccuracy - recentAccuracy) / baselineAccuracy) * 100,
      });
    }

    if (recentLatency > baselineLatency * 1.5) {
      this.triggerAlert('model_latency_degradation', {
        model,
        operation,
        currentLatency: recentLatency,
        baselineLatency,
        degradation: ((recentLatency - baselineLatency) / baselineLatency) * 100,
      });
    }
  }

  private triggerAlert(type: string, data: any) {
    console.warn(`Model performance alert: ${type}`, data);
    // Send to alerting system
  }
}
```

## Log Management

### 1. Structured Logging Configuration

```typescript
// src/utils/structured-logger.ts
export class StructuredLogger {
  private logger: any;

  constructor(serviceName: string) {
    this.logger = this.createLogger(serviceName);
  }

  private createLogger(serviceName: string) {
    return {
      info: (message: string, context?: any) => {
        this.log('INFO', message, context);
      },
      warn: (message: string, context?: any) => {
        this.log('WARN', message, context);
      },
      error: (message: string, context?: any) => {
        this.log('ERROR', message, context);
      },
      debug: (message: string, context?: any) => {
        this.log('DEBUG', message, context);
      },
    };
  }

  private log(level: string, message: string, context?: any) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      service: 'mcp-cortex-ai',
      message,
      ...context,
    };

    console.log(JSON.stringify(logEntry));
  }

  // AI-specific logging methods
  logAIOperation(operation: string, data: any) {
    this.info(`AI Operation: ${operation}`, {
      operation_type: operation,
      duration_ms: data.duration,
      model: data.model,
      success: data.success,
      tokens_used: data.tokensUsed,
      confidence: data.confidence,
    });
  }

  logInsightGeneration(insightData: any) {
    this.info('Insight Generated', {
      strategy: insightData.strategy,
      confidence: insightData.confidence,
      items_processed: insightData.itemsProcessed,
      processing_time: insightData.processingTime,
    });
  }

  logContradictionDetection(contradictionData: any) {
    this.info('Contradiction Detected', {
      strategy: contradictionData.strategy,
      confidence: contradictionData.confidence,
      contradictions_found: contradictionData.found,
      items_analyzed: contradictionData.analyzed,
    });
  }
}
```

### 2. Log Aggregation with Loki

```yaml
# monitoring/docker-compose.loki.yml
version: '3.8'

services:
  loki:
    image: grafana/loki:2.7.0
    container_name: loki
    ports:
      - '3100:3100'
    volumes:
      - ./loki/loki.yml:/etc/loki/local-config.yaml
      - loki_data:/loki
    command: -config.file=/etc/loki/local-config.yaml
    restart: unless-stopped

  promtail:
    image: grafana/promtail:2.7.0
    container_name: promtail
    volumes:
      - ./promtail/promtail.yml:/etc/promtail/config.yml
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
    command: -config.file=/etc/promtail/config.yml
    restart: unless-stopped

volumes:
  loki_data:
```

```yaml
# monitoring/loki/loki.yml
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 1h
  max_chunk_age: 1h
  chunk_target_size: 1048576
  chunk_retain_period: 30s

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
```

## Distributed Tracing

### 1. OpenTelemetry Setup

```typescript
// src/monitoring/tracing.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-otlp-grpc';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';

// Initialize OpenTelemetry
export function initializeTracing(serviceName: string) {
  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);

  const sdk = new NodeSDK({
    resource: new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.SERVICE_VERSION]: '2.0.1',
    }),
    traceExporter: new OTLPTraceExporter({
      url: process.env.JAEGER_ENDPOINT || 'http://jaeger:4317',
    }),
    spanProcessor: new SimpleSpanProcessor(new OTLPTraceExporter()),
  });

  sdk.start();
  return sdk;
}
```

### 2. AI Operation Tracing

```typescript
// src/tracing/ai-tracer.ts
import { trace } from '@opentelemetry/api';

export class AITracer {
  private tracer = trace.getTracer('mcp-cortex-ai');

  async traceAIOperation<T>(
    operationName: string,
    operation: () => Promise<T>,
    attributes?: Record<string, any>
  ): Promise<T> {
    const span = this.tracer.startSpan(operationName, {
      attributes: {
        'service.name': 'mcp-cortex-ai',
        'operation.type': 'ai_operation',
        ...attributes,
      },
    });

    try {
      const startTime = Date.now();
      const result = await operation();
      const duration = Date.now() - startTime;

      span.setAttributes({
        'operation.duration_ms': duration,
        'operation.success': true,
      });

      span.setStatus({ code: 1 }); // OK
      return result;
    } catch (error) {
      span.setAttributes({
        'operation.success': false,
        'error.message': error instanceof Error ? error.message : 'Unknown error',
      });

      span.setStatus({
        code: 2, // ERROR
        message: error instanceof Error ? error.message : 'Unknown error',
      });

      throw error;
    } finally {
      span.end();
    }
  }

  traceInsightGeneration(
    strategy: string,
    itemsCount: number,
    operation: () => Promise<any>
  ): Promise<any> {
    return this.traceAIOperation('ai.insight_generation', operation, {
      'ai.strategy': strategy,
      'ai.items_count': itemsCount,
      'ai.operation_type': 'insight',
    });
  }

  traceContradictionDetection(
    strategy: string,
    itemsCount: number,
    operation: () => Promise<any>
  ): Promise<any> {
    return this.traceAIOperation('ai.contradiction_detection', operation, {
      'ai.strategy': strategy,
      'ai.items_count': itemsCount,
      'ai.operation_type': 'contradiction',
    });
  }
}
```

## Testing and Validation

### 1. Monitoring Setup Validation

```bash
#!/bin/bash
# scripts/validate-monitoring.sh

echo "=== Validating Monitoring Setup ==="

# 1. Check Prometheus is accessible
echo "1. Checking Prometheus..."
curl -s http://localhost:9090/api/v1/status/config || {
  echo "❌ Prometheus not accessible"
  exit 1
}
echo "✅ Prometheus accessible"

# 2. Check AI metrics are being exported
echo "2. Checking AI metrics..."
METRICS_COUNT=$(curl -s http://localhost:9090/api/v1/query?query=ai_operation_total | jq '.data.result | length')
if [ "$METRICS_COUNT" -eq 0 ]; then
    echo "⚠️  No AI metrics found - services may not be running"
else
    echo "✅ Found $METRICS_COUNT AI metrics"
fi

# 3. Check Alert Manager
echo "3. Checking Alert Manager..."
curl -s http://localhost:9093/api/v1/status || {
  echo "❌ Alert Manager not accessible"
  exit 1
}
echo "✅ Alert Manager accessible"

# 4. Check Grafana
echo "4. Checking Grafana..."
curl -s http://localhost:3001/api/health || {
    echo "❌ Grafana not accessible"
    exit 1
}
echo "✅ Grafana accessible"

# 5. Test alerting
echo "5. Testing alert configuration..."
# This would trigger a test alert
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts | length > 0'

echo "=== Monitoring Validation Complete ==="
```

### 2. Metrics Quality Check

```bash
#!/bin/bash
# scripts/check-metrics-quality.sh

echo "=== Checking Metrics Quality ==="

# Check for missing metrics
EXPECTED_METRICS=(
  "ai_operation_total"
  "ai_operation_duration_seconds"
  "ai_insight_accuracy"
  "ai_contradiction_detection_accuracy"
  "ai_queue_depth"
  "ai_resource_usage_percent"
)

for metric in "${EXPECTED_METRICS[@]}"; do
  if curl -s "http://localhost:9090/api/v1/query?query=$metric" | jq -e '.data.result | length > 0' > /dev/null; then
    echo "✅ $metric - present"
  else
    echo "❌ $metric - missing"
  fi
done

# Check for data freshness
echo "Checking data freshness..."
LATEST_TIMESTAMP=$(curl -s "http://localhost:9090/api/v1/query?query=time()" | jq -r '.data.result[0].value[1]')
CURRENT_TIME=$(date +%s)
AGE=$((CURRENT_TIME - LATEST_TIMESTAMP))

if [ $AGE -lt 300 ]; then
    echo "✅ Metrics data is fresh (age: ${AGE}s)"
else
    echo "⚠️  Metrics data is stale (age: ${AGE}s)"
fi

echo "=== Metrics Quality Check Complete ==="
```

### 3. Load Testing with Monitoring

```javascript
// tests/monitoring-load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 10 },
    { duration: '5m', target: 50 },
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],
    http_req_failed: ['rate<0.05'],
    'ai_operation_duration{operation_type="insight_generation"}': ['p(95)<10000'],
  },
};

export default function () {
  // Test AI status endpoint with monitoring
  let response = http.post(
    'http://localhost:3000/api/ai/status',
    JSON.stringify({
      include_metrics: true,
      include_health: true,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );

  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 5s': (r) => r.timings.duration < 5000,
  });

  // Test metrics endpoint
  response = http.get('http://localhost:3000/metrics');
  check(response, {
    'metrics endpoint returns 200': (r) => r.status === 200,
    'contains AI metrics': (r) => r.body.includes('ai_operation_total'),
  });

  sleep(1);
}
```

This comprehensive monitoring and alerting setup guide provides everything needed to monitor MCP-Cortex AI services effectively in production environments. The setup includes business metrics, technical metrics, health monitoring, and proactive alerting to ensure reliable operations.
