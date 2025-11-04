# Cortex Memory MCP - Monitoring Setup Guide

This guide provides comprehensive instructions for setting up monitoring and alerting for the Cortex Memory MCP server using Prometheus, Grafana, and Alertmanager.

## Overview

The monitoring stack includes:

- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Alertmanager**: Alert routing and notification
- **Node Exporter**: System metrics (optional)
- **Docker Compose**: Easy deployment of the monitoring stack

## Prerequisites

- Docker and Docker Compose installed
- Cortex MCP server running (with monitoring enabled)
- At least 4GB RAM and 10GB disk space for monitoring stack

## Quick Start

### 1. Start Monitoring Stack

```bash
# Clone and navigate to the cortex-mcp repository
git clone https://github.com/cortex-ai/cortex-memory-mcp.git
cd cortex-memory-mcp

# Start the monitoring stack
docker-compose -f docker/monitoring-stack.yml up -d
```

### 2. Verify Services

```bash
# Check all services are running
docker-compose -f docker/monitoring-stack.yml ps

# Check logs for any issues
docker-compose -f docker/monitoring-stack.yml logs
```

### 3. Access Dashboards

- **Grafana**: http://localhost:3000 (admin/admin123)
- **Prometheus**: http://localhost:9091
- **Alertmanager**: http://localhost:9093

### 4. Verify Metrics Collection

```bash
# Check if Cortex MCP metrics are available
curl http://localhost:9090/metrics

# Verify Prometheus is scraping metrics
curl "http://localhost:9091/api/v1/query?query=up"
```

## Configuration

### Environment Variables

Configure monitoring behavior using these environment variables:

```bash
# Monitoring Server
MONITORING_PORT=9090              # Port for monitoring server
MONITORING_HOST=0.0.0.0          # Host binding
MONITORING_ENABLE_AUTH=false     # Enable authentication
MONITORING_ENABLE_CORS=true      # Enable CORS

# Cortex MCP
NODE_ENV=production              # Environment
METRICS_COLLECTION=true          # Enable metrics collection
```

### Prometheus Configuration

The Prometheus configuration is located in `prometheus/prometheus.yml`:

```yaml
# Key settings to adjust:
scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['localhost:9090']  # Your Cortex MCP host
    scrape_interval: 15s            # How often to scrape
    metrics_path: '/metrics'         # Metrics endpoint
```

### Alert Rules

Alert rules are defined in `prometheus/alerts/cortex.rules.yaml`:

- **Latency alerts**: P95 > 1000ms, P99 > 2000ms
- **Error rate alerts**: > 2% for 5 minutes
- **Memory alerts**: > 4GB (warning), > 6GB (critical)
- **Circuit breaker alerts**: Open state for 2 minutes
- **Qdrant alerts**: Connection failures, high response time

## Grafana Dashboards

### Import Dashboard

The pre-configured dashboard is automatically provisioned. If you need to import it manually:

1. Navigate to Grafana: http://localhost:3000
2. Go to Dashboards → Import
3. Upload `grafana/dashboards/cortex.json`

### Dashboard Panels

The dashboard includes the following panels:

1. **System Status**: Overall health status
2. **Service Uptime**: Service uptime in hours
3. **Operations per Second**: Total QPS
4. **Active Connections**: Current active connections
5. **Query Rate by Operation**: QPS broken down by operation
6. **Memory Usage Breakdown**: Memory usage by type
7. **95th Percentile Latency**: P95 latency by operation
8. **99th Percentile Latency**: P99 latency by operation
9. **Quality Metrics**: Deduplication, cache hit, error rates
10. **Error Count by Severity**: Errors grouped by severity
11. **Operation Rate Trend**: Operations over time
12. **Memory Usage Trend**: Memory usage over time

## Alerting

### Alert Severities

- **Critical**: Immediate action required (e.g., service down, circuit breaker open)
- **High**: Urgent attention needed (e.g., high latency, critical errors)
- **Warning**: Investigation recommended (e.g., high memory usage, low cache hit rate)
- **Info**: Informational (e.g., service restart, low usage)

### Alert Channels

Configure alert channels in Alertmanager (`alertmanager/alertmanager.yml`):

```yaml
receivers:
  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@cortex-mcp.local'
        subject: '[CRITICAL] Cortex MCP: {{ .GroupLabels.alertname }}'
```

### Common Alert Scenarios

| Alert | Cause | Action |
|-------|-------|--------|
| High P95 Latency | Performance bottleneck | Check resource usage, optimize queries |
| High Memory Usage | Memory leak or high load | Investigate memory usage, restart if needed |
| Circuit Breaker Open | Dependency failure | Check external service status |
| Qdrant Connection Failure | Database connectivity issue | Check Qdrant service status |
| High Error Rate | Application errors | Review application logs |

## Metrics Reference

### Core Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cortex_qps` | gauge | Queries per second by operation |
| `cortex_latency_milliseconds` | histogram | Operation latency with percentiles |
| `cortex_memory_bytes` | gauge | Memory usage by type |
| `cortex_errors_total` | counter | Total errors by severity |
| `cortex_operations_total` | counter | Total operations processed |

### Circuit Breaker Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cortex_circuit_breaker_state` | gauge | Circuit breaker state (0=closed, 1=open, 2=half_open) |
| `cortex_circuit_breaker_failures_total` | counter | Total failures |
| `cortex_circuit_breaker_successes_total` | counter | Total successes |

### Quality Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cortex_quality_percent` | gauge | Quality metrics (dedupe rate, cache hit rate, etc.) |
| `cortex_connections_active` | gauge | Active connections |

## Troubleshooting

### Common Issues

1. **Prometheus not scraping metrics**
   ```bash
   # Check if metrics endpoint is accessible
   curl http://localhost:9090/metrics

   # Check Prometheus targets
   curl http://localhost:9091/api/v1/targets
   ```

2. **Grafana dashboard not showing data**
   - Verify Prometheus datasource is configured
   - Check time range in Grafana
   - Verify metric names in queries

3. **Alerts not firing**
   - Check alert rules syntax: `docker exec cortex-prometheus promtool check rules /etc/prometheus/alerts/*.yml`
   - Verify Alertmanager configuration
   - Check alert routing rules

4. **High memory usage in monitoring stack**
   ```bash
   # Check Prometheus memory usage
   docker stats cortex-prometheus

   # Adjust retention settings in prometheus.yml
   # Reduce storage retention or size limits
   ```

### Performance Tuning

1. **Prometheus Optimization**
   ```yaml
   # In prometheus.yml
   storage:
     tsdb:
       retention.time: 7d  # Reduce retention
       retention.size: 5GB # Reduce size limit
   ```

2. **Grafana Optimization**
   - Reduce dashboard refresh rate
   - Use efficient queries
   - Limit time range for large datasets

3. **Cortex MCP Optimization**
   - Adjust metrics collection interval
   - Disable unnecessary metrics
   - Optimize memory usage

## Scaling Considerations

### High Availability

For production deployments:

1. **Multiple Prometheus Instances**
   ```yaml
   # Use Prometheus federation or Thanos for HA
   ```

2. **Grafana HA**
   ```yaml
   grafana:
     image: grafana/grafana:10.2.0
     deploy:
       replicas: 2
   ```

3. **Persistent Storage**
   ```yaml
   volumes:
     - prometheus_data:/prometheus
     - grafana_data:/var/lib/grafana
   ```

### Long-term Storage

For long-term metrics retention:

1. **Configure Remote Storage**
   ```yaml
   # In prometheus.yml
   remote_write:
     - url: "http://your-storage:9201/api/v1/write"
   ```

2. **Use Cortex/VictoriaMetrics**
   - Deploy dedicated metrics storage
   - Configure appropriate retention policies

## Security

### Authentication

1. **Grafana Authentication**
   ```yaml
   environment:
     - GF_SECURITY_ADMIN_USER=admin
     - GF_SECURITY_ADMIN_PASSWORD=secure-password
   ```

2. **Prometheus Authentication**
   - Use reverse proxy with authentication
   - Configure TLS encryption

3. **Network Security**
   ```yaml
   networks:
     - monitoring:
         internal: true
         driver: bridge
   ```

## Maintenance

### Regular Tasks

1. **Monitor Disk Usage**
   ```bash
   df -h
   docker system df
   ```

2. **Clean Up Old Data**
   ```bash
   # Clean up unused Docker resources
   docker system prune -f
   ```

3. **Update Monitoring Stack**
   ```bash
   # Pull latest images
   docker-compose -f docker/monitoring-stack.yml pull

   # Restart with new images
   docker-compose -f docker/monitoring-stack.yml up -d
   ```

### Backup and Recovery

1. **Backup Configuration**
   ```bash
   tar -czf monitoring-config-backup.tar.gz prometheus/ grafana/ alertmanager/
   ```

2. **Backup Data**
   ```bash
   # Backup Prometheus data
   docker run --rm -v cortex-prometheus_data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-data-backup.tar.gz -C /data .
   ```

## Integration with Other Systems

### Slack Integration

Add to `alertmanager/alertmanager.yml`:

```yaml
receivers:
  - name: 'slack-alerts'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#alerts'
        title: 'Cortex MCP Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

### PagerDuty Integration

```yaml
receivers:
  - name: 'pagerduty-alerts'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
        description: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

## Support

For issues with the monitoring setup:

1. Check the logs: `docker-compose -f docker/monitoring-stack.yml logs [service]`
2. Verify configurations with validation tools
3. Consult the official documentation:
   - [Prometheus Documentation](https://prometheus.io/docs/)
   - [Grafana Documentation](https://grafana.com/docs/)
   - [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)

## Next Steps

After setting up monitoring:

1. Configure alert channels for your team
2. Customize alert thresholds based on your SLA requirements
3. Set up additional dashboards for specific use cases
4. Integrate with your existing monitoring infrastructure
5. Set up automated backup and recovery procedures