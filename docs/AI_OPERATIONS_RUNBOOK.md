# AI Operations Runbook

## Overview

This runbook provides step-by-step procedures for operating, monitoring, and troubleshooting MCP-Cortex AI services in production environments. It covers daily operations, incident response, maintenance procedures, and performance optimization.

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Daily Operations](#daily-operations)
3. [Health Monitoring](#health-monitoring)
4. [Incident Response](#incident-response)
5. [Performance Troubleshooting](#performance-troubleshooting)
6. [Maintenance Procedures](#maintenance-procedures)
7. [Emergency Procedures](#emergency-procedures)
8. [Communication Protocols](#communication-protocols)

## Quick Reference

### Critical Commands

```bash
# Check AI service health
curl -s http://localhost:3000/api/ai/status | jq .

# Check comprehensive status with metrics
curl -s -X POST http://localhost:3000/api/ai/status \
  -H "Content-Type: application/json" \
  -d '{"include_metrics": true, "include_health": true, "include_observability": true}' | jq .

# Check active alerts
curl -s http://localhost:3000/api/ai/status?include_observability=true | jq '.observability.active_alerts'

# Restart AI services
docker-compose restart mcp-cortex-ai

# Check logs
docker-compose logs -f --tail=100 mcp-cortex-ai

# Monitor resource usage
docker stats mcp-cortex-ai --no-stream

# Check circuit breaker status
curl -s http://localhost:3000/health/circuit-breaker | jq .
```

### Service Status Endpoints

| Endpoint         | Purpose                 | Expected Response            |
| ---------------- | ----------------------- | ---------------------------- |
| `/health`        | Basic health check      | `{"status": "healthy"}`      |
| `/health/ai`     | AI services health      | Detailed AI status           |
| `/api/ai/status` | Comprehensive AI status | Full AI metrics and health   |
| `/metrics`       | Prometheus metrics      | Metrics in Prometheus format |
| `/ready`         | Readiness probe         | `{"ready": true}`            |

## Daily Operations

### Morning Checklist (Daily 9:00 AM)

#### 1. Service Health Verification

```bash
#!/bin/bash
# scripts/daily-check.sh

echo "=== Daily AI Service Health Check ==="

# Check basic service health
echo "1. Basic Health Check:"
HEALTH_STATUS=$(curl -s http://localhost:3000/health | jq -r '.status')
echo "   Health Status: $HEALTH_STATUS"

if [ "$HEALTH_STATUS" != "healthy" ]; then
    echo "   ⚠️  Service is not healthy - investigating..."
    curl -s http://localhost:3000/health | jq .
fi

# Check AI services specifically
echo "2. AI Services Status:"
AI_STATUS=$(curl -s http://localhost:3000/health/ai | jq -r '.status')
echo "   AI Services: $AI_STATUS"

# Check Z.AI connectivity
echo "3. Z.AI API Connectivity:"
ZAI_STATUS=$(curl -s -H "Authorization: Bearer $ZAI_API_KEY" \
  https://api.z.ai/api/anthropic/health | jq -r '.status // "unknown"')
echo "   Z.AI API: $ZAI_STATUS"

# Check resource utilization
echo "4. Resource Utilization:"
MEMORY_USAGE=$(docker stats mcp-cortex-ai --no-stream --format "{{.MemPerc}}")
CPU_USAGE=$(docker stats mcp-cortex-ai --no-stream --format "{{.CPUPerc}}")
echo "   Memory: $MEMORY_USAGE"
echo "   CPU: $CPU_USAGE"

# Check active alerts
echo "5. Active Alerts:"
ACTIVE_ALERTS=$(curl -s http://localhost:3000/api/ai/status?include_observability=true | \
  jq '.observability.active_alerts_count')
echo "   Active Alerts: $ACTIVE_ALERTS"

# Check recent errors in logs
echo "6. Recent Errors (last hour):"
ERROR_COUNT=$(docker-compose logs --since=1h mcp-cortex-ai 2>&1 | grep -i error | wc -l)
echo "   Error Count: $ERROR_COUNT"

if [ $ERROR_COUNT -gt 0 ]; then
    echo "   Recent Errors:"
    docker-compose logs --since=1h mcp-cortex-ai 2>&1 | grep -i error | tail -5
fi

echo "=== Daily Check Complete ==="
```

#### 2. Performance Metrics Review

```bash
# Check AI operation metrics
curl -s http://localhost:3000/api/ai/status?include_metrics=true | jq '{
  operations: .metrics.operations,
  insights: .metrics.insights,
  quality: .metrics.quality
}'

# Check cost tracking
curl -s http://localhost:3000/api/ai/status?include_observability=true | jq '.observability.status.uptime'
```

#### 3. Alert Review

```bash
# Review and acknowledge critical alerts
curl -s -X POST http://localhost:3000/api/alerts/acknowledge \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "alert_id_here",
    "acknowledged_by": "ops-team"
  }'
```

### Weekly Procedures

#### 1. Performance Analysis

```bash
# Generate weekly performance report
npm run report:performance -- --period=week

# Check for performance degradation
curl -s http://localhost:3000/api/ai/trends?period=7d | jq '.latency_trend'
```

#### 2. Cost Analysis

```bash
# Generate cost analysis
curl -s -X POST http://localhost:3000/api/ai/cost/analysis \
  -H "Content-Type: application/json" \
  -d '{"period": "7d"}' | jq .
```

#### 3. Model Performance Review

```bash
# Check AI model accuracy trends
curl -s http://localhost:3000/api/ai/quality/report?period=7d | jq '.overall.quality_score'
```

## Health Monitoring

### Real-time Monitoring Dashboard

Access the monitoring dashboard at: `http://your-monitoring-domain:3001`

#### Key Metrics to Monitor

1. **Service Health**
   - Overall service status
   - Individual component health
   - Dependency availability

2. **Performance Metrics**
   - Response times (P50, P95, P99)
   - Throughput (operations per second)
   - Error rates

3. **AI-Specific Metrics**
   - Insight generation performance
   - Contradiction detection accuracy
   - Background queue health

4. **Resource Utilization**
   - Memory usage
   - CPU usage
   - Network I/O

5. **Cost Tracking**
   - Daily/monthly costs
   - Cost per operation
   - Budget compliance

### Health Check Automation

```bash
# scripts/health-monitor.sh
#!/bin/bash

THRESHOLD_LATENCY_P95=5000  # 5 seconds
THRESHOLD_ERROR_RATE=0.05   # 5%
THRESHOLD_MEMORY_USAGE=80    # 80%

# Get current metrics
METRICS=$(curl -s http://localhost:3000/api/ai/status?include_metrics=true)
LATENCY_P95=$(echo $METRICS | jq -r '.metrics.operations.latency_p95')
ERROR_RATE=$(echo $METRICS | jq -r '.metrics.quality.error_rate')
MEMORY_USAGE=$(echo $METRICS | jq -r '.metrics.resources.memory_usage_percent')

# Check thresholds
if (( $(echo "$LATENCY_P95 > $THRESHOLD_LATENCY_P95" | bc -l) )); then
    echo "⚠️  High latency detected: ${LATENCY_P95}ms > ${THRESHOLD_LATENCY_P95}ms"
    # Trigger alert
fi

if (( $(echo "$ERROR_RATE > $THRESHOLD_ERROR_RATE" | bc -l) )); then
    echo "⚠️  High error rate detected: $(echo $ERROR_RATE*100 | bc)% > $(echo $THRESHOLD_ERROR_RATE*100 | bc)%"
    # Trigger alert
fi

if [ "$MEMORY_USAGE" -gt "$THRESHOLD_MEMORY_USAGE" ]; then
    echo "⚠️  High memory usage detected: ${MEMORY_USAGE}% > ${THRESHOLD_MEMORY_USAGE}%"
    # Trigger alert
fi
```

## Incident Response

### Incident Classification

| Severity | Response Time | Escalation | Impact                                   |
| -------- | ------------- | ---------- | ---------------------------------------- |
| Critical | 5 minutes     | Immediate  | Service down, major impact               |
| High     | 15 minutes    | 30 minutes | Degraded performance, significant impact |
| Medium   | 1 hour        | 4 hours    | Partial functionality, moderate impact   |
| Low      | 4 hours       | 24 hours   | Minor issues, low impact                 |

### Standard Operating Procedures

#### Critical Incident: AI Service Down

**Symptoms:**

- Health checks failing
- All AI operations returning errors
- Service unreachable

**Immediate Actions (0-5 minutes):**

1. **Verify Service Status**

```bash
curl -s http://localhost:3000/health || echo "Service unreachable"
docker-compose ps mcp-cortex-ai
```

2. **Check Application Logs**

```bash
docker-compose logs --tail=100 mcp-cortex-ai
```

3. **Check Resource Utilization**

```bash
docker stats mcp-cortex-ai
free -h
df -h
```

4. **Verify Dependencies**

```bash
# Check Qdrant
curl -s http://localhost:6333/health

# Check Z.AI API
curl -s -H "Authorization: Bearer $ZAI_API_KEY" \
  https://api.z.ai/api/anthropic/health
```

**Recovery Actions (5-15 minutes):**

1. **Restart Service**

```bash
docker-compose restart mcp-cortex-ai
```

2. **Scale Resources if Needed**

```bash
docker-compose up -d --scale mcp-cortex-ai=2
```

3. **Roll Back Recent Changes**

```bash
# Identify last deployment
git log --oneline -10

# Roll back if needed
git checkout previous_stable_tag
docker-compose build --no-cache mcp-cortex-ai
docker-compose up -d
```

**Verification (15-30 minutes):**

```bash
# Wait for service to be ready
sleep 30

# Verify health
curl -s http://localhost:3000/health

# Test AI functionality
curl -s -X POST http://localhost:3000/api/ai/status \
  -H "Content-Type: application/json" \
  -d '{"include_metrics": true}'
```

#### High Severity: High Latency

**Symptoms:**

- Response times > 5 seconds
- Users experiencing delays
- Latency alerts triggered

**Immediate Actions (0-15 minutes):**

1. **Assess Latency Impact**

```bash
# Get current latency metrics
curl -s http://localhost:3000/api/ai/status?include_metrics=true | \
  jq '.metrics.operations.latency_p95, .metrics.operations.average_latency'
```

2. **Check Resource Constraints**

```bash
# Check memory usage
docker stats mcp-cortex-ai --no-stream

# Check CPU usage
top -p $(docker inspect mcp-cortex-ai | jq -r '.[0].State.Pid')
```

3. **Check Queue Depths**

```bash
curl -s http://localhost:3000/api/ai/background/status | jq '.queue_depth'
```

**Recovery Actions (15-60 minutes):**

1. **Scale Horizontally**

```bash
docker-compose up -d --scale mcp-cortex-ai=4
```

2. **Adjust Configuration**

```bash
# Reduce batch sizes
export AI_BATCH_SIZE=25
export AI_MAX_CONCURRENT_REQUESTS=100

# Increase timeouts
export AI_OPERATION_TIMEOUT=10000
```

3. **Enable Caching**

```bash
# Verify Redis is running
docker-compose ps redis

# Check cache hit rates
curl -s http://localhost:3000/metrics | grep cache_hits
```

#### Medium Severity: Accuracy Degradation

**Symptoms:**

- AI insight accuracy dropping
- User feedback scores decreasing
- Quality alerts triggered

**Investigation (0-1 hour):**

1. **Analyze Quality Metrics**

```bash
curl -s http://localhost:3000/api/ai/quality/report?period=24h | jq '.overall'
```

2. **Review Recent Changes**

```bash
git log --oneline --since="2 days ago"
docker images mcp-cortex-ai
```

3. **Check Model Performance**

```bash
curl -s http://localhost:3000/api/ai/model/performance | jq '.accuracy_trend'
```

**Recovery Actions (1-4 hours):**

1. **Adjust Confidence Thresholds**

```bash
export AI_INSIGHT_CONFIDENCE_THRESHOLD=0.8
export AI_CONTRADICTION_CONFIDENCE_THRESHOLD=0.85
```

2. **Enable Enhanced Validation**

```bash
export AI_ENHANCED_VALIDATION=true
export AI_VALIDATION_SAMPLE_RATE=1.0
```

3. **Roll Back Model Changes**

```bash
# If recent model update, roll back
export AI_MODEL_PREVIOUS=glm-4.6-v1
docker-compose restart mcp-cortex-ai
```

### Incident Communication Template

#### Initial Alert (T+0)

```
🚨 AI Service Incident Alert

Service: MCP-Cortex AI Services
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Time: [Current Time]
Impact: [Brief description of user impact]

Current Status:
- Service Health: [healthy/degraded/down]
- Affected Features: [list of affected AI features]
- Estimated Users Impacted: [number or estimate]

Next Update: [Time of next communication]

Incident Commander: [Name]
On-call Engineer: [Name]
```

#### Progress Update (T+30 minutes)

```
📋 AI Service Incident Update

Incident ID: [INC-XXXXX]
Time: [Current Time]
Duration: [X minutes]

Current Status:
- Investigation: [what we've learned]
- Impact: [updated impact assessment]
- Mitigation: [steps taken]
- ETA: [estimated resolution time]

Work in Progress:
- [Task 1] - [Owner] - [Status]
- [Task 2] - [Owner] - [Status]

Next Update: [Time of next communication]
```

#### Resolution Notification (T+End)

```
✅ AI Service Incident Resolved

Incident ID: [INC-XXXXX]
Resolution Time: [Time]
Total Duration: [X hours Y minutes]

Root Cause:
[Description of what caused the incident]

Resolution Applied:
[Steps taken to resolve the issue]

Preventive Measures:
[Actions to prevent recurrence]

Service Status:
- All AI services: [operational]
- Performance: [normal/degraded]
- Monitoring: [enhanced/normal]

Thank you for your patience.
```

## Performance Troubleshooting

### Performance Diagnostic Commands

```bash
#!/bin/bash
# scripts/performance-diagnostic.sh

echo "=== AI Services Performance Diagnostic ==="

# 1. System Resources
echo "1. System Resources:"
echo "   Memory Usage:"
free -h
echo "   CPU Usage:"
top -bn1 | head -5
echo "   Disk Usage:"
df -h

# 2. Container Resources
echo "2. Container Resources:"
docker stats mcp-cortex-ai --no-stream
echo "   Container Limits:"
docker inspect mcp-cortex-ai | jq '.[0].HostConfig.Resources'

# 3. Application Metrics
echo "3. Application Metrics:"
METRICS=$(curl -s http://localhost:3000/api/ai/status?include_metrics=true)
echo "   Operation Latency (ms):"
echo $METRICS | jq -r '.metrics.operations | {average: .averageLatency, p95: .latency_p95, p99: .latency_p99}'
echo "   Throughput (ops/sec):"
echo $METRICS | jq -r '.metrics.operations.throughput'
echo "   Error Rate:"
echo $METRICS | jq -r '.metrics.quality.error_rate'

# 4. Background Jobs
echo "4. Background Jobs:"
BG_STATUS=$(curl -s http://localhost:3000/api/ai/background/status)
echo $BG_STATUS | jq '.queue_depth, .active_jobs, .failed_jobs'

# 5. Circuit Breakers
echo "5. Circuit Breaker Status:"
CB_STATUS=$(curl -s http://localhost:3000/health/circuit-breaker)
echo $CB_STATUS | jq '.breakers[] | select(.state != "closed")'

# 6. Dependencies
echo "6. Dependency Health:"
DEPS=$(curl -s http://localhost:3000/health/dependencies)
echo $DEPS | jq '.dependencies[] | {name: .name, status: .status, response_time: .response_time}'

echo "=== Diagnostic Complete ==="
```

### Common Performance Issues

#### High Memory Usage

**Diagnosis:**

```bash
# Check memory breakdown
curl -s http://localhost:3000/api/ai/status?include_metrics=true | \
  jq '.metrics.resources.memory_usage_percent'

# Check cache size
curl -s http://localhost:3000/metrics | grep cache_size
```

**Solutions:**

```bash
# Reduce cache size
export AI_CACHE_MAX_SIZE_MB=100

# Enable garbage collection
export NODE_OPTIONS="--max-old-space-size=2048"

# Restart service
docker-compose restart mcp-cortex-ai
```

#### High CPU Usage

**Diagnosis:**

```bash
# Profile CPU usage
docker exec mcp-cortex-ai node --prof /tmp/cpu-prof.log

# Check processing load
curl -s http://localhost:3000/api/ai/background/status | jq '.active_jobs'
```

**Solutions:**

```bash
# Scale horizontally
docker-compose up -d --scale mcp-cortex-ai=3

# Reduce concurrent operations
export AI_MAX_CONCURRENT_REQUESTS=50

# Optimize batch processing
export AI_BATCH_PROCESSING_INTERVAL=20000
```

#### Database Performance Issues

**Diagnosis:**

```bash
# Check Qdrant performance
curl -s http://localhost:6333/health | jq '.collections[] | select(.name | contains("cortex"))'

# Check slow queries
docker logs qdrant 2>&1 | grep "slow" | tail -10
```

**Solutions:**

```bash
# Optimize Qdrant configuration
docker exec qdrant qdrant-cli collections update cortex-memory \
  --hnsw-config "{\"m\":16, \"ef_construct\":100}\" \

# Add replicas if using clustered Qdrant
docker-compose up -d --scale qdrant=3
```

## Maintenance Procedures

### Scheduled Maintenance

#### Weekly Maintenance Window (Sunday 2:00 AM - 4:00 AM UTC)

```bash
#!/bin/bash
# scripts/weekly-maintenance.sh

echo "=== Starting Weekly AI Services Maintenance ==="

# 1. Backup Configuration and Data
echo "1. Creating backups..."
./scripts/backup.sh

# 2. Health Check Pre-Maintenance
echo "2. Pre-maintenance health check..."
curl -s http://localhost:3000/health | jq -r '.status'

# 3. Graceful Service Shutdown
echo "3. Initiating graceful shutdown..."
curl -s -X POST http://localhost:3000/admin/shutdown \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"grace_period": 300}'

# Wait for shutdown
sleep 60

# 4. Update Dependencies
echo "4. Updating dependencies..."
docker-compose pull
npm update --production

# 5. Database Maintenance
echo "5. Database maintenance..."
docker exec qdrant qdrant-cli collections clean --collection-name cortex-memory
docker exec qdrant qdrant-cli collections optimize --collection-name cortex-memory

# 6. Clear Old Logs
echo "6. Rotating logs..."
docker-compose logs --no-log-prefix mcp-cortex-ai > /var/log/mcp-cortex-ai-$(date +%Y%m%d).log
docker system prune -f

# 7. Restart Services
echo "7. Restarting services..."
docker-compose up -d

# 8. Post-Maintenance Health Check
echo "8. Post-maintenance health check..."
sleep 30
curl -s http://localhost:3000/health

# 9. Performance Verification
echo "9. Performance verification..."
curl -s http://localhost:3000/api/ai/status?include_metrics=true | \
  jq '.metrics.operations.latency_p95'

echo "=== Weekly Maintenance Complete ==="
```

#### Monthly Maintenance

```bash
#!/bin/bash
# scripts/monthly-maintenance.sh

echo "=== Starting Monthly AI Services Maintenance ==="

# 1. Comprehensive Backup
echo "1. Full system backup..."
./scripts/full-backup.sh

# 2. Security Updates
echo "2. Applying security updates..."
npm audit fix
docker-compose pull

# 3. Performance Analysis
echo "3. Performance analysis..."
npm run report:performance -- --period=30d

# 4. Cost Analysis
echo "4. Cost analysis..."
curl -s -X POST http://localhost:3000/api/ai/cost/analysis \
  -H "Content-Type: application/json" \
  -d '{"period": "30d"}' > /reports/cost-analysis-$(date +%Y%m).json

# 5. Model Performance Review
echo "5. Model performance review..."
npm run report:model-performance -- --period=30d

# 6. Configuration Review
echo "6. Configuration review..."
./scripts/config-audit.sh

echo "=== Monthly Maintenance Complete ==="
```

### Zero-Downtime Deployment

```bash
#!/bin/bash
# scripts/zero-downtime-deploy.sh

NEW_VERSION=$1
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "=== Zero-Downtime Deployment: v$NEW_VERSION ==="

# 1. Pre-deployment Health Check
echo "1. Pre-deployment health check..."
if ! curl -s http://localhost:3000/health | jq -e '.status == "healthy"' > /dev/null; then
    echo "❌ Service not healthy - aborting deployment"
    exit 1
fi

# 2. Scale Up Temporarily
echo "2. Scaling up for deployment..."
docker-compose up -d --scale mcp-cortex-ai=4

# 3. Deploy New Version to Half of Instances
echo "3. Deploying new version to half of instances..."
docker build -t cortex/mcp-cortex-ai:v$NEW_VERSION .

# Update service with rolling update
docker-compose up -d --no-deps mcp-cortex-ai:v$NEW_VERSION

# 4. Health Check on New Version
echo "4. Health check on new version..."
sleep 60
NEW_INSTANCES=$(docker-compose ps mcp-cortex-ai | grep "Up.*v$NEW_VERSION" | wc -l)
if [ "$NEW_INSTANCES" -eq 0 ]; then
    echo "❌ New version not starting properly - rolling back"
    docker-compose up -d mcp-cortex-ai:previous
    exit 1
fi

# 5. Traffic Shift
echo "5. Shifting traffic to new version..."
# Load balancer will automatically distribute traffic

# 6. Monitor for Issues
echo "6. Monitoring for issues..."
for i in {1..10}; do
    sleep 30
    if curl -s http://localhost:3000/health | jq -e '.status == "healthy"' > /dev/null; then
        echo "✅ Health check passed ($i/10)"
    else
        echo "❌ Health check failed ($i/10) - investigating"
        docker-compose logs --tail=50 mcp-cortex-ai
    fi
done

# 7. Complete Deployment
echo "7. Completing deployment..."
docker-compose up -d mcp-cortex-ai:v$NEW_VERSION

# 8. Scale Back to Normal
echo "8. Scaling back to normal capacity..."
docker-compose up -d --scale mcp-cortex-ai=3

# 9. Final Health Check
echo "9. Final health check..."
if curl -s http://localhost:3000/health | jq -e '.status == "healthy"' > /dev/null; then
    echo "✅ Deployment successful!"
else
    echo "❌ Deployment failed - rolling back"
    docker-compose up -d mcp-cortex-ai:previous
    exit 1
fi

echo "=== Zero-Downtime Deployment Complete ==="
```

## Emergency Procedures

### Emergency Shutdown

```bash
#!/bin/bash
# scripts/emergency-shutdown.sh

echo "🚨 EMERGENCY SHUTDOWN INITIATED 🚨"

# 1. Immediate Service Stop
echo "1. Stopping AI services immediately..."
docker-compose stop mcp-cortex-ai

# 2. Preserve Current State
echo "2. Preserving current state..."
docker-compose logs mcp-cortex-ai > /var/log/emergency-shutdown-$(date +%Y%m%d-%H%M%S).log

# 3. Backup Critical Data
echo "3. Emergency backup..."
./scripts/emergency-backup.sh

# 4. Notify Teams
echo "4. Sending emergency notifications..."
curl -X POST https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK \
  -H 'Content-type: application/json' \
  --data "{\"text\":\"🚨 EMERGENCY SHUTDOWN: MCP-Cortex AI services stopped at $(date)\"}"

echo "⚠️  Emergency shutdown complete. Services stopped but data preserved."
```

### Data Recovery

```bash
#!/bin/bash
# scripts/data-recovery.sh

echo "=== AI Services Data Recovery ==="

BACKUP_DATE=$1
if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    echo "Available backups:"
    ls -la /backups/
    exit 1
fi

echo "Recovering from backup: $BACKUP_DATE"

# 1. Stop Services
echo "1. Stopping services..."
docker-compose down

# 2. Restore Configuration
echo "2. Restoring configuration..."
cp -r /backups/config-$BACKUP_DATE/* ./config/

# 3. Restore Qdrant Data
echo "3. Restoring Qdrant data..."
docker volume rm qdrant_data
docker volume create qdrant_data
docker run --rm -v qdrant_data:/qdrant/storage \
  -v /backups/qdrant-$BACKUP_DATE.tar.gz:/backup.tar.gz \
  alpine tar xzf /backup.tar.gz -C /qdrant/storage

# 4. Start Services
echo "4. Starting services..."
docker-compose up -d

# 5. Verify Recovery
echo "5. Verifying recovery..."
sleep 60
curl -s http://localhost:3000/health

echo "=== Data Recovery Complete ==="
```

### Service Degradation

```bash
#!/bin/bash
# scripts/service-degradation.sh

DEGRADATION_LEVEL=$1
case $DEGRADATION_LEVEL in
  "minimal")
    echo "Applying minimal degradation..."
    # Disable expensive AI features
    export AI_INSIGHTS_ENABLED=false
    export AI_PREDICTIVE_INSIGHTS_ENABLED=false
    ;;
  "moderate")
    echo "Applying moderate degradation..."
    # Disable most AI features, keep core functionality
    export AI_INSIGHTS_ENABLED=false
    export AI_CONTRADICTION_DETECTION_ENABLED=false
    export AI_BACKGROUND_PROCESSING_ENABLED=false
    ;;
  "severe")
    echo "Applying severe degradation..."
    # Disable all AI features, basic operation only
    export AI_ENABLED=false
    ;;
  *)
    echo "Usage: $0 <minimal|moderate|severe>"
    exit 1
    ;;
esac

# Apply configuration changes
docker-compose restart mcp-cortex-ai

echo "Service degradation applied. Monitoring impact..."
sleep 30
curl -s http://localhost:3000/health
```

## Communication Protocols

### Alert Escalation Matrix

| Alert Type        | Level 1 (5 min)  | Level 2 (15 min)    | Level 3 (30 min)    |
| ----------------- | ---------------- | ------------------- | ------------------- |
| Service Down      | On-call Engineer | Team Lead           | Engineering Manager |
| High Latency      | On-call Engineer | Team Lead           | Engineering Manager |
| Accuracy Issues   | AI Team Lead     | Engineering Manager | CTO                 |
| Cost Overrun      | Operations Lead  | Finance Team        | Executive Team      |
| Security Incident | Security Team    | CISO                | CEO                 |

### Notification Channels

#### Slack Integration

```javascript
// notifications/slack.js
const SlackWebhook = require('slack-webhook');

const sendSlackAlert = async (alert) => {
  const webhook = new SlackWebhook(process.env.SLACK_WEBHOOK_URL);

  const message = {
    text: alert.title,
    attachments: [
      {
        color: alert.severity === 'critical' ? 'danger' : 'warning',
        fields: [
          { title: 'Service', value: 'MCP-Cortex AI', short: true },
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Time', value: new Date().toISOString(), short: true },
          { title: 'Description', value: alert.description, short: false },
        ],
        actions: [
          {
            type: 'button',
            text: 'View Details',
            url: `${process.env.DASHBOARD_URL}/alerts/${alert.id}`,
          },
        ],
      },
    ],
  };

  await webhook.send(message);
};
```

#### PagerDuty Integration

```javascript
// notifications/pagerduty.js
const PagerDuty = require('pagerduty');

const createPagerDutyIncident = async (alert) => {
  const pd = new PagerDuty({
    serviceKey: process.env.PAGERDUTY_SERVICE_KEY,
  });

  const incident = {
    type: 'incident',
    title: alert.title,
    service: {
      type: 'service_reference',
      id: process.env.PAGERDUTY_SERVICE_ID,
    },
    urgency: alert.severity === 'critical' ? 'high' : 'low',
    body: {
      type: 'incident_body',
      details: alert.description,
    },
  };

  return await pd.createIncident(incident);
};
```

### Status Page Updates

```javascript
// notifications/status-page.js
const updateStatusPage = async (status) => {
  const response = await fetch(`${process.env.STATUS_PAGE_API}/incidents`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.STATUS_PAGE_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      incident: {
        name: status.title,
        status: status.impact,
        body: status.description,
      },
      component_ids: [process.env.STATUS_PAGE_AI_COMPONENT_ID],
    }),
  });

  return response.json();
};
```

This comprehensive AI operations runbook provides the procedures and guidelines needed to effectively operate, monitor, and maintain MCP-Cortex AI services in production environments. Regular review and updates of these procedures are essential to maintain operational excellence.
