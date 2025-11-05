# MCP Cortex Rollback Operations Runbook

**Version**: v2.0.0
**Last Updated**: 2025-11-05
**Owner**: Platform Operations Team
**Approval Required**: Rollback > 1 hour impact requires Engineering Manager approval

## 🚨 Executive Summary

This runbook provides comprehensive rollback procedures for the MCP Cortex Memory Server. It covers application deployments, database schema changes, configuration updates, and infrastructure modifications. All rollbacks must follow the documented procedures to ensure service continuity and data integrity.

**Target Rollback Time**: < 30 minutes for application rollbacks
**Target Database Recovery**: < 2 hours for major database rollbacks
**Maximum Allowed Downtime**: < 15 minutes for critical services

---

## 🔄 Rollback Classification

### Rollback Types

| Type | Trigger | Impact | Duration | Approval Required |
|------|---------|--------|----------|-------------------|
| **Application Rollback** | Deployment failure, performance degradation | Medium | 15-30 min | On-call Engineer |
| **Database Rollback** | Schema issues, data corruption | High | 30-120 min | Engineering Manager |
| **Configuration Rollback** | Configuration errors, env variable issues | Medium | 5-15 min | On-call Engineer |
| **Infrastructure Rollback** | Cloud provider issues, network changes | High | 30-60 min | Director of Engineering |
| **Emergency Rollback** | Data loss, security breach | Critical | 5-15 min | Any Engineer + Notification |

### Rollback Triggers

**Automatic Triggers**:
- Health check failures (> 3 consecutive)
- Error rate > 5% sustained for 5 minutes
- Response time > 2 seconds sustained for 10 minutes
- Database connection failures

**Manual Triggers**:
- Customer reported major issues
- Performance degradation during load testing
- Security vulnerability detection
- Business logic errors

---

## 🚀 Pre-Rollback Procedures

### Step 1: Impact Assessment

**Assessment Checklist**:
```bash
# Determine rollback scope
echo "Rollback Impact Assessment"
echo "========================="

# Check current deployment
git rev-parse HEAD
git log --oneline -5

# Identify affected components
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
systemctl list-units --type=service --state=running | grep cortex

# Assess data impact
npm run db:health
curl -s http://localhost:6333/collections | jq '.result.collections[] | {name: .name, points_count: .points_count}'

# Check active users/sessions
curl -s http://localhost:3000/metrics | grep -E "(active_users|sessions)"
```

**Impact Assessment Matrix**:

| Component | Current State | Last Known Good | Data Impact | User Impact |
|-----------|---------------|-----------------|-------------|-------------|
| **Application** | Version X.Y.Z | Version X.Y.(Z-1) | None | Medium |
| **Database** | Schema v2.1 | Schema v2.0 | Possible | High |
| **Configuration** | Config v1.3 | Config v1.2 | None | Low |
| **Infrastructure** | Infra v3.0 | Infra v2.9 | None | High |

### Step 2: Preparation Checklist

**Preparation Commands**:
```bash
# Create rollback snapshot
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
echo "Creating rollback snapshot: rollback-$TIMESTAMP"

# Backup current state
npm run ops:backup:manual --name="pre-rollback-$TIMESTAMP"

# Document rollback plan
cat > /tmp/rollback-plan-$TIMESTAMP.md << EOF
# Rollback Plan - $TIMESTAMP
## Reason: [rollback reason]
## Target Version: [target version]
## Estimated Duration: [duration]
## Risk Assessment: [low/medium/high]
## Rollback Steps:
1. [step 1]
2. [step 2]
...
EOF

# Create rollback communication
slack-notify --channel="#incidents" --message="Rollback initiated for MCP Cortex - Reason: [reason] - ETA: [duration]"
```

**Pre-Rollback Validation**:
```bash
# Verify rollback target exists
docker images | grep cortex
git tag | grep -E "v[0-9]+\.[0-9]+\.[0-9]+" | sort -V | tail -5

# Validate backup integrity
npm run ops:backup:verify --backup=latest

# Check system capacity for rollback
df -h
free -h
top -b -n1 | head -5
```

---

## 🛠️ Application Rollback Procedures

### Scenario 1: Docker Container Rollback

**Rollback Steps**:
```bash
# 1. Identify current version
CURRENT_IMAGE=$(docker ps --format "{{.Image}}" | grep cortex)
echo "Current image: $CURRENT_IMAGE"

# 2. Identify target version
TARGET_IMAGE="cortex-memory-mcp:v2.0.0"
echo "Rolling back to: $TARGET_IMAGE"

# 3. Pull target image
docker pull $TARGET_IMAGE

# 4. Stop current container
docker stop cortex-mcp
docker stop cortex-api

# 5. Deploy target image
docker run -d \
  --name cortex-mcp \
  --restart unless-stopped \
  -p 3000:3000 \
  -e QDRANT_URL=http://qdrant:6333 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e NODE_ENV=production \
  $TARGET_IMAGE

# 6. Verify deployment
docker ps | grep cortex
curl -s http://localhost:3000/health | jq .

# 7. Monitor for 5 minutes
timeout 300 bash -c 'while true; do curl -s http://localhost:3000/health; sleep 10; done'
```

**Rollback Verification**:
```bash
# Health checks
npm run prod:health
npm run test:connection

# Performance checks
npm run perf:gate:ci

# Functionality checks
npm run test:integration:happy
npm run test:integration:performance
```

### Scenario 2: System Service Rollback

**Rollback Steps**:
```bash
# 1. Identify current version
systemctl status cortex-mcp --no-pager -l
CURRENT_VERSION=$(cat /app/cortex-mcp/current-version)
echo "Current version: $CURRENT_VERSION"

# 2. Identify target version
TARGET_VERSION="v2.0.0"
echo "Rolling back to: $TARGET_VERSION"

# 3. Backup current installation
cp -r /app/cortex-mcp/current /app/cortex-mcp/backup-$(date +%Y%m%d-%H%M%S)

# 4. Deploy target version
cd /app/cortex-mcp/releases
git checkout $TARGET_VERSION
npm ci --production
npm run build

# 5. Update current symlink
ln -sfn /app/cortex-mcp/releases/$TARGET_VERSION /app/cortex-mcp/current

# 6. Restart service
sudo systemctl restart cortex-mcp

# 7. Verify deployment
systemctl status cortex-mcp --no-pager
journalctl -u cortex-mcp --since "1 minute ago" --no-pager

# 8. Health verification
curl -s http://localhost:3000/health | jq .
```

### Scenario 3: Cloud Deployment Rollback

**Kubernetes Rollback**:
```bash
# 1. Check current deployment
kubectl get pods -n cortex
kubectl describe deployment cortex-mcp -n cortex

# 2. Identify rollback target
kubectl rollout history deployment/cortex-mcp -n cortex
REVISION=$(kubectl rollout history deployment/cortex-mcp -n cortex | grep v2.0.0 | awk '{print $1}')

# 3. Execute rollback
kubectl rollout undo deployment/cortex-mcp --to-revision=$REVISION -n cortex

# 4. Monitor rollback progress
kubectl rollout status deployment/cortex-mcp -n cortex --timeout=300s

# 5. Verify rollback
kubectl get pods -n cortex
kubectl logs -f deployment/cortex-mcp -n cortex --tail=50

# 6. Health checks
kubectl exec -it deployment/cortex-mcp -n cortex -- npm run prod:health
```

**Terraform Infrastructure Rollback**:
```bash
# 1. Identify current state
terraform state list
terraform show

# 2. Identify target state
git log --oneline terraform/ | head -10
TARGET_COMMIT=$(git log --oneline terraform/ | grep "stable deployment" | head -1 | awk '{print $1}')

# 3. Checkout target infrastructure code
cd terraform/
git checkout $TARGET_COMMIT

# 4. Apply previous state
terraform plan -out=rollback.tfplan
terraform apply rollback.tfplan

# 5. Verify infrastructure
terraform validate
terraform plan
```

---

## 🗄️ Database Rollback Procedures

### Scenario 1: Qdrant Data Recovery

**Data Recovery Steps**:
```bash
# 1. Assess current state
curl -s http://localhost:6333/collections | jq .
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'

# 2. Identify backup target
BACKUP_DIR="/app/backups/qdrant"
LATEST_BACKUP=$(ls -t $BACKUP_DIR | head -1)
echo "Using backup: $LATEST_BACKUP"

# 3. Create emergency backup (if possible)
curl -X POST http://localhost:6333/collections/cortex-memory/points/export \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000000}' > /tmp/emergency-export-$(date +%Y%m%d-%H%M%S).json

# 4. Stop application to prevent conflicts
sudo systemctl stop cortex-mcp

# 5. Backup current collection (if possible)
curl -X POST http://localhost:6333/collections/cortex-memory/backup \
  -H "Content-Type: application/json" \
  -d '{"backup_name": "pre-rollback-$(date +%Y%m%d-%H%M%S)"}'

# 6. Delete corrupted collection
curl -X DELETE http://localhost:6333/collections/cortex-memory

# 7. Restore from backup
python3 /app/scripts/restore-qdrant-backup.py \
  --backup-path $BACKUP_DIR/$LATEST_BACKUP \
  --collection-name cortex-memory

# 8. Verify restoration
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'

# 9. Restart application
sudo systemctl start cortex-mcp

# 10. Monitor application
journalctl -u cortex-mcp -f --no-pager &
tail -f /app/logs/cortex-mcp.log &
```

### Scenario 2: Schema Rollback

**Schema Rollback Steps**:
```bash
# 1. Identify current schema version
CURRENT_SCHEMA=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.config.params.vectors.size')
echo "Current schema version: $CURRENT_SCHEMA"

# 2. Identify target schema
TARGET_SCHEMA="1536"  # OpenAI ada-002 size
echo "Target schema: $TARGET_SCHEMA"

# 3. Export current data
curl -X POST http://localhost:6333/collections/cortex-memory/points/export \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000000, "with_payload": true, "with_vector": true}' \
  > /tmp/schema-rollback-export-$(date +%Y%m%d-%H%M%S).json

# 4. Stop application
sudo systemctl stop cortex-mcp

# 5. Recreate collection with target schema
curl -X DELETE http://localhost:6333/collections/cortex-memory

curl -X PUT http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    },
    "optimizers_config": {
      "default_segment_number": 2
    }
  }'

# 6. Import data
python3 /app/scripts/import-qdrant-data.py \
  --data-file /tmp/schema-rollback-export-*.json \
  --collection-name cortex-memory \
  --batch-size 100

# 7. Verify import
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'

# 8. Test functionality
curl -X POST http://localhost:6333/collections/cortex-memory/points/search \
  -H "Content-Type: application/json" \
  -d '{
    "vector": [0.1, 0.2, 0.3],
    "limit": 5
  }'

# 9. Restart application
sudo systemctl start cortex-mcp
```

### Scenario 3: Point-in-Time Recovery

**Point-in-Time Recovery**:
```bash
# 1. Identify recovery point
RECOVERY_TIME="2025-11-05T14:30:00Z"
echo "Recovery point: $RECOVERY_TIME"

# 2. Find appropriate backup
BACKUP_TOOL=/app/scripts/find-backup-by-time.sh
TARGET_BACKUP=$($BACKUP_TOOL --time="$RECOVERY_TIME")
echo "Target backup: $TARGET_BACKUP"

# 3. Validate backup integrity
npm run ops:backup:verify --backup=$TARGET_BACKUP

# 4. Stop all services
sudo systemctl stop cortex-mcp qdrant

# 5. Restore Qdrant data
cd /app/backups
tar -xzf $TARGET_BACKUP -C /

# 6. Restart Qdrant
sudo systemctl start qdrant
sleep 30

# 7. Verify Qdrant health
curl -s http://localhost:6333/health

# 8. Restart application
sudo systemctl start cortex-mcp

# 9. Verify application health
curl -s http://localhost:3000/health

# 10. Test search functionality
npm run test:integration:happy
```

---

## ⚙️ Configuration Rollback Procedures

### Scenario 1: Environment Variable Rollback

**Environment Rollback**:
```bash
# 1. Identify current configuration
env | grep -E "(QDRANT|OPENAI|NODE|CORTEX)" | sort > /tmp/current-env-$(date +%Y%m%d-%H%M%S).env

# 2. Identify last known good configuration
GOOD_ENV="/app/config/production.env.backup"
if [ -f "$GOOD_ENV" ]; then
    echo "Using backup configuration: $GOOD_ENV"
else
    echo "No backup configuration found"
    exit 1
fi

# 3. Validate backup configuration
cat $GOOD_ENV | grep -E "(QDRANT_URL|OPENAI_API_KEY)" | while read line; do
    if [[ ! $line =~ ^[A-Z_]+=.* ]]; then
        echo "Invalid configuration line: $line"
        exit 1
    fi
done

# 4. Create current configuration backup
cp /app/.env /app/.env.backup-$(date +%Y%m%d-%H%M%S)

# 5. Restore configuration
cp $GOOD_ENV /app/.env

# 6. Restart service with new configuration
sudo systemctl restart cortex-mcp

# 7. Verify configuration applied
systemctl status cortex-mcp --no-pager -l
journalctl -u cortex-mcp --since "1 minute ago" --no-pager

# 8. Test functionality
curl -s http://localhost:3000/health | jq .
npm run test:connection
```

### Scenario 2: Database Configuration Rollback

**Database Configuration**:
```bash
# 1. Current Qdrant configuration
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.config'

# 2. Identify target configuration
TARGET_CONFIG="/app/config/qdrant/collection-config-v2.0.json"

# 3. Backup current configuration
curl -s http://localhost:6333/collections/cortex-memory > /tmp/current-qdrant-config-$(date +%Y%m%d-%H%M%S).json

# 4. Apply target configuration
curl -X PATCH http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d @$TARGET_CONFIG

# 5. Wait for configuration to apply
sleep 10

# 6. Verify new configuration
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.config'

# 7. Test functionality
curl -X POST http://localhost:6333/collections/cortex-memory/points/search \
  -H "Content-Type: application/json" \
  -d '{
    "vector": [0.1, 0.2, 0.3],
    "limit": 1
  }'
```

---

## 🌐 Infrastructure Rollback Procedures

### Scenario 1: Network Configuration Rollback

**Network Rollback**:
```bash
# 1. Identify current network configuration
iptables -L -n -v
ip route show
netstat -tulpn | grep :3000

# 2. Identify rollback target
TARGET_CONFIG="/app/network/iptables.rules.backup"

# 3. Backup current configuration
iptables-save > /tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules

# 4. Restore target configuration
iptables-restore < $TARGET_CONFIG

# 5. Verify connectivity
ping -c 3 8.8.8.8
curl -s http://localhost:3000/health

# 6. Test external connectivity
curl -s http://localhost:6333/health
curl -I https://api.openai.com/v1/models
```

### Scenario 2: Docker Network Rollback

**Docker Network Rollback**:
```bash
# 1. Current Docker network state
docker network ls
docker network inspect cortex-network

# 2. Identify target network configuration
TARGET_COMPOSE="/app/docker/docker-compose.backup.yml"

# 3. Backup current state
docker-compose -f /app/docker/docker-compose.yml config > /tmp/current-docker-compose-$(date +%Y%m%d-%H%M%S).yml

# 4. Stop current services
docker-compose -f /app/docker/docker-compose.yml down

# 5. Restore target configuration
cp $TARGET_COMPOSE /app/docker/docker-compose.yml

# 6. Start services with target configuration
docker-compose -f /app/docker/docker-compose.yml up -d

# 7. Verify network connectivity
docker ps
docker network ls
docker network inspect cortex-network

# 8. Test service connectivity
docker exec cortex-mcp curl -s http://localhost:3000/health
docker exec cortex-mcp curl -s http://qdrant:6333/health
```

---

## 🚨 Emergency Rollback Procedures

### Emergency Scenario: Data Corruption Detected

**Immediate Actions**:
```bash
# 1. STOP ALL SERVICES IMMEDIATELY
sudo systemctl stop cortex-mcp
docker stop $(docker ps -q --filter "name=cortex")

# 2. Lock down database
curl -X POST http://localhost:6333/collections/cortex-memory/lock \
  -H "Content-Type: application/json" \
  -d '{"reason": "emergency rollback"}'

# 3. Notify team
slack-notify --channel="#incidents" --message="EMERGENCY ROLLBACK INITIATED - Data corruption detected"
pagerduty-trigger --severity=critical --summary="MCP Cortex emergency rollback"

# 4. Create emergency backup
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p /app/emergency-backups/$TIMESTAMP
curl -s http://localhost:6333/collections/cortex-memory/points/export \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000000, "with_payload": true, "with_vector": true}' \
  > /app/emergency-backups/$TIMESTAMP/cortex-memory-export.json

# 5. Identify last known good backup
LAST_GOOD_BACKUP=$(find /app/backups/qdrant -name "*.tar.gz" -mtime -7 -exec ls -lt {} \; | head -1 | awk '{print $NF}')
echo "Last known good backup: $LAST_GOOD_BACKUP"

# 6. Execute emergency restore
/app/scripts/emergency-restore.sh --backup=$LAST_GOOD_BACKUP --force

# 7. Verify system integrity
/app/scripts/system-integrity-check.sh

# 8. Restore services
sudo systemctl start cortex-mcp

# 9. Monitor for 30 minutes
timeout 1800 /app/scripts/health-monitor.sh
```

### Emergency Scenario: Security Breach Response

**Security Rollback**:
```bash
# 1. Isolate affected systems
sudo systemctl stop cortex-mcp
docker stop $(docker ps -q --filter "name=cortex")
iptables -I INPUT -p tcp --dport 3000 -j DROP
iptables -I INPUT -p tcp --dport 6333 -j DROP

# 2. Rotate all secrets
/app/scripts/rotate-secrets.sh --all --immediate

# 3. Restore from known good state
LAST_GOOD_BACKUP=$(find /app/backups/qdrant -name "*.tar.gz" -mtime -1 -exec ls -lt {} \; | head -1 | awk '{print $NF}')
/app/scripts/security-restore.sh --backup=$LAST_GOOD_BACKUP

# 4. Update all API keys and tokens
/app/scripts/update-credentials.sh --all

# 5. Restart services with new credentials
sudo systemctl start cortex-mcp

# 6. Verify security measures
/app/scripts/security-audit.sh --immediate

# 7. Notify security team
security-team-notify --incident="security_breach_rollback" --severity=critical
```

---

## ✅ Post-Rollback Verification

### Step 1: Health Checks

**Comprehensive Health Verification**:
```bash
# 1. Basic health checks
npm run prod:health
curl -s http://localhost:3000/health | jq .
curl -s http://localhost:6333/health | jq .

# 2. Service status
systemctl status cortex-mcp qdrant --no-pager
docker ps | grep -E "(cortex|qdrant)"

# 3. Performance checks
npm run perf:gate:ci
npm run test:performance

# 4. Functionality checks
npm run test:integration:happy
npm run test:integration:performance
npm run test:integration:reassembly

# 5. Security checks
npm run security:check
npm run security:audit
```

### Step 2: Data Integrity Validation

**Data Verification**:
```bash
# 1. Database integrity
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'
/app/scripts/validate-data-integrity.sh

# 2. Search functionality
curl -X POST http://localhost:6333/collections/cortex-memory/points/search \
  -H "Content-Type: application/json" \
  -d '{
    "vector": [0.1, 0.2, 0.3],
    "limit": 5,
    "with_payload": true
  }'

# 3. Store functionality
curl -X POST http://localhost:3000/api/v1/memory/store \
  -H "Content-Type: application/json" \
  -d '{
    "items": [{
      "kind": "observation",
      "content": "Rollback verification test",
      "scope": {"project": "test"}
    }]
  }'

# 4. Find functionality
curl -X POST http://localhost:3000/api/v1/memory/find \
  -H "Content-Type: application/json" \
  -d '{
    "query": "rollback verification",
    "limit": 1
  }'
```

### Step 3: Performance Validation

**Performance Checks**:
```bash
# 1. Response time validation
TIME=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)
if (( $(echo "$TIME > 1.0" | bc -l) )); then
    echo "ERROR: Response time too high: ${TIME}s"
    exit 1
fi

# 2. Load testing
npm run bench:quick

# 3. Memory usage validation
MEMORY=$(ps aux | grep -E "node.*cortex" | awk '{sum+=$6} END {print sum/1024}')
if (( $(echo "$MEMORY > 2048" | bc -l) )); then
    echo "WARNING: High memory usage: ${MEMORY}MB"
fi

# 4. Error rate validation
ERROR_COUNT=$(journalctl -u cortex-mcp --since "10 minutes ago" | grep -i error | wc -l)
if [ $ERROR_COUNT -gt 0 ]; then
    echo "ERROR: Found $ERROR_COUNT errors in logs"
    exit 1
fi
```

---

## 📊 Rollback Monitoring

### Real-time Monitoring

**Monitoring Commands**:
```bash
# 1. Health monitoring loop
timeout 1800 bash -c '
while true; do
    echo "$(date): Health check"
    curl -s http://localhost:3000/health | jq .status
    sleep 30
done
'

# 2. Performance monitoring
timeout 1800 bash -c '
while true; do
    echo "$(date): Performance metrics"
    curl -s http://localhost:3000/metrics | grep -E "(response_time|error_rate)"
    sleep 60
done
'

# 3. Log monitoring
journalctl -u cortex-mcp -f --no-pager &
tail -f /app/logs/cortex-mcp.log &

# 4. System resource monitoring
htop -d 30
iostat -x 30
```

### Alert Thresholds

**Post-Rollback Alert Thresholds**:
- Error rate > 1% (normally > 0.1%)
- Response time > 500ms (normally > 100ms)
- Memory usage > 4GB (normally > 2GB)
- Database connection errors > 0

**Alert Commands**:
```bash
# Custom alert thresholds
export ALERT_ERROR_RATE_THRESHOLD=1.0
export ALERT_RESPONSE_TIME_THRESHOLD=500
export ALERT_MEMORY_THRESHOLD=4096

# Start monitoring with custom thresholds
npm run monitor:alerts --custom-thresholds
```

---

## 📋 Rollback Documentation

### Rollback Report Template

**Required Information**:
```markdown
# Rollback Report

## Executive Summary
- **Incident ID**: INC-[YYYYMMDD]-[sequence]
- **Rollback Type**: [application/database/configuration/infrastructure]
- **Trigger**: [rollback reason]
- **Duration**: [start time] to [end time]
- **Impact**: [description of impact]

## Rollback Details
### Source Version
- **Version**: [version rolled back from]
- **Deployment Time**: [deployment time]
- **Issues Identified**: [list of issues]

### Target Version
- **Version**: [version rolled back to]
- **Last Known Good**: [date/time when version was stable]
- **Features Lost**: [features reverted]

## Rollback Process
### Pre-Rollback Actions
- [ ] Impact assessment completed
- [ ] Backup created
- [ ] Rollback plan documented
- [ ] Stakeholders notified

### Rollback Execution
- [ ] Services stopped
- [ ] Configuration restored
- [ ] Services restarted
- [ ] Health checks passed

### Post-Rollback Verification
- [ ] Basic functionality verified
- [ ] Performance validated
- [ ] Data integrity confirmed
- [ ] Monitoring stable

## Impact Assessment
### User Impact
- **Affected Users**: [count/percentage]
- **Duration of Impact**: [time period]
- **Customer Complaints**: [count]
- **SLA Impact**: [description]

### Business Impact
- **Revenue Impact**: [description]
- **Brand Impact**: [description]
- **Operational Impact**: [description]

## Root Cause Analysis
### Primary Cause
[Technical explanation of what went wrong]

### Contributing Factors
- [factor 1]
- [factor 2]
- [factor 3]

### Detection Gaps
[What could have been detected earlier]

## Lessons Learned
### What Went Well
- [item 1]
- [item 2]

### Areas for Improvement
- [item 1]
- [item 2]

### Action Items
- [ ] [action item] - Owner: [name] - Due: [date]
- [ ] [action item] - Owner: [name] - Due: [date]
- [ ] [action item] - Owner: [name] - Due: [date]

## Preventive Measures
### Technical Improvements
- [improvement 1]
- [improvement 2]

### Process Improvements
- [improvement 1]
- [improvement 2]

### Monitoring Improvements
- [improvement 1]
- [improvement 2]
```

---

## 🔄 Rollback Automation

### Automated Rollback Script

**Emergency Rollback Automation**:
```bash
#!/bin/bash
# emergency-rollback.sh - Automated emergency rollback procedure

set -euo pipefail

# Configuration
ROLLBACK_TYPE=${1:-"application"}
TARGET_VERSION=${2:-"latest-stable"}
FORCE_ROLLBACK=${3:-"false"}

# Logging
LOG_FILE="/var/log/cortex-rollback.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo "=== Emergency Rollback Started ==="
echo "Timestamp: $(date)"
echo "Rollback Type: $ROLLBACK_TYPE"
echo "Target Version: $TARGET_VERSION"
echo "Force Rollback: $FORCE_ROLLBACK"

# Pre-rollback checks
echo "Performing pre-rollback checks..."
if ! systemctl is-active --quiet cortex-mcp; then
    echo "ERROR: cortex-mcp service is not running"
    exit 1
fi

if ! curl -s http://localhost:3000/health > /dev/null; then
    echo "ERROR: Health check failed"
    exit 1
fi

# Create backup
echo "Creating emergency backup..."
BACKUP_NAME="emergency-rollback-$(date +%Y%m%d-%H%M%S)"
npm run ops:backup:manual --name="$BACKUP_NAME"

# Execute rollback based on type
case $ROLLBACK_TYPE in
    "application")
        echo "Executing application rollback..."
        npm run ops:rollback:application --version="$TARGET_VERSION" --force="$FORCE_ROLLBACK"
        ;;
    "database")
        echo "Executing database rollback..."
        npm run ops:rollback:database --backup="$TARGET_VERSION" --force="$FORCE_ROLLBACK"
        ;;
    "configuration")
        echo "Executing configuration rollback..."
        npm run ops:rollback:config --version="$TARGET_VERSION"
        ;;
    *)
        echo "ERROR: Unknown rollback type: $ROLLBACK_TYPE"
        exit 1
        ;;
esac

# Post-rollback verification
echo "Performing post-rollback verification..."
if ! npm run prod:health; then
    echo "ERROR: Post-rollback health check failed"
    exit 1
fi

echo "=== Emergency Rollback Completed Successfully ==="
```

**Rollback Validation Script**:
```bash
#!/bin/bash
# validate-rollback.sh - Post-rollback validation

set -euo pipefail

VALIDATION_ERRORS=0

echo "=== Rollback Validation Started ==="

# Health checks
echo "1. Checking service health..."
if curl -s http://localhost:3000/health | jq -e '.status == "healthy"'; then
    echo "✅ Service health check passed"
else
    echo "❌ Service health check failed"
    ((VALIDATION_ERRORS++))
fi

# Database connectivity
echo "2. Checking database connectivity..."
if curl -s http://localhost:6333/health > /dev/null; then
    echo "✅ Database connectivity check passed"
else
    echo "❌ Database connectivity check failed"
    ((VALIDATION_ERRORS++))
fi

# Basic functionality
echo "3. Testing basic functionality..."
TEST_RESPONSE=$(curl -s -X POST http://localhost:3000/api/v1/memory/find \
    -H "Content-Type: application/json" \
    -d '{"query": "test", "limit": 1}')

if echo "$TEST_RESPONSE" | jq -e '.items' > /dev/null; then
    echo "✅ Basic functionality test passed"
else
    echo "❌ Basic functionality test failed"
    ((VALIDATION_ERRORS++))
fi

# Performance check
echo "4. Checking performance..."
RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)
if (( $(echo "$RESPONSE_TIME < 1.0" | bc -l) )); then
    echo "✅ Performance check passed (${RESPONSE_TIME}s)"
else
    echo "❌ Performance check failed (${RESPONSE_TIME}s > 1.0s)"
    ((VALIDATION_ERRORS++))
fi

# Error rate check
echo "5. Checking error rate..."
ERROR_COUNT=$(journalctl -u cortex-mcp --since "5 minutes ago" | grep -i error | wc -l)
if [ $ERROR_COUNT -eq 0 ]; then
    echo "✅ Error rate check passed (no errors in last 5 minutes)"
else
    echo "❌ Error rate check failed ($ERROR_COUNT errors in last 5 minutes)"
    ((VALIDATION_ERRORS++))
fi

echo "=== Rollback Validation Completed ==="
echo "Validation Errors: $VALIDATION_ERRORS"

if [ $VALIDATION_ERRORS -eq 0 ]; then
    echo "✅ All validation checks passed"
    exit 0
else
    echo "❌ $VALIDATION_ERRORS validation checks failed"
    exit 1
fi
```

---

## 📚 Appendices

### A. Rollback Decision Matrix

| Condition | Rollback Recommended | Time to Decide | Risk Level |
|-----------|---------------------|----------------|------------|
| API error rate > 5% | Yes | 5 minutes | Medium |
| Response time > 2s | Yes | 10 minutes | Low |
| Database connection failures | Yes | Immediate | High |
| Data corruption detected | Yes | Immediate | Critical |
| Security vulnerability | Yes | Immediate | Critical |
| Customer complaints > 10 | Yes | 15 minutes | Medium |
| Performance degradation > 50% | Yes | 10 minutes | Medium |

### B. Rollback Contact Information

**Rollback Approvals**:
| Rollback Type | Approval Required | Contact | Backup Contact |
|---------------|------------------|---------|----------------|
| Application | On-call Engineer | @oncall-eng | @backup-eng |
| Database | Engineering Manager | @eng-manager | @tech-lead |
| Configuration | On-call Engineer | @oncall-eng | @devops-lead |
| Infrastructure | Director of Engineering | @director-eng | @vp-eng |
| Emergency | Any Engineer + Notify | @oncall-eng | @eng-manager |

### C. Rollback Metrics

**Key Performance Indicators**:
- Mean Time to Rollback (MTTR): Target < 30 minutes
- Rollback Success Rate: Target > 95%
- Post-Rollback Stability: Target 99.9% uptime
- Customer Impact: Target < 15 minutes downtime

**Rollback Tracking**:
```bash
# Track rollback metrics
npm run ops:metrics:rollback

# Generate rollback report
npm run ops:report --type=rollback --date=$(date +%Y-%m-%d)

# Analyze rollback trends
npm run ops:analyze:rollback-trends
```

---

**Document Owner**: Platform Operations Team
**Last Reviewed**: 2025-11-05
**Next Review**: 2025-12-05
**Version**: v2.0.0

**For updates or corrections, create a pull request or contact the Platform Operations Team.**