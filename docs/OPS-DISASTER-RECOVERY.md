# Disaster Recovery & Operations Manual

## Overview

This comprehensive disaster recovery and operations manual provides step-by-step procedures for maintaining, troubleshooting, and recovering the Cortex Memory MCP Server in production environments. This guide is designed for new engineers and operations teams to ensure system reliability and quick recovery from failures.

## System Architecture Overview

### Current Architecture (Qdrant-Only)

```
Cortex MCP v2.0.0 Architecture
├── Application Layer (Node.js + TypeScript)
│   ├── MCP Server (Port 3000)
│   ├── REST API (Port 3000)
│   └── Health Checks (Port 3000)
├── Database Layer
│   └── Qdrant Vector Database (Port 6333)
│       ├── Vector Storage (1536 dimensions)
│       ├── Semantic Search
│       └── Collections Management
├── External Dependencies
│   ├── OpenAI API (Embeddings)
│   └── Monitoring Stack (Prometheus/Grafana)
└── Storage Layer
    ├── Local File System (Logs)
    └── Backup Storage (S3/Local)
```

### Critical Components

| Component | Role | Recovery Priority | RTO | RPO |
|-----------|------|-------------------|-----|-----|
| **Qdrant Database** | Primary data storage | Critical | 15 min | 5 min |
| **MCP Server** | API and business logic | High | 5 min | 0 min |
| **OpenAI API** | Embedding generation | High | 30 min | N/A |
| **Monitoring** | System observability | Medium | 1 hour | N/A |

## 🚨 Emergency Procedures

### 1. Immediate Response Checklist

When an incident occurs, follow this checklist immediately:

```bash
# 1. Assess the situation (5 minutes)
echo "=== SYSTEM STATUS ASSESSMENT ==="
date
echo "Checking service status..."

# Check MCP Server
curl -f http://localhost:3000/health || echo "❌ MCP Server DOWN"
curl -f http://localhost:3000/ready || echo "❌ MCP Server not ready"

# Check Qdrant
curl -f http://localhost:6333/health || echo "❌ Qdrant DOWN"
curl -f http://localhost:6333/collections/cortex-memory || echo "❌ Collection missing"

# Check system resources
echo "Memory usage:"
free -h
echo "Disk usage:"
df -h
echo "CPU load:"
uptime

# 2. Check recent errors (2 minutes)
echo "=== RECENT ERRORS ==="
tail -50 /app/logs/error.log
tail -50 /app/logs/cortex-mcp.log

# 3. Identify the scope (3 minutes)
echo "=== IMPACT ASSESSMENT ==="
ps aux | grep node || echo "No Node.js processes running"
docker ps | grep qdrant || echo "No Qdrant containers running"
```

### 2. Service Restart Procedures

#### Restarting MCP Server

```bash
# Graceful restart
systemctl restart cortex-mcp

# Manual restart (if systemctl fails)
cd /app
pkill -f "node.*index.js" || true
nohup node dist/index.js > /app/logs/mcp-restart.log 2>&1 &

# Verify restart
sleep 10
curl -f http://localhost:3000/health && echo "✅ MCP Server restarted successfully"
```

#### Restarting Qdrant

```bash
# Docker deployment
docker restart qdrant

# Kubernetes deployment
kubectl rollout restart deployment/qdrant -n cortex-mcp

# Manual deployment
cd /opt/qdrant
pkill -f qdrant || true
./qdrant --storage-path /data/qdrant > /var/log/qdrant.log 2>&1 &

# Verify restart
sleep 30
curl -f http://localhost:6333/health && echo "✅ Qdrant restarted successfully"
```

### 3. Database Recovery Procedures

#### Qdrant Collection Recovery

```bash
#!/bin/bash
# scripts/recover-collection.sh

echo "🔄 Qdrant Collection Recovery Procedure"
echo "========================================"

COLLECTION_NAME="cortex-memory"
BACKUP_DIR="/backups/qdrant"
DATE=$(date +%Y%m%d_%H%M%S)

# 1. Check if collection exists
echo "📋 Checking collection status..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:6333/collections/$COLLECTION_NAME)

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✅ Collection exists and is accessible"

    # Check collection info
    curl -s http://localhost:6333/collections/$COLLECTION_NAME | jq '.'
    exit 0
fi

echo "❌ Collection not found or inaccessible (HTTP $HTTP_CODE)"

# 2. Attempt to recreate collection
echo "🔧 Attempting to recreate collection..."

curl -X PUT http://localhost:6333/collections/$COLLECTION_NAME \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    },
    "optimizers_config": {
      "default_segment_number": 2,
      "max_segment_size": 200000,
      "memmap_threshold": 50000
    },
    "wal_config": {
      "wal_capacity_mb": 32,
      "wal_segments_ahead": 0
    },
    "quantization_config": {
      "scalar": {
        "type": "int8",
        "quantile": 0.99
      }
    }
  }'

# 3. Verify collection creation
sleep 5
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:6333/collections/$COLLECTION_NAME)

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✅ Collection recreated successfully"
    echo "⚠️  Note: Collection is empty - restore from backup if needed"
else
    echo "❌ Failed to recreate collection (HTTP $HTTP_CODE)"
    echo "🔄 Attempting Qdrant service restart..."

    # Restart Qdrant and retry
    systemctl restart qdrant
    sleep 30

    # Recreate after restart
    curl -X PUT http://localhost:6333/collections/$COLLECTION_NAME \
      -H "Content-Type: application/json" \
      -d '{
        "vectors": {
          "size": 1536,
          "distance": "Cosine"
        }
      }'

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      http://localhost:6333/collections/$COLLECTION_NAME)

    if [ "$HTTP_CODE" -eq 200 ]; then
        echo "✅ Collection recreated after Qdrant restart"
    else
        echo "❌ Critical: Unable to recreate collection"
        echo "🆘 Manual intervention required - check Qdrant logs"
        exit 1
    fi
fi

echo "📊 Collection recovery completed"
```

#### Vector Data Recovery

```bash
#!/bin/bash
# scripts/recover-vectors.sh

echo "📊 Vector Data Recovery"
echo "======================="

COLLECTION_NAME="cortex-memory"
BACKUP_DIR="/backups/qdrant"

# 1. Check current vector count
echo "📈 Current vector count:"
curl -s http://localhost:6333/collections/$COLLECTION_NAME | jq '.result.points_count'

# 2. List available backups
echo "📦 Available backups:"
ls -la $BACKUP_DIR/*.snapshot.gz 2>/dev/null || echo "No backups found"

# 3. Interactive restore if backup exists
if [ -n "$(ls -A $BACKUP_DIR/*.snapshot.gz 2>/dev/null)" ]; then
    echo "🔄 Backup found. Do you want to restore? (y/N)"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "📋 Select backup to restore:"
        select backup in $BACKUP_DIR/*.snapshot.gz; do
            if [ -n "$backup" ]; then
                echo "🔄 Restoring from: $backup"

                # Decompress backup
                gunzip -c "$backup" > /tmp/restore.snapshot

                # Restore collection from snapshot
                curl -X POST "http://localhost:6333/collections/$COLLECTION_NAME/snapshots/restore" \
                  -H "Content-Type: application/json" \
                  -d '{"snapshot_name": "restore.snapshot"}'

                # Verify restore
                sleep 10
                VECTOR_COUNT=$(curl -s http://localhost:6333/collections/$COLLECTION_NAME | jq '.result.points_count')
                echo "✅ Restore completed. New vector count: $VECTOR_COUNT"

                break
            fi
        done
    fi
else
    echo "⚠️  No backups available. Collection will be empty."
fi
```

## 🔄 Backup & Restore Procedures

### 1. Automated Backup Setup

#### Daily Backup Script

```bash
#!/bin/bash
# scripts/daily-backup.sh

set -e

# Configuration
BACKUP_DIR="/backups"
S3_BUCKET="cortex-backups"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "🔄 Starting daily backup procedure"

# Create backup directory
mkdir -p $BACKUP_DIR/qdrant
mkdir -p $BACKUP_DIR/config
mkdir -p $BACKUP_DIR/logs

# 1. Qdrant Backup
log "📊 Creating Qdrant snapshot..."
SNAPSHOT_NAME="cortex_backup_$DATE"

curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$SNAPSHOT_NAME\"}"

# Wait for snapshot creation
sleep 30

# Find and copy snapshot
SNAPSHOT_PATH="/qdrant/snapshots/cortex-memory/$SNAPSHOT_NAME.snapshot"
if [ -f "$SNAPSHOT_PATH" ]; then
    cp "$SNAPSHOT_PATH" "$BACKUP_DIR/qdrant/"
    gzip "$BACKUP_DIR/qdrant/$SNAPSHOT_NAME.snapshot"
    log "✅ Qdrant snapshot created: $SNAPSHOT_NAME.snapshot.gz"
else
    log "❌ Failed to create Qdrant snapshot"
    exit 1
fi

# 2. Configuration Backup
log "⚙️ Backing up configuration..."
cp -r /app/config $BACKUP_DIR/config/config_$DATE/
cp /app/.env $BACKUP_DIR/config/.env_$DATE
cp /app/package.json $BACKUP_DIR/config/package_$DATE.json

# Create config archive
tar -czf "$BACKUP_DIR/config/config_$DATE.tar.gz" -C "$BACKUP_DIR/config" "config_$DATE" ".env_$DATE" "package_$DATE.json"
rm -rf "$BACKUP_DIR/config/config_$DATE" "$BACKUP_DIR/config/.env_$DATE" "$BACKUP_DIR/config/package_$DATE.json"

# 3. Logs Backup
log "📝 Backing up logs..."
find /app/logs -name "*.log" -mtime -1 -exec cp {} $BACKUP_DIR/logs/ \;
tar -czf "$BACKUP_DIR/logs/logs_$DATE.tar.gz" -C "$BACKUP_DIR/logs" .

# 4. Upload to S3 (if configured)
if command -v aws &> /dev/null; then
    log "☁️ Uploading to S3..."

    aws s3 cp "$BACKUP_DIR/qdrant/$SNAPSHOT_NAME.snapshot.gz" \
        "s3://$S3_BUCKET/qdrant/$SNAPSHOT_NAME.snapshot.gz" \
        --storage-class STANDARD_IA

    aws s3 cp "$BACKUP_DIR/config/config_$DATE.tar.gz" \
        "s3://$S3_BUCKET/config/config_$DATE.tar.gz" \
        --storage-class STANDARD_IA

    aws s3 cp "$BACKUP_DIR/logs/logs_$DATE.tar.gz" \
        "s3://$S3_BUCKET/logs/logs_$DATE.tar.gz" \
        --storage-class STANDARD_IA

    log "✅ Upload to S3 completed"
else
    log "⚠️ AWS CLI not found, skipping S3 upload"
fi

# 5. Cleanup old backups
log "🧹 Cleaning up old backups..."
find $BACKUP_DIR/qdrant -name "*.snapshot.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR/config -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR/logs -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

# S3 cleanup (if available)
if command -v aws &> /dev/null; then
    aws s3 ls "s3://$S3_BUCKET/qdrant/" | \
        while read -r line; do
            createDate=$(echo $line | awk '{print $1" "$2}')
            createDate=$(date -d "$createDate" +%s)
            olderThan=$(date -d "$RETENTION_DAYS days ago" +%s)
            if [[ $createDate -lt $olderThan ]]; then
                fileName=$(echo $line | awk '{print $4}')
                if [[ $fileName != "" ]]; then
                    aws s3 rm "s3://$S3_BUCKET/qdrant/$fileName"
                fi
            fi
        done
fi

# 6. Backup verification
log "✅ Backup verification..."
BACKUP_SIZE=$(du -sh $BACKUP_DIR | cut -f1)
VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count')

log "📊 Backup Summary:"
log "   Backup Size: $BACKUP_SIZE"
log "   Vector Count: $VECTOR_COUNT"
log "   Snapshot: $SNAPSHOT_NAME.snapshot.gz"

log "✅ Daily backup completed successfully"
```

#### Backup Verification Script

```bash
#!/bin/bash
# scripts/verify-backup.sh

echo "🔍 Backup Verification"
echo "====================="

BACKUP_DIR="/backups"
TODAY=$(date +%Y%m%d)

# 1. Check today's backup exists
echo "📋 Checking today's backup..."
TODAY_BACKUP=$(find $BACKUP_DIR/qdrant -name "*$TODAY*.snapshot.gz" | head -1)

if [ -z "$TODAY_BACKUP" ]; then
    echo "❌ No backup found for today"
    exit 1
fi

echo "✅ Found backup: $TODAY_BACKUP"

# 2. Verify backup integrity
echo "🔍 Verifying backup integrity..."
if gzip -t "$TODAY_BACKUP"; then
    echo "✅ Backup file integrity verified"
else
    echo "❌ Backup file is corrupted"
    exit 1
fi

# 3. Test backup restoration (dry run)
echo "🧪 Testing backup restoration (dry run)..."
TEST_DIR="/tmp/backup_test_$$"
mkdir -p $TEST_DIR

# Extract backup to test directory
gunzip -c "$TODAY_BACKUP" > "$TEST_DIR/test.snapshot"

# Check if snapshot looks valid
if [ -s "$TEST_DIR/test.snapshot" ]; then
    echo "✅ Backup extraction test passed"
else
    echo "❌ Backup extraction test failed"
    rm -rf $TEST_DIR
    exit 1
fi

rm -rf $TEST_DIR

# 4. Check S3 backup (if configured)
if command -v aws &> /dev/null; then
    echo "☁️ Checking S3 backup..."
    S3_BACKUP=$(aws s3 ls s3://cortex-backups/qdrant/ | grep "$TODAY" | head -1)

    if [ -n "$S3_BACKUP" ]; then
        echo "✅ S3 backup verified"
    else
        echo "⚠️ S3 backup not found"
    fi
fi

echo "✅ Backup verification completed successfully"
```

### 2. Restore Procedures

#### Full System Restore

```bash
#!/bin/bash
# scripts/full-restore.sh

set -e

BACKUP_DATE=$1
RESTORE_DIR="/tmp/restore_$$"

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    echo "Example: $0 20241103_120000"
    exit 1
fi

echo "🔄 Full System Restore"
echo "====================="
echo "Backup Date: $BACKUP_DATE"

# Create restore directory
mkdir -p $RESTORE_DIR

# 1. Stop services
echo "⏹️ Stopping services..."
systemctl stop cortex-mcp
systemctl stop qdrant

# 2. Backup current state (just in case)
echo "💾 Backing up current state..."
CURRENT_DATE=$(date +%Y%m%d_%H%M%S)
cp -r /qdrant/storage "/backups/emergency_backup_$CURRENT_DATE" 2>/dev/null || true

# 3. Download backup from S3 if needed
echo "📥 Downloading backup..."
aws s3 cp "s3://cortex-backups/qdrant/cortex_backup_$BACKUP_DATE.snapshot.gz" "$RESTORE_DIR/"

# 4. Extract backup
echo "📂 Extracting backup..."
gunzip -c "$RESTORE_DIR/cortex_backup_$BACKUP_DATE.snapshot.gz" > "$RESTORE_DIR/restore.snapshot"

# 5. Clear current Qdrant data
echo "🧹 Clearing current Qdrant data..."
rm -rf /qdrant/storage/*

# 6. Start Qdrant
echo "🚀 Starting Qdrant..."
systemctl start qdrant
sleep 30

# 7. Create collection
echo "🏗️ Creating collection..."
curl -X PUT http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    }
  }'

# 8. Restore data
echo "📊 Restoring vector data..."
cp "$RESTORE_DIR/restore.snapshot" "/qdrant/snapshots/cortex-memory/"

curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots/restore" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_name": "restore.snapshot"}'

# 9. Verify restore
echo "🔍 Verifying restore..."
sleep 30

VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count')
COLLECTION_INFO=$(curl -s http://localhost:6333/collections/cortex-memory)

echo "📊 Restore Results:"
echo "   Vector Count: $VECTOR_COUNT"
echo "   Collection Info: $COLLECTION_INFO"

# 10. Start Cortex MCP
echo "🚀 Starting Cortex MCP..."
systemctl start cortex-mcp
sleep 15

# 11. Final verification
echo "🔍 Final system verification..."
curl -f http://localhost:3000/health && echo "✅ MCP Server healthy"
curl -f http://localhost:6333/health && echo "✅ Qdrant healthy"

# Cleanup
rm -rf $RESTORE_DIR

echo "✅ Full system restore completed successfully!"
echo "🎯 System is ready for operation"
```

#### Point-in-Time Recovery

```bash
#!/bin/bash
# scripts/point-in-time-restore.sh

set -e

BACKUP_TIMESTAMP=$1  # Unix timestamp
RESTORE_DIR="/tmp/pitr_restore_$$"

if [ -z "$BACKUP_TIMESTAMP" ]; then
    echo "Usage: $0 <unix_timestamp>"
    echo "Example: $0 1698710400"
    exit 1
fi

echo "🕐 Point-in-Time Recovery"
echo "========================="
echo "Target Time: $(date -d @$BACKUP_TIMESTAMP)"

# Convert timestamp to backup date format
BACKUP_DATE=$(date -d @$BACKUP_TIMESTAMP +%Y%m%d_%H%M%S)

echo "🔍 Looking for backup near: $BACKUP_DATE"

# Find closest backup
CLOSEST_BACKUP=$(aws s3 ls s3://cortex-backups/qdrant/ | \
    awk '{print $4}' | \
    grep -E "cortex_backup_[0-9]{8}_[0-9]{6}\.snapshot\.gz" | \
    sed 's/cortex_backup_//' | sed 's/\.snapshot\.gz//' | \
    sort -n | \
    awk -v target="$BACKUP_DATE" '
    function abs(x) { return x < 0 ? -x : x }
    {
        diff = abs($1 - target)
        if (diff < min_diff || NR == 1) {
            min_diff = diff
            closest = $1
        }
    }
    END {
        print closest
    }')

if [ -z "$CLOSEST_BACKUP" ]; then
    echo "❌ No suitable backup found"
    exit 1
fi

echo "📦 Selected backup: cortex_backup_$CLOSEST_BACKUP.snapshot.gz"
echo "⚠️  Note: This is the closest available backup to your target time"

# Proceed with restore using the found backup
./scripts/full-restore.sh "$CLOSEST_BACKUP"

echo "✅ Point-in-time recovery completed"
```

## 🚨 Monitoring & Alerting

### 1. Critical Alerts Configuration

#### Prometheus Alert Rules

```yaml
# monitoring/cortex-critical-alerts.yml
groups:
  - name: cortex-critical
    rules:
      - alert: CortexMCPDown
        expr: up{job="cortex-mcp"} == 0
        for: 1m
        labels:
          severity: critical
          service: cortex-mcp
        annotations:
          summary: "Cortex MCP Server is down"
          description: "Cortex MCP server has been down for more than 1 minute"
          runbook_url: "https://docs.cortex.ai/runbooks/mcp-server-down"

      - alert: QdrantDown
        expr: up{job="qdrant"} == 0
        for: 2m
        labels:
          severity: critical
          service: qdrant
        annotations:
          summary: "Qdrant database is down"
          description: "Qdrant vector database has been down for more than 2 minutes"
          runbook_url: "https://docs.cortex.ai/runbooks/qdrant-down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
          runbook_url: "https://docs.cortex.ai/runbooks/high-error-rate"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
          service: cortex-mcp
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value }}s"
          runbook_url: "https://docs.cortex.ai/runbooks/high-response-time"

      - alert: LowVectorCount
        expr: qdrant_collection_points < 1000
        for: 10m
        labels:
          severity: warning
          service: qdrant
        annotations:
          summary: "Low vector count in collection"
          description: "Collection has only {{ $value }} vectors - possible data loss"
          runbook_url: "https://docs.cortex.ai/runbooks/low-vector-count"

      - alert: DiskSpaceCritical
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
          service: system
        annotations:
          summary: "Critical disk space"
          description: "Disk space is {{ $value }}% full"
          runbook_url: "https://docs.cortex.ai/runbooks/disk-space"

      - alert: MemoryUsageHigh
        expr: (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 < 10
        for: 5m
        labels:
          severity: warning
          service: system
        annotations:
          summary: "High memory usage"
          description: "Available memory is {{ $value }}%"
          runbook_url: "https://docs.cortex.ai/runbooks/high-memory"
```

#### AlertManager Configuration

```yaml
# monitoring/alertmanager.yml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alerts@cortex.ai'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'web.hook'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://localhost:5001/'

  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@cortex.ai'
        subject: '[CRITICAL] Cortex Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Runbook: {{ .Annotations.runbook_url }}
          {{ end }}
    slack_configs:
      - api_url: 'SLACK_WEBHOOK_URL'
        channel: '#cortex-alerts'
        title: '🚨 CRITICAL ALERT'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}

  - name: 'warning-alerts'
    email_configs:
      - to: 'devops@cortex.ai'
        subject: '[WARNING] Cortex Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
```

### 2. Health Check Scripts

#### Comprehensive Health Check

```bash
#!/bin/bash
# scripts/health-check.sh

set -e

echo "🏥 Cortex MCP Health Check"
echo "========================="
DATE=$(date)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    local status=$1
    local message=$2

    case $status in
        "OK")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "CRITICAL")
            echo -e "${RED}❌ $message${NC}"
            ;;
        *)
            echo -e "ℹ️  $message"
            ;;
    esac
}

# Initialize health status
OVERALL_STATUS="OK"
ISSUES_FOUND=()

echo "Health check started at: $DATE"
echo

# 1. Check MCP Server
echo "🔍 Checking MCP Server..."
if curl -f -s http://localhost:3000/health > /dev/null; then
    MCP_RESPONSE=$(curl -s http://localhost:3000/health)
    print_status "OK" "MCP Server is healthy"

    # Check response time
    RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)
    if (( $(echo "$RESPONSE_TIME > 1.0" | bc -l) )); then
        print_status "WARN" "MCP Server response time is ${RESPONSE_TIME}s (slow)"
        ISSUES_FOUND+=("MCP slow response")
    fi
else
    print_status "CRITICAL" "MCP Server is down"
    OVERALL_STATUS="CRITICAL"
    ISSUES_FOUND+=("MCP server down")
fi

# 2. Check Qdrant
echo
echo "🔍 Checking Qdrant Database..."
if curl -f -s http://localhost:6333/health > /dev/null; then
    print_status "OK" "Qdrant is healthy"

    # Check collection
    COLLECTION_STATUS=$(curl -s http://localhost:6333/collections/cortex-memory)
    VECTOR_COUNT=$(echo $COLLECTION_STATUS | jq -r '.result.points_count // "unknown"')

    if [ "$VECTOR_COUNT" != "unknown" ] && [ "$VECTOR_COUNT" -gt 0 ]; then
        print_status "OK" "Collection has $VECTOR_COUNT vectors"
    elif [ "$VECTOR_COUNT" = "unknown" ]; then
        print_status "WARN" "Unable to determine vector count"
        ISSUES_FOUND+=("Vector count unknown")
    else
        print_status "WARN" "Collection is empty"
        ISSUES_FOUND+=("Empty collection")
    fi
else
    print_status "CRITICAL" "Qdrant is down"
    OVERALL_STATUS="CRITICAL"
    ISSUES_FOUND+=("Qdrant down")
fi

# 3. Check System Resources
echo
echo "🔍 Checking System Resources..."

# Memory check
MEMORY_AVAILABLE=$(free | awk 'NR==2{printf "%.1f", $7*100/$2}')
if (( $(echo "$MEMORY_AVAILABLE < 10" | bc -l) )); then
    print_status "CRITICAL" "Only ${MEMORY_AVAILABLE}% memory available"
    OVERALL_STATUS="CRITICAL"
    ISSUES_FOUND+=("Low memory")
elif (( $(echo "$MEMORY_AVAILABLE < 20" | bc -l) )); then
    print_status "WARN" "Only ${MEMORY_AVAILABLE}% memory available"
    ISSUES_FOUND+=("Memory warning")
else
    print_status "OK" "${MEMORY_AVAILABLE}% memory available"
fi

# Disk check
DISK_AVAILABLE=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
if [ "$DISK_AVAILABLE" -gt 90 ]; then
    print_status "CRITICAL" "Disk usage is ${DISK_AVAILABLE}%"
    OVERALL_STATUS="CRITICAL"
    ISSUES_FOUND+=("Disk space critical")
elif [ "$DISK_AVAILABLE" -gt 80 ]; then
    print_status "WARN" "Disk usage is ${DISK_AVAILABLE}%"
    ISSUES_FOUND+=("Disk space warning")
else
    print_status "OK" "Disk usage is ${DISK_AVAILABLE}%"
fi

# CPU check
CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
if (( $(echo "$CPU_LOAD > 2.0" | bc -l) )); then
    print_status "WARN" "CPU load is ${CPU_LOAD}"
    ISSUES_FOUND+=("High CPU load")
else
    print_status "OK" "CPU load is ${CPU_LOAD}"
fi

# 4. Check External Dependencies
echo
echo "🔍 Checking External Dependencies..."

# OpenAI API check
if curl -f -s -H "Authorization: Bearer $OPENAI_API_KEY" \
   https://api.openai.com/v1/models > /dev/null 2>&1; then
    print_status "OK" "OpenAI API is accessible"
else
    print_status "WARN" "OpenAI API is not accessible"
    ISSUES_FOUND+=("OpenAI API issue")
fi

# 5. Check Recent Logs
echo
echo "🔍 Checking Recent Logs..."
ERROR_COUNT=$(grep -c "ERROR" /app/logs/cortex-mcp.log 2>/dev/null || echo "0")
if [ "$ERROR_COUNT" -gt 10 ]; then
    print_status "WARN" "Found $ERROR_COUNT errors in recent logs"
    ISSUES_FOUND+=("High error count")
else
    print_status "OK" "Low error count in logs ($ERROR_COUNT)"
fi

# 6. Summary
echo
echo "📊 Health Check Summary"
echo "======================="
echo "Overall Status: $OVERALL_STATUS"

if [ ${#ISSUES_FOUND[@]} -gt 0 ]; then
    echo
    echo "Issues Found:"
    for issue in "${ISSUES_FOUND[@]}"; do
        echo "  - $issue"
    done

    echo
    if [ "$OVERALL_STATUS" = "CRITICAL" ]; then
        echo "🚨 IMMEDIATE ACTION REQUIRED"
        echo "Run: ./scripts/emergency-response.sh"
    else
        echo "⚠️  Monitor these issues and address as needed"
    fi
else
    echo "✅ All systems operating normally"
fi

echo
echo "Health check completed at: $(date)"

# Exit with appropriate code
if [ "$OVERALL_STATUS" = "CRITICAL" ]; then
    exit 2
elif [ ${#ISSUES_FOUND[@]} -gt 0 ]; then
    exit 1
else
    exit 0
fi
```

## 📋 New Engineer Onboarding

### 1. System Access & Setup

#### Initial Access Checklist

```bash
#!/bin/bash
# scripts/onboarding-setup.sh

echo "👋 Welcome to Cortex MCP Operations!"
echo "=================================="
echo "This script will set up your environment for Cortex MCP operations."
echo

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check if user has sudo access
if ! sudo -n true 2>/dev/null; then
    echo "❌ This script requires sudo access. Please run with sudo."
    exit 1
fi

# Check if required tools are installed
REQUIRED_TOOLS=("curl" "jq" "docker" "kubectl" "aws")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "❌ Missing required tools: ${MISSING_TOOLS[*]}"
    echo "Please install these tools and run this script again."
    exit 1
fi

echo "✅ All required tools are installed"

# Create workspace directory
WORKSPACE_DIR="/home/$USER/cortex-ops"
mkdir -p $WORKSPACE_DIR
cd $WORKSPACE_DIR

echo "📁 Created workspace: $WORKSPACE_DIR"

# Clone or update operations repository
if [ -d "cortex-ops" ]; then
    cd cortex-ops
    git pull origin main
    echo "📥 Updated operations repository"
else
    git clone https://github.com/your-org/cortex-ops.git
    cd cortex-ops
    echo "📥 Cloned operations repository"
fi

# Set up scripts directory
mkdir -p scripts
chmod +x scripts/*.sh

# Create configuration directory
mkdir -p config
mkdir -p logs
mkdir -p backups

echo "🔧 Created required directories"

# Download latest configuration
echo "⚙️ Downloading configuration..."
# This would typically pull from your configuration management system
# aws s3 cp s3://cortex-configs/production.env config/

# Set up environment variables
echo "📝 Setting up environment variables..."
cat > ~/.bashrc.d/cortex-mcp.sh << 'EOF'
# Cortex MCP Environment Variables
export CORTEX_MCP_HOME="/home/$USER/cortex-ops"
export PATH="$PATH:$CORTEX_MCP_HOME/scripts"

# Aliases for common operations
alias cortex-health='~/cortex-ops/scripts/health-check.sh'
alias cortex-logs='tail -f /app/logs/cortex-mcp.log'
alias cortex-backup='~/cortex-ops/scripts/daily-backup.sh'
alias cortex-restart='sudo systemctl restart cortex-mcp'

# Useful functions
cortex-status() {
    echo "🏥 Cortex MCP Status"
    echo "=================="
    sudo systemctl status cortex-mcp --no-pager
    sudo systemctl status qdrant --no-pager
    curl -s http://localhost:3000/health | jq .
}

cortex-logs-error() {
    tail -100 /app/logs/cortex-mcp.log | grep ERROR
}
EOF

# Source the new environment
source ~/.bashrc.d/cortex-mcp.sh

echo "✅ Environment setup completed"

# Test access
echo
echo "🧪 Testing system access..."
if sudo systemctl status cortex-mcp --no-pager > /dev/null 2>&1; then
    echo "✅ Can access Cortex MCP service"
else
    echo "❌ Cannot access Cortex MCP service - check permissions"
fi

if curl -s http://localhost:3000/health > /dev/null; then
    echo "✅ Can access Cortex MCP API"
else
    echo "❌ Cannot access Cortex MCP API - check if service is running"
fi

echo
echo "🎉 Onboarding setup completed!"
echo
echo "Next steps:"
echo "1. Read the documentation: ~/cortex-ops/docs/"
echo "2. Review the runbooks: ~/cortex-ops/runbooks/"
echo "3. Test your access: cortex-health"
echo "4. Join the operations Slack channel: #cortex-ops"
echo
echo "Important contacts:"
echo "- Operations Lead: ops-lead@cortex.ai"
echo "- Engineering Team: eng@cortex.ai"
echo "- Emergency: oncall@cortex.ai"
echo
echo "Useful commands:"
echo "- cortex-status    - Check system status"
echo "- cortex-health    - Run comprehensive health check"
echo "- cortex-logs      - View live logs"
echo "- cortex-backup    - Create backup"
echo "- cortex-restart   - Restart service"
```

### 2. Knowledge Base & Documentation

#### Quick Reference Card

```bash
# Create quick reference file
cat > ~/cortex-ops/QUICK_REFERENCE.md << 'EOF'
# Cortex MCP Operations Quick Reference

## 🚨 Emergency Commands (First 5 Minutes)

```bash
# Check system status
cortex-status

# Full health check
cortex-health

# Restart services
cortex-restart

# View recent errors
cortex-logs-error

# Emergency restore (if needed)
sudo ~/cortex-ops/scripts/emergency-restore.sh
```

## 🔍 Common Troubleshooting

### MCP Server Issues
```bash
# Check if service is running
sudo systemctl status cortex-mcp

# Restart service
sudo systemctl restart cortex-mcp

# View logs
sudo journalctl -u cortex-mcp -f

# Check configuration
cat /app/.env
```

### Qdrant Issues
```bash
# Check Qdrant status
curl http://localhost:6333/health

# Restart Qdrant
sudo systemctl restart qdrant

# Check collection info
curl http://localhost:6333/collections/cortex-memory | jq .
```

### Performance Issues
```bash
# Check system resources
free -h
df -h
top

# Check connection counts
netstat -an | grep :3000 | wc -l
netstat -an | grep :6333 | wc -l
```

## 📊 Monitoring

### Grafana Dashboards
- Main Dashboard: https://grafana.cortex.ai/d/cortex-main
- Database Dashboard: https://grafana.cortex.ai/d/cortex-db
- System Dashboard: https://grafana.cortex.ai/d/cortex-system

### AlertManager
- Alerts: https://alertmanager.cortex.ai
- Silence Rules: https://alertmanager.cortex.ai/#/silences

## 🔄 Maintenance Tasks

### Daily
```bash
# Health check
cortex-health

# Check backups
ls -la /backups/qdrant/
```

### Weekly
```bash
# Log cleanup
sudo ~/cortex-ops/scripts/cleanup-logs.sh

# Performance review
# Check Grafana dashboards for trends
```

### Monthly
```bash
# Security updates
sudo apt update && sudo apt upgrade -y

# Backup verification
~/cortex-ops/scripts/verify-backup.sh
```

## 📞 Escalation Contacts

| Issue Type | Contact | Method |
|------------|---------|--------|
| Critical System Failure | On-call Engineer | oncall@cortex.ai, +1-555-CORTEX1 |
| Security Incident | Security Team | security@cortex.ai, #security-alerts |
| Performance Issues | Performance Team | perf@cortex.ai, #perf-team |
| Database Issues | DBA Team | dba@cortex.ai, #dba-team |

## 🏥 Health Check Interpretation

- ✅ OK: System is healthy
- ⚠️ WARN: Monitor closely, may need attention
- ❌ CRITICAL: Immediate action required

## 🔧 Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| Environment Variables | `/app/.env` | Runtime configuration |
| MCP Config | `/app/config/mcp.json` | MCP server settings |
| Qdrant Config | `/etc/qdrant/config.yaml` | Database configuration |
| Systemd Service | `/etc/systemd/system/cortex-mcp.service` | Service definition |

## 📁 Important Directories

| Directory | Purpose |
|-----------|---------|
| `/app/logs` | Application logs |
| `/backups` | Backup storage |
| `/app/config` | Configuration files |
| `/qdrant/storage` | Qdrant data storage |
| `/var/log` | System logs |
EOF

echo "✅ Created quick reference guide"
```

## 🔧 Troubleshooting Runbooks

### 1. Service Down Scenarios

#### MCP Server Down Runbook

```markdown
# Runbook: MCP Server Down

## Severity: Critical
## Estimated Time to Resolve: 5-15 minutes

## Symptoms
- Health check fails: `curl http://localhost:3000/health`
- Service status shows inactive: `systemctl status cortex-mcp`
- API calls return connection refused
- Alert: CortexMCPDown

## Immediate Actions (First 5 Minutes)

### 1. Verify Service Status
```bash
# Check service status
sudo systemctl status cortex-mcp

# Check if process is running
ps aux | grep "node.*index.js"

# Check port availability
netstat -tlnp | grep :3000
```

### 2. Check Logs for Errors
```bash
# Check recent logs
sudo journalctl -u cortex-mcp --no-pager -n 50

# Check application logs
tail -50 /app/logs/cortex-mcp.log
tail -50 /app/logs/error.log
```

### 3. Common Issues & Solutions

#### Out of Memory
**Symptoms**: OOM killer messages in logs
**Solution**:
```bash
# Check memory usage
free -h

# Restart service
sudo systemctl restart cortex-mcp

# If OOM persists, check for memory leaks
# Monitor with: top -p $(pgrep -f "node.*index.js")
```

#### Configuration Error
**Symptoms**: Failed to start due to config issues
**Solution**:
```bash
# Check environment variables
cat /app/.env

# Validate configuration
node -e "require('./dist/index.js')"

# Fix configuration issues and restart
sudo systemctl restart cortex-mcp
```

#### Port Already in Use
**Symptoms**: Address already in use error
**Solution**:
```bash
# Find process using port
sudo lsof -i :3000

# Kill conflicting process
sudo kill -9 <PID>

# Restart service
sudo systemctl restart cortex-mcp
```

### 4. Restart Procedure
```bash
# Graceful restart
sudo systemctl restart cortex-mcp

# If graceful restart fails
sudo pkill -f "node.*index.js"
sleep 5
sudo systemctl start cortex-mcp

# Verify service is running
sudo systemctl status cortex-mcp
curl http://localhost:3000/health
```

### 5. Verification
```bash
# Health check
curl http://localhost:3000/health

# Readiness check
curl http://localhost:3000/ready

# Check logs for startup
sudo journalctl -u cortex-mcp -f
```

## Escalation Criteria
Escalate immediately if:
- Service fails to restart after 3 attempts
- Multiple services are down
- Data corruption is suspected
- Security breach is suspected

## Prevention
- Monitor memory usage trends
- Regular log review
- Configuration validation in CI/CD
- Regular restart after updates
```

### 2. Performance Issues

#### High Response Time Runbook

```markdown
# Runbook: High Response Time

## Severity: Warning
## Estimated Time to Resolve: 15-30 minutes

## Symptoms
- API response times > 2 seconds
- Slow search queries
- High CPU or memory usage
- Alert: HighResponseTime

## Investigation Steps

### 1. Measure Current Performance
```bash
# Test API response time
time curl http://localhost:3000/health

# Check detailed metrics
curl http://localhost:3000/metrics | grep http_request_duration

# Monitor system resources
top -p $(pgrep -f "node.*index.js")
iostat -x 1 5
```

### 2. Check Common Causes

#### High CPU Usage
```bash
# Identify CPU-intensive processes
top -p $(pgrep -f "node.*index.js")

# Check for infinite loops or memory leaks
sudo strace -p $(pgrep -f "node.*index.js") -c

# Solution: Restart service if needed
sudo systemctl restart cortex-mcp
```

#### Memory Pressure
```bash
# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable|SwapTotal|SwapFree)"

# Check Node.js heap usage
node -e "
const process = require('process');
const used = process.memoryUsage();
console.log('Memory Usage:');
for (let key in used) {
  console.log(\`\${key}: \${Math.round(used[key] / 1024 / 1024 * 100) / 100} MB\`);
}
"

# Solution: Add more memory or optimize application
```

#### Database Performance
```bash
# Check Qdrant performance
curl http://localhost:6333/metrics

# Check search query performance
curl -X POST http://localhost:6333/collections/cortex-memory/search \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, ...], "limit": 10}' \
  -w "Time: %{time_total}s\n"

# Solution: Optimize search parameters or add more resources
```

#### Network Issues
```bash
# Check network connectivity
ping -c 3 localhost
netstat -i

# Check connection limits
ulimit -n
cat /proc/sys/net/core/somaxconn

# Solution: Increase connection limits or fix network issues
```

### 3. Performance Optimization

#### Application Level
```bash
# Check for memory leaks
node --inspect dist/index.js
# Connect Chrome DevTools and analyze heap

# Enable performance logging
export LOG_LEVEL=debug
export NODE_OPTIONS="--trace-warnings"
```

#### Database Level
```bash
# Optimize Qdrant configuration
# Edit /etc/qdrant/config.yaml
# Add more search threads, optimize memory usage

# Create collection with optimized settings
curl -X PUT http://localhost:6333/collections/cortex-memory-optimized \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    },
    "optimizers_config": {
      "default_segment_number": 4,
      "max_segment_size": 100000,
      "memmap_threshold": 20000
    }
  }'
```

### 4. Monitoring & Verification
```bash
# Monitor performance after changes
watch -n 5 'curl -s http://localhost:3000/metrics | grep http_request_duration'

# Check if response times improve
time curl http://localhost:3000/api/memory/find \
  -H "Content-Type: application/json" \
  -d '{"query": "test", "limit": 10}'
```

## Escalation Criteria
Escalate if:
- Response times remain > 5s after optimization
- System resources are consistently > 90%
- Multiple users are affected
- Issue persists > 1 hour

## Prevention
- Set up performance monitoring alerts
- Regular performance testing
- Capacity planning based on usage trends
- Regular optimization reviews
```

## 📊 System Metrics & KPIs

### 1. Key Performance Indicators

```bash
# scripts/metrics-collector.sh

#!/bin/bash
# Collect and report system metrics

METRICS_FILE="/var/log/cortex-metrics.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log metric
log_metric() {
    echo "$DATE $1" >> $METRICS_FILE
}

# Collect system metrics
log_metric "SYSTEM_MEMORY_AVAILABLE=$(free | awk 'NR==2{print $7}')"
log_metric "SYSTEM_MEMORY_TOTAL=$(free | awk 'NR==2{print $2}')"
log_metric "SYSTEM_DISK_USED=$(df / | awk 'NR==2{print $3}')"
log_metric "SYSTEM_DISK_TOTAL=$(df / | awk 'NR==2{print $2}')"
log_metric "SYSTEM_CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')"

# Collect application metrics
if curl -s http://localhost:3000/health > /dev/null; then
    log_metric "MCP_STATUS=healthy"

    # Get application metrics if available
    if curl -s http://localhost:3000/metrics > /dev/null; then
        HTTP_REQUESTS=$(curl -s http://localhost:3000/metrics | grep "http_requests_total" | tail -1)
        RESPONSE_TIME=$(curl -s http://localhost:3000/metrics | grep "http_request_duration_seconds" | tail -1)

        log_metric "MCP_HTTP_REQUESTS=$HTTP_REQUESTS"
        log_metric "MCP_RESPONSE_TIME=$RESPONSE_TIME"
    fi
else
    log_metric "MCP_STATUS=unhealthy"
fi

# Collect database metrics
if curl -s http://localhost:6333/health > /dev/null; then
    log_metric "QDRANT_STATUS=healthy"

    # Get collection info
    COLLECTION_INFO=$(curl -s http://localhost:6333/collections/cortex-memory)
    VECTOR_COUNT=$(echo $COLLECTION_INFO | jq -r '.result.points_count // 0')
    DISK_SIZE=$(echo $COLLECTION_INFO | jq -r '.result.disk_data_size // 0')

    log_metric "QDRANT_VECTOR_COUNT=$VECTOR_COUNT"
    log_metric "QDRANT_DISK_SIZE=$DISK_SIZE"
else
    log_metric "QDRANT_STATUS=unhealthy"
fi

echo "Metrics collected at $DATE"
```

### 2. Performance Baselines

```bash
# scripts/performance-baseline.sh

#!/bin/bash
# Establish performance baselines

echo "📊 Establishing Performance Baselines"
echo "===================================="

BASELINE_FILE="/var/log/cortex-baseline.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to record baseline
record_baseline() {
    echo "$DATE BASELINE $1" >> $BASELINE_FILE
}

# API Response Time Baseline
echo "🕐 Measuring API response times..."
RESPONSE_TIME_HEALTH=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)
RESPONSE_TIME_SEARCH=$(curl -o /dev/null -s -w '%{time_total}' \
  -X POST http://localhost:3000/api/memory/find \
  -H "Content-Type: application/json" \
  -d '{"query": "test", "limit": 10}')

record_baseline "API_HEALTH_RESPONSE_TIME=$RESPONSE_TIME_HEALTH"
record_baseline "API_SEARCH_RESPONSE_TIME=$RESPONSE_TIME_SEARCH"

# System Resource Baselines
echo "💾 Recording system resource baselines..."
MEMORY_AVAILABLE=$(free | awk 'NR==2{printf "%.1f", $7*100/$2}')
DISK_AVAILABLE=$(df / | awk 'NR==2{printf "%.1f", $5}' | sed 's/%//')
CPU_LOAD_1MIN=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')

record_baseline "SYSTEM_MEMORY_AVAILABLE_PERCENT=$MEMORY_AVAILABLE"
record_baseline "SYSTEM_DISK_AVAILABLE_PERCENT=$DISK_AVAILABLE"
record_baseline "SYSTEM_CPU_LOAD_1MIN=$CPU_LOAD_1MIN"

# Database Performance Baselines
echo "🗄️ Recording database performance baselines..."
VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.points_count // 0')
SEARCH_PERFORMANCE=$(curl -X POST http://localhost:6333/collections/cortex-memory/search \
  -H "Content-Type: application/json" \
  -d '{"vector": '"$(head -c 10 /dev/urandom | base64 | head -c 1536 | grep -o . | paste -sd "," -)"', "limit": 10}' \
  -o /dev/null -s -w '%{time_total}')

record_baseline "DB_VECTOR_COUNT=$VECTOR_COUNT"
record_baseline "DB_SEARCH_TIME=$SEARCH_PERFORMANCE"

# Generate summary
echo ""
echo "📋 Performance Baseline Summary"
echo "==============================="
echo "Date: $DATE"
echo "API Health Response: ${RESPONSE_TIME_HEALTH}s"
echo "API Search Response: ${RESPONSE_TIME_SEARCH}s"
echo "Memory Available: ${MEMORY_AVAILABLE}%"
echo "Disk Available: ${DISK_AVAILABLE}%"
echo "CPU Load (1min): $CPU_LOAD_1MIN"
echo "Vector Count: $VECTOR_COUNT"
echo "Search Time: ${SEARCH_PERFORMANCE}s"
echo ""
echo "✅ Baseline recorded to $BASELINE_FILE"
```

## 🎯 Success Criteria & Validation

### System Recovery Validation

```bash
#!/bin/bash
# scripts/validate-recovery.sh

echo "🔍 System Recovery Validation"
echo "============================="

VALIDATION_LOG="/var/log/recovery-validation.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log validation result
log_validation() {
    echo "$DATE VALIDATION $1: $2" >> $VALIDATION_LOG
}

# Initialize validation results
PASSED_CHECKS=0
TOTAL_CHECKS=0

# Function to run validation check
run_check() {
    local test_name=$1
    local test_command=$2

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    echo "🧪 Running: $test_name"

    if eval "$test_command"; then
        echo "✅ PASSED: $test_name"
        log_validation "PASSED" "$test_name"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        echo "❌ FAILED: $test_name"
        log_validation "FAILED" "$test_name"
        return 1
    fi
}

# Run validation checks
echo "Starting validation checks..."

# Service availability checks
run_check "MCP Server Health" "curl -f http://localhost:3000/health"
run_check "MCP Server Ready" "curl -f http://localhost:3000/ready"
run_check "Qdrant Health" "curl -f http://localhost:6333/health"

# Functionality checks
run_check "Memory Store API" "curl -f -X POST http://localhost:3000/api/memory/store -H 'Content-Type: application/json' -d '{\"items\":[{\"kind\":\"observation\",\"content\":\"test\"}]}'"
run_check "Memory Find API" "curl -f -X POST http://localhost:3000/api/memory/find -H 'Content-Type: application/json' -d '{\"query\":\"test\"}'"

# Database checks
run_check "Collection Exists" "curl -f http://localhost:6333/collections/cortex-memory"
run_check "Vector Search Works" "curl -f -X POST http://localhost:6333/collections/cortex-memory/search -H 'Content-Type: application/json' -d '{\"vector\":[0.1,0.2],\"limit\":1}'"

# System resource checks
run_check "Memory Available" "test \$(free | awk 'NR==2{printf \"%d\", \$7*100/\$2}') -gt 10"
run_check "Disk Space Available" "test \$(df / | awk 'NR==2{print \$5}' | sed 's/%//') -lt 90"

# External dependency checks
run_check "OpenAI API Access" "curl -f -s -H \"Authorization: Bearer \$OPENAI_API_KEY\" https://api.openai.com/v1/models > /dev/null"

# Performance checks
run_check "API Response Time" "test \$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health | cut -d. -f1) -lt 5"
run_check "Database Search Performance" "test \$(curl -o /dev/null -s -w '%{time_total}' -X POST http://localhost:6333/collections/cortex-memory/search -H 'Content-Type: application/json' -d '{\"vector\":[0.1,0.2],\"limit\":1}' | cut -d. -f1) -lt 2"

# Summary
echo ""
echo "📊 Validation Summary"
echo "===================="
echo "Date: $DATE"
echo "Checks Passed: $PASSED_CHECKS/$TOTAL_CHECKS"
echo "Success Rate: $(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))%"

if [ $PASSED_CHECKS -eq $TOTAL_CHECKS ]; then
    echo "✅ All validation checks passed - System is fully operational"
    log_validation "SUCCESS" "All validation checks passed"
    exit 0
else
    echo "⚠️  Some validation checks failed - Review and address issues"
    log_validation "PARTIAL" "$PASSED_CHECKS/$TOTAL_CHECKS checks passed"
    exit 1
fi
```

This comprehensive disaster recovery and operations manual provides complete procedures for maintaining, monitoring, and recovering the Cortex Memory MCP Server. New engineers can use this guide to quickly understand system operations and effectively handle incidents, while experienced operators have detailed runbooks for complex scenarios.

## 📚 Additional Resources

- [Architecture Documentation](../ARCH-SYSTEM.md)
- [API Reference](../API-REFERENCE.md)
- [Configuration Guide](../SETUP-CONFIGURATION.md)
- [Troubleshooting Guide](../TROUBLESHOOT-ERRORS.md)
- [Monitoring Setup](../CONFIG-MONITORING.md)

For emergencies, contact the on-call team at **oncall@cortex.ai** or call **+1-555-CORTEX1**.