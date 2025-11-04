# Incident Response: Qdrant Service Failure

## Overview

This incident response runbook addresses Qdrant service failures, which are critical incidents affecting the primary data storage layer of the Cortex Memory MCP Server. Qdrant failures impact vector storage, semantic search, and overall system functionality.

## Incident Classification

| Severity | Impact | Response Time | Recovery Time |
|----------|--------|---------------|---------------|
| **Critical** | Complete service outage, no data access | 5 minutes | 15 minutes |
| **High** | Degraded performance, intermittent access | 15 minutes | 1 hour |
| **Medium** | Slow queries, partial functionality | 30 minutes | 4 hours |

## Symptoms and Detection

### Primary Symptoms
- API calls return database connection errors
- Search and memory operations fail
- Health checks fail for `/api/memory/*` endpoints
- High error rates in application logs
- Timeouts when accessing Qdrant directly

### Detection Methods
```bash
# Quick health check (1 minute)
echo "🔍 QDRANT SERVICE HEALTH CHECK"
echo "============================="

# Test Qdrant directly
QDRANT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6333/health 2>/dev/null || echo "000")

if [ "$QDRANT_STATUS" != "200" ]; then
    echo "❌ Qdrant service is DOWN (HTTP $QDRANT_STATUS)"
    echo "Initiating emergency response procedures..."
else
    echo "✅ Qdrant service is UP"
fi

# Test through MCP API
API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/memory/find -H 'Content-Type: application/json' -d '{"query":"test","limit":1}' 2>/dev/null || echo "000")

if [ "$API_STATUS" != "200" ]; then
    echo "❌ MCP API is experiencing issues (HTTP $API_STATUS)"
else
    echo "✅ MCP API is functioning"
fi
```

## Immediate Response (First 5 Minutes)

### 1. Initial Assessment (2 minutes)

```bash
#!/bin/bash
# scripts/incident-qdrant-assessment.sh

set -euo pipefail

echo "🚨 QDRANT INCIDENT ASSESSMENT"
echo "============================"

INCIDENT_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Incident detected at: $INCIDENT_START"

# Check Qdrant service status
echo ""
echo "🔍 Service Status Check:"
echo "======================="

# Docker deployment
if command -v docker &> /dev/null; then
    echo "Docker containers:"
    docker ps | grep qdrant || echo "No Qdrant containers running"
    echo ""
    echo "Qdrant container logs (last 20 lines):"
    docker logs --tail 20 qdrant 2>/dev/null || echo "Unable to fetch container logs"
fi

# Kubernetes deployment
if command -v kubectl &> /dev/null; then
    echo "Kubernetes pods:"
    kubectl get pods -n cortex-mcp -l app=qdrant 2>/dev/null || echo "No Qdrant pods found"
    echo ""
    echo "Qdrant pod events:"
    kubectl describe pods -n cortex-mcp -l app=qdrant | grep -A 20 "Events:" || echo "No events available"
fi

# System resources
echo ""
echo "💻 System Resources:"
echo "===================="
echo "Memory usage:"
free -h
echo ""
echo "Disk usage:"
df -h
echo ""
echo "CPU load:"
uptime

# Network connectivity
echo ""
echo "🌐 Network Connectivity:"
echo "========================"
echo "Port 6333 (Qdrant HTTP):"
netstat -tlnp | grep :6333 || echo "Port 6333 not listening"

echo "Port 6334 (Qdrant gRPC):"
netstat -tlnp | grep :6334 || echo "Port 6334 not listening"

# Check for common issues
echo ""
echo "🐛 Common Issue Detection:"
echo "=========================="

# Check for disk space issues
DISK_USAGE=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "⚠️ HIGH DISK USAGE: ${DISK_USAGE}% - Likely cause of Qdrant failure"
fi

# Check for memory issues
MEMORY_AVAILABLE=$(free -m | awk 'NR==2{print $7}')
if [ "$MEMORY_AVAILABLE" -lt 1024 ]; then
    echo "⚠️ LOW MEMORY: ${MEMORY_AVAILABLE}MB available - Likely cause of Qdrant failure"
fi

# Check for port conflicts
if netstat -tlnp | grep :6333 | grep -v qdrant > /dev/null; then
    echo "⚠️ PORT CONFLICT: Another process using port 6333"
fi

echo ""
echo "Assessment completed at: $(date '+%Y-%m-%d %H:%M:%S')"
```

### 2. Emergency Communication (1 minute)

```bash
#!/bin/bash
# scripts/incident-notify.sh

set -euo pipefail

SEVERITY=${1:-"critical"}
INCIDENT_ID="QDRANT-$(date +%Y%m%d%H%M%S)"

echo "📢 EMERGENCY NOTIFICATION"
echo "========================"
echo "Incident ID: $INCIDENT_ID"
echo "Severity: $SEVERITY"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Create incident notification
cat > /tmp/incident_notification.txt << EOF
🚨 CRITICAL INCIDENT: QDRANT SERVICE FAILURE 🚨

Incident ID: $INCIDENT_ID
Severity: $SEVERITY
Impact: Cortex Memory MCP service outage or severe degradation
Time: $(date '+%Y-%m-%d %H:%M:%S')

Current Status:
- Qdrant vector database is not responding
- Memory search and storage operations are failing
- API endpoints returning database errors

Impact:
- Users cannot store or retrieve memories
- Semantic search functionality is unavailable
- Overall system is severely degraded

Next Steps:
1. Emergency response team has been notified
2. Service recovery procedures are underway
3. Estimated recovery time: 15-30 minutes

Communication:
- Status updates will be provided every 10 minutes
- Use incident ID $INCIDENT_ID for all communications

Contact: On-call Engineer - ${ON_CALL_ENGINEER:-"TBD"}
EOF

# Display notification
cat /tmp/incident_notification.txt

# Send to Slack (if webhook configured)
if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-type: application/json' \
        --data "$(jq -n --arg text "$(cat /tmp/incident_notification.txt)" '{"text": $text}')"
    echo "Slack notification sent"
fi

# Send email (if configured)
if command -v mail &> /dev/null && [ -n "${ALERT_EMAIL:-}" ]; then
    cat /tmp/incident_notification.txt | mail -s "CRITICAL: Qdrant Service Failure - $INCIDENT_ID" "$ALERT_EMAIL"
    echo "Email notification sent"
fi

echo "Emergency notification completed"
```

### 3. Service Recovery Attempts (2 minutes)

```bash
#!/bin/bash
# scripts/emergency-qdrant-restart.sh

set -euo pipefail

echo "🔄 EMERGENCY QDRANT RECOVERY"
echo "==========================="

RECOVERY_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Recovery started at: $RECOVERY_START"

# Create backup before recovery attempts
echo "📦 Creating emergency backup..."
BACKUP_DIR="/tmp/qdrant_emergency_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -d "/qdrant/storage" ]; then
    cp -r /qdrant/storage "$BACKUP_DIR/"
    echo "Storage backed up to: $BACKUP_DIR"
fi

# Recovery Attempt 1: Service restart
echo ""
echo "🔧 Recovery Attempt 1: Service Restart"
echo "======================================"

if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    echo "Restarting Docker container..."
    docker restart qdrant

    # Wait for restart
    sleep 30

    # Test health
    if curl -f -s http://localhost:6333/health > /dev/null; then
        echo "✅ SUCCESS: Qdrant recovered via container restart"
        echo "Recovery time: $(date '+%Y-%m-%d %H:%M:%S')"
        exit 0
    else
        echo "❌ Container restart failed"
    fi
fi

if command -v kubectl &> /dev/null; then
    echo "Restarting Kubernetes pods..."
    kubectl delete pods -n cortex-mcp -l app=qdrant
    kubectl wait --for=condition=Ready pods -n cortex-mcp -l app=qdrant --timeout=300s

    # Test health
    if curl -f -s http://localhost:6333/health > /dev/null; then
        echo "✅ SUCCESS: Qdrant recovered via pod restart"
        echo "Recovery time: $(date '+%Y-%m-%d %H:%M:%S')"
        exit 0
    else
        echo "❌ Pod restart failed"
    fi
fi

# Recovery Attempt 2: Configuration repair
echo ""
echo "🔧 Recovery Attempt 2: Configuration Repair"
echo "=========================================="

# Check for corrupted configuration
if [ -f "/qdrant/config/config.yaml" ]; then
    echo "Checking configuration file..."
    if ! yq eval '.' /qdrant/config/config.yaml > /dev/null 2>&1; then
        echo "Configuration file corrupted - restoring backup"
        if [ -f "/qdrant/config/config.yaml.backup" ]; then
            cp /qdrant/config/config.yaml.backup /qdrant/config/config.yaml
            echo "Configuration restored from backup"
        fi
    fi
fi

# Recovery Attempt 3: Storage repair
echo ""
echo "🔧 Recovery Attempt 3: Storage Repair"
echo "===================================="

if [ -d "/qdrant/storage" ]; then
    echo "Checking storage integrity..."

    # Look for corrupted files
    find /qdrant/storage -name "*.snapshot" -size 0 | while read file; do
        echo "Found empty snapshot file: $file"
        mv "$file" "$file.corrupted"
    done

    # Check for lock files that might prevent startup
    find /qdrant/storage -name "*.lock" -exec rm {} \; 2>/dev/null || true
    echo "Lock files cleared"
fi

# Recovery Attempt 4: Fresh start with data recovery
echo ""
echo "🔧 Recovery Attempt 4: Fresh Start with Data Recovery"
echo "===================================================="

if [ -d "$BACKUP_DIR/storage" ]; then
    echo "Attempting fresh start with data recovery..."

    # Move current storage (keep as backup)
    if [ -d "/qdrant/storage" ]; then
        mv /qdrant/storage "/qdrant/storage.corrupted.$(date +%Y%m%d_%H%M%S)"
    fi

    # Start with empty storage
    mkdir -p /qdrant/storage

    # Restart service
    if command -v docker &> /dev/null; then
        docker restart qdrant
        sleep 30
    fi

    if command -v kubectl &> /dev/null; then
        kubectl delete pods -n cortex-mcp -l app=qdrant
        kubectl wait --for=condition=Ready pods -n cortex-mcp -l app=qdrant --timeout=300s
    fi

    # Test if service starts
    if curl -f -s http://localhost:6333/health > /dev/null; then
        echo "✅ Service started successfully"

        # Attempt to restore collection
        echo "Restoring collection..."
        curl -X PUT http://localhost:6333/collections/cortex-memory \
            -H "Content-Type: application/json" \
            -d '{
                "vectors": {
                    "size": 1536,
                    "distance": "Cosine"
                }
            }' 2>/dev/null || echo "Collection restoration failed - will retry later"

        echo "✅ PARTIAL RECOVERY: Service is running, data restoration may be needed"
        echo "Recovery time: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "❌ All recovery attempts failed"
        echo "Escalating to disaster recovery procedures"
    fi
fi

echo "Emergency recovery procedures completed"
```

## Detailed Troubleshooting (Minutes 5-15)

### 1. Log Analysis (5 minutes)

```bash
#!/bin/bash
# scripts/analyze-qdrant-logs.sh

set -euo pipefail

echo "📋 QDRANT LOG ANALYSIS"
echo "====================="

LOG_DIR=${LOG_DIR:-"/qdrant/logs"}

# Docker logs
if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    echo "🐳 Docker Container Logs:"
    echo "========================"

    echo "Last 50 lines:"
    docker logs --tail 50 qdrant

    echo ""
    echo "Error patterns:"
    docker logs qdrant 2>&1 | grep -i error | tail -10

    echo ""
    echo "Warning patterns:"
    docker logs qdrant 2>&1 | grep -i warning | tail -10

    echo ""
    echo "Crash patterns:"
    docker logs qdrant 2>&1 | grep -i -E "(panic|fatal|crashed|killed)" | tail -5
fi

# Kubernetes logs
if command -v kubectl &> /dev/null; then
    echo "☸️ Kubernetes Pod Logs:"
    echo "======================"

    POD_NAME=$(kubectl get pods -n cortex-mcp -l app=qdrant -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -n "$POD_NAME" ]; then
        echo "Pod: $POD_NAME"
        echo ""
        echo "Last 50 lines:"
        kubectl logs -n cortex-mcp $POD_NAME --tail=50

        echo ""
        echo "Previous container logs (if restarted):"
        kubectl logs -n cortex-mcp $POD_NAME --previous --tail=50 2>/dev/null || echo "No previous logs"

        echo ""
        echo "Events:"
        kubectl describe pod -n cortex-mcp $POD_NAME | grep -A 20 "Events:"
    fi
fi

# System logs
echo ""
echo "🖥️ System Logs:"
echo "==============="

# Check systemd service
if systemctl is-active --quiet qdrant 2>/dev/null; then
    echo "Qdrant systemd service logs:"
    journalctl -u qdrant --since "1 hour ago" --no-pager -n 50
fi

# Check for OOM kills
echo ""
echo "Out of Memory events:"
dmesg | grep -i "killed process" | tail -5 || echo "No OOM events found"

# Disk space issues
echo ""
echo "Disk space alerts:"
grep -i "no space left" /var/log/syslog 2>/dev/null | tail -5 || echo "No disk space issues in logs"
```

### 2. Resource Analysis (3 minutes)

```bash
#!/bin/bash
# scripts/analyze-qdrant-resources.sh

set -euo pipefail

echo "💻 QDRANT RESOURCE ANALYSIS"
echo "=========================="

# Memory analysis
echo "🧠 Memory Analysis:"
echo "=================="
echo "System memory:"
free -h

echo ""
echo "Qdrant memory usage:"
if command -v docker &> /dev/null; then
    docker stats qdrant --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
fi

if command -v kubectl &> /dev/null; then
    kubectl top pods -n cortex-mcp -l app=qdrant 2>/dev/null || echo "No metrics available"
fi

# Check for memory leaks
echo ""
echo "Memory trend (last hour):"
if [ -f "/proc/meminfo" ]; then
    echo "Available memory: $(grep MemAvailable /proc/meminfo | awk '{print $2/1024}') MB"
fi

# Disk analysis
echo ""
echo "💾 Disk Analysis:"
echo "================="
echo "Disk usage:"
df -h

echo ""
echo "Qdrant storage size:"
if [ -d "/qdrant/storage" ]; then
    du -sh /qdrant/storage
    echo "Storage contents:"
    ls -la /qdrant/storage/ | head -10
fi

echo ""
echo "I/O statistics:"
iostat -x 1 1 2>/dev/null || echo "iostat not available"

# Network analysis
echo ""
echo "🌐 Network Analysis:"
echo "==================="
echo "Network connections:"
netstat -an | grep :6333

echo ""
echo "Network errors:"
cat /proc/net/netstat | grep -E "(ListenDrops|ListenErrors|TCPSynRetrans)" || echo "No network errors detected"

# Process analysis
echo ""
echo "🔍 Process Analysis:"
echo "===================="
echo "Qdrant process:"
ps aux | grep qdrant | grep -v grep

echo ""
echo "File descriptors:"
if command -v docker &> /dev/null; then
    docker exec qdrant ls /proc/self/fd | wc -l | xargs echo "Open file descriptors:"
fi

# Check for common resource issues
echo ""
echo "🐛 Resource Issue Detection:"
echo "============================"

# Check memory pressure
MEMORY_AVAILABLE=$(free -m | awk 'NR==2{print $7}')
if [ "$MEMORY_AVAILABLE" -lt 512 ]; then
    echo "⚠️ CRITICAL: Low memory available (${MEMORY_AVAILABLE}MB)"
fi

# Check disk space
DISK_AVAILABLE=$(df . | tail -1 | awk '{print $4}')
if [ "$DISK_AVAILABLE" -lt 1048576 ]; then  # 1GB in KB
    echo "⚠️ CRITICAL: Low disk space (${DISK_AVAILABLE}KB available)"
fi

# Check file descriptor limits
if command -v docker &> /dev/null; then
    FD_LIMIT=$(docker exec qdrant cat /proc/self/limits | grep "Max open files" | awk '{print $5}')
    FD_USED=$(docker exec qdrant ls /proc/self/fd | wc -l)
    if [ "$FD_USED" -gt $((FD_LIMIT * 80 / 100)) ]; then
        echo "⚠️ WARNING: High file descriptor usage ($FD_USED/$FD_LIMIT)"
    fi
fi
```

### 3. Configuration Analysis (2 minutes)

```bash
#!/bin/bash
# scripts/analyze-qdrant-config.sh

set -euo pipefail

echo "⚙️ QDRANT CONFIGURATION ANALYSIS"
echo "=============================="

# Check configuration files
echo "📄 Configuration Files:"
echo "======================"

if [ -f "/qdrant/config/config.yaml" ]; then
    echo "Main configuration file exists"
    echo "Configuration validation:"

    # Validate YAML syntax
    if yq eval '.' /qdrant/config/config.yaml > /dev/null 2>&1; then
        echo "✅ YAML syntax is valid"
    else
        echo "❌ YAML syntax is invalid"
        yq eval '.' /qdrant/config/config.yaml 2>&1 | head -5
    fi

    echo ""
    echo "Key configuration settings:"
    yq eval '.storage' /qdrant/config/config.yaml 2>/dev/null || echo "Storage config not found"
    yq eval '.service' /qdrant/config/config.yaml 2>/dev/null || echo "Service config not found"
    yq eval '.cluster' /qdrant/config/config.yaml 2>/dev/null || echo "Cluster config not found"
else
    echo "❌ Main configuration file not found"
fi

# Check environment variables
echo ""
echo "🌍 Environment Variables:"
echo "========================="
env | grep QDRANT | sort

# Check Docker configuration
if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    echo ""
    echo "🐳 Docker Configuration:"
    echo "======================"

    echo "Container inspection:"
    docker inspect qdrant | jq '.[0].Config.Env[]' 2>/dev/null | grep QDRANT || echo "No Qdrant environment variables"

    echo ""
    echo "Resource limits:"
    docker inspect qdrant | jq '.[0].HostConfig.Resources' 2>/dev/null || echo "No resource limits configured"

    echo ""
    echo "Port mappings:"
    docker inspect qdrant | jq '.[0].NetworkSettings.Ports' 2>/dev/null || echo "No port mappings"
fi

# Check Kubernetes configuration
if command -v kubectl &> /dev/null; then
    echo ""
    echo "☸️ Kubernetes Configuration:"
    echo "=========================="

    DEPLOYMENT_NAME=$(kubectl get deployments -n cortex-mcp -l app=qdrant -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -n "$DEPLOYMENT_NAME" ]; then
        echo "Deployment: $DEPLOYMENT_NAME"
        echo ""
        echo "Resource requests/limits:"
        kubectl describe deployment $DEPLOYMENT_NAME -n cortex-mcp | grep -A 10 "Requests:" || echo "No resource requests configured"

        echo ""
        echo "Environment variables:"
        kubectl describe deployment $DEPLOYMENT_NAME -n cortex-mcp | grep -A 20 "Environment:" || echo "No environment variables"

        echo ""
        echo "Volume mounts:"
        kubectl describe deployment $DEPLOYMENT_NAME -n cortex-mcp | grep -A 10 "Mounts:" || echo "No volume mounts"
    fi
fi

# Check for common configuration issues
echo ""
echo "🐛 Configuration Issue Detection:"
echo "================================"

# Check for conflicting ports
if netstat -tlnp | grep :6333 | grep -v qdrant > /dev/null; then
    echo "⚠️ WARNING: Port 6333 conflict detected"
    netstat -tlnp | grep :6333
fi

# Check storage permissions
if [ -d "/qdrant/storage" ]; then
    STORAGE_PERMS=$(stat -c "%a:%U:%G" /qdrant/storage)
    echo "Storage permissions: $STORAGE_PERMS"

    # Check if writable
    if ! touch /qdrant/storage/.test_write 2>/dev/null; then
        echo "❌ ERROR: Storage directory is not writable"
    else
        rm -f /qdrant/storage/.test_write
        echo "✅ Storage directory is writable"
    fi
fi

# Check memory configuration
MEMORY_LIMIT=$(env | grep QDRANT__MEMORY_LIMIT | cut -d= -f2)
if [ -n "$MEMORY_LIMIT" ]; then
    echo "Memory limit configured: $MEMORY_LIMIT"

    # Check if it's reasonable
    AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $2}')
    if [ "$MEMORY_LIMIT" -gt "$AVAILABLE_MEMORY" ]; then
        echo "⚠️ WARNING: Memory limit exceeds available system memory"
    fi
fi
```

## Escalation Procedures (Minutes 15-30)

### 1. Data Recovery from Backup (10 minutes)

```bash
#!/bin/bash
# scripts/recover-qdrant-from-backup.sh

set -euo pipefail

BACKUP_DATE=${1:-"latest"}
BACKUP_DIR=${BACKUP_DIR:-"/backups/qdrant"}

echo "📦 QDRANT DATA RECOVERY FROM BACKUP"
echo "=================================="

if [ "$BACKUP_DATE" = "latest" ]; then
    BACKUP_FILE=$(ls -t $BACKUP_DIR/*.snapshot.gz | head -1)
else
    BACKUP_FILE="$BACKUP_DIR/cortex_backup_${BACKUP_DATE}.snapshot.gz"
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    echo "Available backups:"
    ls -la $BACKUP_DIR/*.snapshot.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

echo "Using backup: $BACKUP_FILE"

# Stop Qdrant service
echo ""
echo "🛑 Stopping Qdrant service..."
if command -v docker &> /dev/null; then
    docker stop qdrant
fi

if command -v kubectl &> /dev/null; then
    kubectl scale deployment qdrant --replicas=0 -n cortex-mcp
fi

# Backup current storage (in case recovery fails)
echo ""
echo "📋 Backing up current storage..."
CURRENT_BACKUP="/tmp/qdrant_storage_backup_$(date +%Y%m%d_%H%M%S)"
if [ -d "/qdrant/storage" ]; then
    mv /qdrant/storage "$CURRENT_BACKUP"
    echo "Current storage backed up to: $CURRENT_BACKUP"
fi

# Create fresh storage directory
mkdir -p /qdrant/storage

# Start Qdrant service
echo ""
echo "🚀 Starting Qdrant service..."
if command -v docker &> /dev/null; then
    docker start qdrant
    sleep 30
fi

if command -v kubectl &> /dev/null; then
    kubectl scale deployment qdrant --replicas=1 -n cortex-mcp
    kubectl wait --for=condition=Ready pods -n cortex-mcp -l app=qdrant --timeout=300s
fi

# Create collection
echo ""
echo "📂 Creating collection..."
curl -X PUT http://localhost:6333/collections/cortex-memory \
    -H "Content-Type: application/json" \
    -d '{
        "vectors": {
            "size": 1536,
            "distance": "Cosine"
        }
    }'

# Restore from backup
echo ""
echo "🔄 Restoring from backup..."

# Extract backup to snapshot directory
SNAPSHOT_NAME="restore_$(date +%Y%m%d_%H%M%S)"
mkdir -p /qdrant/snapshots/cortex-memory

gunzip -c "$BACKUP_FILE" > "/qdrant/snapshots/cortex-memory/${SNAPSHOT_NAME}.snapshot"

# Restore collection from snapshot
RESTORE_RESPONSE=$(curl -s -X POST "http://localhost:6333/collections/cortex-memory/snapshots/restore" \
    -H "Content-Type: application/json" \
    -d "{\"snapshot_name\": \"${SNAPSHOT_NAME}.snapshot\"}")

echo "Restore response: $RESTORE_RESPONSE"

# Wait for restore completion
sleep 30

# Verify restoration
echo ""
echo "✅ Verifying restoration..."
VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.points_count // 0')

if [ "$VECTOR_COUNT" -gt 0 ]; then
    echo "✅ SUCCESS: $VECTOR_COUNT vectors restored"

    # Test functionality
    echo "Testing memory operations..."
    TEST_RESPONSE=$(curl -s -X POST http://localhost:3000/api/memory/find \
        -H "Content-Type: application/json" \
        -d '{"query":"test","limit":5}')

    if echo "$TEST_RESPONSE" | jq -e '.items' > /dev/null; then
        echo "✅ Memory operations working correctly"
    else
        echo "⚠️ Memory operations need verification"
    fi

    echo ""
    echo "🎉 Data recovery completed successfully"
    echo "Recovered $VECTOR_COUNT vectors from backup"
    echo "Backup used: $BACKUP_FILE"

else
    echo "❌ RESTORATION FAILED: No vectors found after restore"
    echo "Attempting rollback..."

    # Stop service and restore previous storage
    if command -v docker &> /dev/null; then
        docker stop qdrant
    fi

    if [ -d "$CURRENT_BACKUP" ]; then
        rm -rf /qdrant/storage
        mv "$CURRENT_BACKUP" /qdrant/storage
        echo "Previous storage restored"
    fi

    echo "Manual investigation required"
    exit 1
fi
```

### 2. Full System Reset (5 minutes)

```bash
#!/bin/bash
# scripts/qdrant-full-reset.sh

set -euo pipefail

echo "🔄 QDRANT FULL SYSTEM RESET"
echo "=========================="

# Warning confirmation
echo "⚠️ WARNING: This will completely reset Qdrant and all data will be lost!"
echo "   Only proceed if all other recovery methods have failed"
echo ""
read -p "Type 'RESET' to confirm full system reset: " confirm

if [ "$confirm" != "RESET" ]; then
    echo "Reset cancelled"
    exit 0
fi

# Stop all services
echo ""
echo "🛑 Stopping all services..."
if command -v docker &> /dev/null; then
    docker stop qdrant
fi

if command -v kubectl &> /dev/null; then
    kubectl scale deployment qdrant --replicas=0 -n cortex-mcp
fi

# Backup current state
echo ""
echo "📦 Backing up current state..."
BACKUP_DIR="/tmp/qdrant_reset_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -d "/qdrant/storage" ]; then
    mv /qdrant/storage "$BACKUP_DIR/"
    echo "Storage backed up to: $BACKUP_DIR/storage"
fi

if [ -d "/qdrant/logs" ]; then
    cp -r /qdrant/logs "$BACKUP_DIR/"
    echo "Logs backed up to: $BACKUP_DIR/logs"
fi

# Clean up all Qdrant data
echo ""
echo "🧹 Cleaning up Qdrant data..."
rm -rf /qdrant/*
mkdir -p /qdrant/storage
mkdir -p /qdrant/logs

# Start with fresh configuration
echo ""
echo "🚀 Starting with fresh configuration..."
if command -v docker &> /dev/null; then
    docker start qdrant
    sleep 30
fi

if command -v kubectl &> /dev/null; then
    kubectl scale deployment qdrant --replicas=1 -n cortex-mcp
    kubectl wait --for=condition=Ready pods -n cortex-mcp -l app=qdrant --timeout=300s
fi

# Initialize new collection
echo ""
echo "📂 Initializing new collection..."
curl -X PUT http://localhost:6333/collections/cortex-memory \
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
        }
    }'

# Verify new system
echo ""
echo "✅ Verifying new system..."
if curl -f -s http://localhost:6333/health > /dev/null; then
    echo "✅ Qdrant service is healthy"

    VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.points_count // 0')
    echo "✅ Collection created successfully ($VECTOR_COUNT vectors)"

    # Test API integration
    if curl -f -s http://localhost:3000/health > /dev/null; then
        echo "✅ MCP API integration working"
    else
        echo "⚠️ MCP API needs verification"
    fi

    echo ""
    echo "🎉 Full system reset completed successfully"
    echo "Previous state backed up to: $BACKUP_DIR"
    echo "System is now running with fresh data"

else
    echo "❌ Reset failed - service not starting"
    echo "Restoring from backup..."

    if command -v docker &> /dev/null; then
        docker stop qdrant
    fi

    if [ -d "$BACKUP_DIR/storage" ]; then
        mv "$BACKUP_DIR/storage" /qdrant/
        echo "Previous storage restored"
    fi

    echo "Manual intervention required"
    exit 1
fi
```

## Post-Incident Procedures

### 1. Incident Documentation (10 minutes)

```bash
#!/bin/bash
# scripts/document-qdrant-incident.sh

set -euo pipefail

INCIDENT_ID=${1:-"QDRANT-$(date +%Y%m%d%H%M%S)"}
SEVERITY=${2:-"critical"}

echo "📋 INCIDENT DOCUMENTATION"
echo "========================"
echo "Incident ID: $INCIDENT_ID"
echo "Severity: $SEVERITY"
echo "Documentation Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Create incident report
REPORT_FILE="/tmp/incident_report_${INCIDENT_ID}.md"

cat > $REPORT_FILE << EOF
# Qdrant Service Failure Incident Report

## Incident Summary
- **Incident ID**: $INCIDENT_ID
- **Severity**: $SEVERITY
- **Start Time**: $(date '+%Y-%m-%d %H:%M:%S')
- **Duration**: [TO BE FILLED]
- **Status**: Resolved

## Impact
- **Service Availability**: Complete outage
- **User Impact**: Users could not store or retrieve memories
- **Business Impact**: High - core functionality unavailable
- **Affected Systems**: Cortex Memory MCP Server

## Timeline
EOF

# Add timeline (this would be populated during the incident)
cat >> $REPORT_FILE << EOF
- **$(date '+%Y-%m-%d %H:%M:%S')**: Incident detected - Qdrant service unresponsive
- **$(date '+%Y-%m-%d %H:%M:%S')**: Emergency response team notified
- **$(date '+%Y-%m-%d %H:%M:%S')**: Initial diagnosis started
- **[TO BE FILLED]**: Recovery actions taken
- **[TO BE FILLED]**: Service restored
- **[TO BE FILLED]**: Post-incident verification completed

## Root Cause Analysis
EOF

# Add root cause findings
cat >> $REPORT_FILE << EOF
### Primary Cause
[TO BE FILLED - Identify the main cause of the failure]

### Contributing Factors
[TO BE FILLED - List any contributing factors]

### Detection Methods
- Health check failures
- API error monitoring
- Log analysis
- System resource monitoring

## Resolution Actions
EOF

# Add resolution steps
cat >> $REPORT_FILE << EOF
### Immediate Actions (First 5 minutes)
1. Incident assessment and diagnosis
2. Emergency notification
3. Service recovery attempts

### Detailed Troubleshooting (Minutes 5-15)
1. Log analysis
2. Resource analysis
3. Configuration analysis

### Recovery Procedures (Minutes 15-30)
[TO BE FILLED - Specific recovery steps taken]

## Post-Incident Actions
EOF

# Add post-incident follow-up
cat >> $REPORT_FILE << EOF
### Immediate Follow-up (Next 24 hours)
- [ ] Monitor system stability
- [ ] Verify all functionality
- [ ] Check for data loss or corruption
- [ ] Review monitoring alerts

### Short-term Improvements (Next week)
- [ ] Update monitoring thresholds
- [ ] Improve alerting sensitivity
- [ ] Document lessons learned
- [ ] Update runbooks

### Long-term Improvements (Next month)
- [ ] Implement high availability for Qdrant
- [ ] Add automated failover procedures
- [ ] Improve backup and recovery processes
- [ ] Conduct incident post-mortem

## Lessons Learned
EOF

# Add lessons learned
cat >> $REPORT_FILE << EOF
### What Went Well
- [TO BE FILLED]
- [TO BE FILLED]

### What Could Be Improved
- [TO BE FILLED]
- [TO BE FILLED]

### Action Items
- [TO BE FILLED]
- [TO BE FILLED]

## Technical Details
EOF

# Add technical details
cat >> $REPORT_FILE << EOF
### System Information
- **Qdrant Version**: [TO BE FILLED]
- **System Configuration**: [TO BE FILLED]
- **Resource Allocation**: [TO BE FILLED]

### Error Messages
\`\`\`
[TO BE FILLED - Add relevant error messages]
\`\`\`

### Log Files Referenced
- [TO BE FILLED - List key log files]
- [TO BE FILLED - Add log file locations]

## Communication
EOF

# Add communication details
cat >> $REPORT_FILE << EOF
### Internal Notifications
- Engineering team: [Time sent]
- Management: [Time sent]
- Support team: [Time sent]

### External Communications
- Customer notification: [TO BE FILLED]
- Status page updates: [TO BE FILLED]

### Stakeholder Updates
- [TO BE FILLED]

---
**Report Generated**: $(date '+%Y-%m-%d %H:%M:%S')
**Report Author**: [TO BE FILLED]
**Review Status**: Pending Review
EOF

echo "Incident report created: $REPORT_FILE"
echo "Please complete the TO BE FILLED sections"

# Store incident in Cortex Memory if available
if curl -f -s http://localhost:3000/health > /dev/null; then
    echo ""
    echo "📝 Storing incident in Cortex Memory..."

    INCIDENT_SUMMARY="Qdrant service failure incident $INCIDENT_ID - Service outage resolved after recovery procedures. Root cause analysis pending. Impact: Complete service outage for approximately [DURATION]. Resolution: [BRIEF DESCRIPTION]."

    curl -s -X POST http://localhost:3000/api/memory/store \
        -H "Content-Type: application/json" \
        -d "{
            \"items\": [{
                \"kind\": \"incident\",
                \"content\": \"$INCIDENT_SUMMARY\",
                \"metadata\": {
                    \"incident_id\": \"$INCIDENT_ID\",
                    \"severity\": \"$SEVERITY\",
                    \"service\": \"qdrant\",
                    \"start_time\": \"$(date -Iseconds)\",
                    \"report_file\": \"$REPORT_FILE\"
                }
            }]
        }" > /dev/null

    echo "Incident stored in Cortex Memory"
fi

echo ""
echo "🎉 Incident documentation completed"
echo "Next steps:"
echo "1. Complete the incident report"
echo "2. Schedule post-mortem meeting"
echo "3. Implement identified improvements"
echo "4. Update monitoring and alerting"
```

### 2. Prevention Measures (5 minutes)

```bash
#!/bin/bash
# scripts/implement-qdrant-prevention.sh

set -euo pipefail

echo "🛡️ IMPLEMENTING PREVENTION MEASURES"
echo "=================================="

# Set up enhanced monitoring
echo ""
echo "📊 Setting up enhanced monitoring..."

# Create monitoring script
cat > /usr/local/bin/monitor-qdrant.sh << 'EOF'
#!/bin/bash
# Enhanced Qdrant monitoring script

QDRANT_URL="http://localhost:6333"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90

# Check Qdrant health
if ! curl -f -s "$QDRANT_URL/health" > /dev/null; then
    echo "CRITICAL: Qdrant service is down"
    # Send alert
    exit 1
fi

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
DISK_USAGE=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')

if (( $(echo "$CPU_USAGE > $ALERT_THRESHOLD_CPU" | bc -l) )); then
    echo "WARNING: High CPU usage: $CPU_USAGE%"
fi

if (( $(echo "$MEMORY_USAGE > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
    echo "WARNING: High memory usage: $MEMORY_USAGE%"
fi

if [ "$DISK_USAGE" -gt "$ALERT_THRESHOLD_DISK" ]; then
    echo "WARNING: High disk usage: $DISK_USAGE%"
fi

# Check Qdrant metrics
VECTOR_COUNT=$(curl -s "$QDRANT_URL/collections/cortex-memory" | jq -r '.result.points_count // 0')
echo "Current vector count: $VECTOR_COUNT"

echo "Qdrant monitoring check completed"
EOF

chmod +x /usr/local/bin/monitor-qdrant.sh

# Add to crontab for monitoring every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor-qdrant.sh >> /var/log/qdrant-monitor.log 2>&1") | crontab -

echo "✅ Enhanced monitoring installed"

# Set up log rotation
echo ""
echo "📋 Setting up log rotation..."
cat > /etc/logrotate.d/qdrant << EOF
/qdrant/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 qdrant qdrant
    postrotate
        # Send signal to Qdrant to reopen logs
        systemctl reload qdrant || true
    endscript
}
EOF

echo "✅ Log rotation configured"

# Set up automated backups
echo ""
echo "💾 Setting up automated backups..."
cat > /usr/local/bin/backup-qdrant.sh << 'EOF'
#!/bin/bash
# Automated Qdrant backup script

BACKUP_DIR="/backups/qdrant"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="auto_backup_$DATE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create snapshot
curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$BACKUP_NAME\"}"

# Wait for snapshot creation
sleep 10

# Copy and compress snapshot
SNAPSHOT_PATH="/qdrant/snapshots/cortex-memory/$BACKUP_NAME.snapshot"
if [ -f "$SNAPSHOT_PATH" ]; then
    cp "$SNAPSHOT_PATH" "$BACKUP_DIR/"
    gzip "$BACKUP_DIR/$BACKUP_NAME.snapshot"

    # Clean old backups (keep last 7 days)
    find "$BACKUP_DIR" -name "*.snapshot.gz" -mtime +7 -delete

    echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME.snapshot.gz"
else
    echo "Backup failed: snapshot not created"
    exit 1
fi
EOF

chmod +x /usr/local/bin/backup-qdrant.sh

# Add to crontab for daily backups at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-qdrant.sh >> /var/log/qdrant-backup.log 2>&1") | crontab -

echo "✅ Automated backups configured"

# Set up resource alerts
echo ""
echo "🚨 Setting up resource alerts..."
cat > /usr/local/bin/check-qdrant-resources.sh << 'EOF'
#!/bin/bash
# Resource monitoring and alerting script

ALERT_EMAIL="ops@yourcompany.com"
LOG_FILE="/var/log/qdrant-resource-alerts.log"

# Check disk space
DISK_USAGE=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
    ALERT_MSG="WARNING: Qdrant disk usage is ${DISK_USAGE}% on $(hostname)"
    echo "$ALERT_MSG" >> "$LOG_FILE"
    echo "$ALERT_MSG" | mail -s "Qdrant Disk Space Alert" "$ALERT_EMAIL"
fi

# Check memory
MEMORY_AVAILABLE=$(free -m | awk 'NR==2{print $7}')
if [ "$MEMORY_AVAILABLE" -lt 1024 ]; then
    ALERT_MSG="CRITICAL: Low memory available for Qdrant: ${MEMORY_AVAILABLE}MB on $(hostname)"
    echo "$ALERT_MSG" >> "$LOG_FILE"
    echo "$ALERT_MSG" | mail -s "Qdrant Memory Alert" "$ALERT_EMAIL"
fi

# Check service status
if ! curl -f -s http://localhost:6333/health > /dev/null; then
    ALERT_MSG="CRITICAL: Qdrant service is down on $(hostname)"
    echo "$ALERT_MSG" >> "$LOG_FILE"
    echo "$ALERT_MSG" | mail -s "Qdrant Service Down" "$ALERT_EMAIL"
fi
EOF

chmod +x /usr/local/bin/check-qdrant-resources.sh

# Add to crontab for resource checks every 10 minutes
(crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/check-qdrant-resources.sh") | crontab -

echo "✅ Resource alerts configured"

# Create health check endpoint
echo ""
echo "🔍 Setting up comprehensive health check..."
cat > /usr/local/bin/qdrant-health-check.sh << 'EOF'
#!/bin/bash
# Comprehensive Qdrant health check

QDRANT_URL="http://localhost:6333"
API_URL="http://localhost:3000"

# Check Qdrant service
QDRANT_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$QDRANT_URL/health")
if [ "$QDRANT_HEALTH" != "200" ]; then
    echo "QDRANT_UNHEALTHY: HTTP $QDRANT_HEALTH"
    exit 1
fi

# Check collection
COLLECTION_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$QDRANT_URL/collections/cortex-memory")
if [ "$COLLECTION_STATUS" != "200" ]; then
    echo "COLLECTION_UNHEALTHY: HTTP $COLLECTION_STATUS"
    exit 1
fi

# Check API integration
API_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health")
if [ "$API_HEALTH" != "200" ]; then
    echo "API_UNHEALTHY: HTTP $API_HEALTH"
    exit 1
fi

# Test memory operation
MEMORY_TEST=$(curl -s -X POST "$API_URL/api/memory/find" \
    -H "Content-Type: application/json" \
    -d '{"query":"test","limit":1}' | jq -r '.items // null')

if [ "$MEMORY_TEST" = "null" ]; then
    echo "MEMORY_OPERATIONS_UNHEALTHY"
    exit 1
fi

echo "ALL_SYSTEMS_HEALTHY"
exit 0
EOF

chmod +x /usr/local/bin/qdrant-health-check.sh

echo "✅ Comprehensive health check configured"

echo ""
echo "🎉 Prevention measures implemented successfully"
echo "Summary of changes:"
echo "1. Enhanced monitoring (every 5 minutes)"
echo "2. Automated log rotation"
echo "3. Daily automated backups"
echo "4. Resource usage alerts"
echo "5. Comprehensive health checks"
echo ""
echo "Monitoring logs: /var/log/qdrant-monitor.log"
echo "Backup logs: /var/log/qdrant-backup.log"
echo "Alert logs: /var/log/qdrant-resource-alerts.log"
echo ""
echo "Test the new monitoring:"
echo "  /usr/local/bin/monitor-qdrant.sh"
echo "  /usr/local/bin/qdrant-health-check.sh"
```

## Communication Templates

### Initial Incident Notification
```
🚨 INCIDENT ALERT: QDRANT SERVICE FAILURE 🚨

Incident ID: QDRANT-20241103-143000
Severity: CRITICAL
Start Time: [TIME]

Impact:
- Cortex Memory MCP service is DOWN
- Users cannot store or retrieve memories
- All search functionality is unavailable

Current Status:
- Qdrant vector database is not responding
- Emergency response team engaged
- Recovery procedures in progress

Estimated Recovery Time: 15-30 minutes

Next Update: [TIME + 10 minutes]
Status Page: [URL]
```

### Recovery Notification
```
✅ INCIDENT RESOLVED: QDRANT SERVICE RESTORED

Incident ID: QDRANT-20241103-143000
Severity: CRITICAL
Duration: [DURATION]

Resolution:
- Qdrant service has been restored
- All functionality is operational
- Data integrity verified

Impact:
- No data loss occurred
- Service is fully operational
- Normal performance restored

Root Cause:
[BRIEF DESCRIPTION]

Prevention Measures:
[SUMMARY OF ACTIONS TAKEN]

Thank you for your patience.
```

This comprehensive incident response runbook provides step-by-step procedures for handling Qdrant service failures, from initial detection through recovery and prevention. Each procedure includes specific commands, expected outputs, and clear success criteria.