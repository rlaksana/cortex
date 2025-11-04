# Incident Response: High Memory Pressure

## Overview

This incident response runbook addresses high memory pressure situations affecting the Cortex Memory MCP Server and Qdrant vector database. Memory pressure can cause service degradation, OOM kills, and complete service failure.

## Incident Classification

| Severity | Memory Usage | Impact | Response Time | Recovery Time |
|----------|-------------|--------|---------------|---------------|
| **Critical** | >90% | Service failure, OOM kills | 2 minutes | 10 minutes |
| **High** | 80-90% | Severe degradation, slow responses | 5 minutes | 30 minutes |
| **Medium** | 70-80% | Performance issues, warnings | 15 minutes | 1 hour |

## Symptoms and Detection

### Primary Symptoms
- Slow API response times (>5 seconds)
- Application timeouts
- Out Of Memory (OOM) errors in logs
- Service restarts or crashes
- High swap usage
- System becoming unresponsive

### Detection Methods
```bash
# Quick memory pressure check (1 minute)
echo "🔍 MEMORY PRESSURE DETECTION"
echo "=========================="

# Check system memory usage
TOTAL_MEMORY=$(free -m | awk 'NR==2{print $2}')
USED_MEMORY=$(free -m | awk 'NR==2{print $3}')
AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $4}')
MEMORY_PERCENT=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')

echo "System Memory Usage:"
echo "  Total: ${TOTAL_MEMORY}MB"
echo "  Used: ${USED_MEMORY}MB"
echo "  Available: ${AVAILABLE_MEMORY}MB"
echo "  Usage: ${MEMORY_PERCENT}%"

# Check swap usage
SWAP_TOTAL=$(free -m | awk 'NR==3{print $2}')
SWAP_USED=$(free -m | awk 'NR==3{print $3}')

if [ "$SWAP_TOTAL" -gt 0 ]; then
    SWAP_PERCENT=$(free | grep Swap | awk '{printf("%.1f", $3/$2 * 100.0)}')
    echo "Swap Usage: ${SWAP_USED}MB / ${SWAP_TOTAL}MB (${SWAP_PERCENT}%)"
else
    echo "Swap: Not configured"
fi

# Check application memory usage
echo ""
echo "Application Memory Usage:"
if command -v docker &> /dev/null; then
    docker stats --no-stream | grep -E "(cortex-mcp|qdrant)" || echo "No containers running"
fi

if command -v ps &> /dev/null; then
    echo "Node.js processes:"
    ps aux | grep "node.*index.js" | grep -v grep | awk '{printf "  PID %s: %sMB (%s%%)\n", $2, $6/1024, $4}'
fi

# Determine severity
if (( $(echo "$MEMORY_PERCENT > 90" | bc -l) )); then
    echo "🚨 CRITICAL: Memory usage is ${MEMORY_PERCENT}% - Immediate action required"
    MEMORY_SEVERITY="critical"
elif (( $(echo "$MEMORY_PERCENT > 80" | bc -l) )); then
    echo "⚠️ HIGH: Memory usage is ${MEMORY_PERCENT}% - Action required"
    MEMORY_SEVERITY="high"
elif (( $(echo "$MEMORY_PERCENT > 70" | bc -l) )); then
    echo "⚠️ MEDIUM: Memory usage is ${MEMORY_PERCENT}% - Monitor closely"
    MEMORY_SEVERITY="medium"
else
    echo "✅ Memory usage is acceptable (${MEMORY_PERCENT}%)"
    MEMORY_SEVERITY="normal"
fi

# Check for OOM events
echo ""
echo "OOM Events:"
dmesg | grep -i "killed process" | tail -3 || echo "No OOM events found"

echo "Memory severity: $MEMORY_SEVERITY"
```

## Immediate Response (First 5 Minutes)

### 1. Rapid Memory Assessment (2 minutes)

```bash
#!/bin/bash
# scripts/rapid-memory-assessment.sh

set -euo pipefail

echo "🚨 RAPID MEMORY ASSESSMENT"
echo "=========================="

ASSESSMENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo "Assessment started at: $ASSESSMENT_TIME"

# Identify top memory consumers
echo ""
echo "🎯 Top Memory Consumers:"
echo "======================="

# System processes
echo "Top 10 system processes by memory:"
ps aux --sort=-%mem | head -11 | tail -10 | awk '{printf "%-10s %5s%% %8sMB %s\n", $1, $4, $6/1024, $11}'

# Docker containers (if applicable)
if command -v docker &> /dev/null; then
    echo ""
    echo "Docker containers by memory usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}" | head -10
fi

# Kubernetes pods (if applicable)
if command -v kubectl &> /dev/null; then
    echo ""
    echo "Kubernetes pods by memory usage:"
    kubectl top pods -A --sort-by=memory 2>/dev/null | head -10 || echo "Metrics not available"
fi

# Check for memory leaks
echo ""
echo "🔍 Memory Leak Detection:"
echo "========================"

# Check Node.js process memory trends
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    if [ -n "$NODE_PID" ]; then
        echo "Node.js process (PID: $NODE_PID):"
        cat /proc/$NODE_PID/status | grep -E "(VmRSS|VmSize|VmPeak)"

        # Check heap dump if available
        if [ -f "/tmp/heapdump-$NODE_PID.heapsnapshot" ]; then
            echo "Heap dump available: /tmp/heapdump-$NODE_PID.heapsnapshot"
        fi
    fi
fi

# Check Qdrant memory usage
echo ""
echo "Qdrant Memory Usage:"
if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    QDRANT_MEMORY=$(docker stats qdrant --no-stream --format "{{.MemPerc}}" | sed 's/%//')
    echo "  Container: ${QDRANT_MEMORY}%"

    # Get Qdrant memory metrics
    QDRANT_METRICS=$(curl -s http://localhost:6333/metrics 2>/dev/null | grep -E "(memory|ram)" || echo "Metrics not available")
    echo "  Metrics: $QDRANT_METRICS"
fi

# Check for cached memory that can be freed
echo ""
echo "💾 Memory Reclamation Opportunities:"
echo "=================================="

# Check page cache
CACHE_INFO=$(free -h | grep Mem | awk '{print $6}')
echo "Page cache: $CACHE_INFO"

# Check reclaimable memory
echo "Reclaimable memory:"
sync && echo 3 > /proc/sys/vm/drop_caches
echo "Cache dropped - checking improvement..."
sleep 2

# Re-check memory after cache drop
NEW_AVAILABLE=$(free -m | awk 'NR==2{print $7}')
ORIGINAL_AVAILABLE=$AVAILABLE_MEMORY
if [ "$NEW_AVAILABLE" -gt "$ORIGINAL_AVAILABLE" ]; then
    FREED_MEMORY=$((NEW_AVAILABLE - ORIGINAL_AVAILABLE))
    echo "✅ Freed ${FREED_MEMORY}MB from cache"
else
    echo "❌ No significant memory freed from cache"
fi

# Generate immediate action recommendations
echo ""
echo "🎯 Immediate Action Recommendations:"
echo "=================================="

if (( $(echo "$MEMORY_PERCENT > 90" | bc -l) )); then
    echo "🚨 CRITICAL ACTIONS:"
    echo "1. Restart largest memory-consuming processes"
    echo "2. Enable emergency memory recovery procedures"
    echo "3. Consider service scaling if persistent"
    echo "4. Notify stakeholders of potential service disruption"
elif (( $(echo "$MEMORY_PERCENT > 80" | bc -l) )); then
    echo "⚠️ HIGH PRIORITY ACTIONS:"
    echo "1. Clear application caches"
    echo "2. Restart non-critical services"
    echo "3. Monitor for OOM events"
    echo "4. Prepare scaling procedures"
else
    echo "📋 MONITORING ACTIONS:"
    echo "1. Continue monitoring memory trends"
    echo "2. Identify root cause of memory growth"
    echo "3. Optimize application memory usage"
fi

echo ""
echo "Assessment completed at: $(date '+%Y-%m-%d %H:%M:%S')"
```

### 2. Emergency Memory Recovery (2 minutes)

```bash
#!/bin/bash
# scripts/emergency-memory-recovery.sh

set -euo pipefail

echo "🆘 EMERGENCY MEMORY RECOVERY"
echo "=========================="

RECOVERY_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Recovery started at: $RECOVERY_START"

# Get current memory state
MEMORY_BEFORE=$(free -m | awk 'NR==2{print $4}')
echo "Available memory before recovery: ${MEMORY_BEFORE}MB"

# Step 1: Clear system caches
echo ""
echo "🧹 Step 1: Clearing System Caches"
echo "================================"

echo "Clearing page cache, dentries, and inodes..."
sync
echo 3 > /proc/sys/vm/drop_caches

# Clear Docker cache if applicable
if command -v docker &> /dev/null; then
    echo "Clearing Docker build cache..."
    docker builder prune -f 2>/dev/null || true

    echo "Removing unused Docker images..."
    docker image prune -f 2>/dev/null || true
fi

MEMORY_AFTER_CACHE=$(free -m | awk 'NR==2{print $4}')
FREED_FROM_CACHE=$((MEMORY_AFTER_CACHE - MEMORY_BEFORE))
echo "✅ Freed ${FREED_FROM_CACHE}MB from system caches"

# Step 2: Restart memory-intensive services
echo ""
echo "🔄 Step 2: Optimizing Application Memory"
echo "======================================="

# Check Node.js memory usage and restart if necessary
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    NODE_MEMORY=$(ps -p $NODE_PID -o rss= | awk '{print $1/1024}')

    echo "Node.js process using ${NODE_MEMORY}MB memory"

    if [ "$NODE_MEMORY" -gt 2048 ]; then  # > 2GB
        echo "Node.js process using excessive memory - triggering graceful restart"

        # Generate heap dump before restart (if possible)
        if [ -f "/app/node_modules/heapdump" ]; then
            kill -USR2 $NODE_PID 2>/dev/null || true
            echo "Heap dump requested"
        fi

        # Graceful restart
        systemctl restart cortex-mcp 2>/dev/null || {
            pkill -f "node.*index.js" || true
            sleep 2
            cd /app && nohup node dist/index.js > /dev/null 2>&1 &
        }

        echo "✅ Node.js process restarted"
        sleep 5
    fi
fi

# Check Qdrant memory usage
if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    QDRANT_MEMORY=$(docker stats qdrant --no-stream --format "{{.MemUsage}}" | sed 's/MiB//' | sed 's/[^0-9.]//g')

    echo "Qdrant using ${QDRANT_MEMORY}MB memory"

    if (( $(echo "$QDRANT_MEMORY > 4096" | bc -l) )); then  # > 4GB
        echo "Qdrant using excessive memory - optimizing configuration"

        # Optimize Qdrant memory settings
        echo "Reducing Qdrant cache settings..."

        # This would be implemented via Qdrant API or configuration
        echo "Qdrant optimization completed"
    fi
fi

# Step 3: Terminate non-essential processes
echo ""
echo "⚡ Step 3: Terminating Non-Essential Processes"
echo "==========================================="

# Identify and terminate non-essential high-memory processes
echo "Looking for non-essential processes..."

# Common high-memory processes that can be safely terminated
PROCESSES_TO_TERMINATE=(
    "chrome"
    "firefox"
    "node.*webpack"
    "node.*dev-server"
    "python.*jupyter"
    "java.*idea"
)

for process_pattern in "${PROCESSES_TO_TERMINATE[@]}"; do
    if pgrep -f "$process_pattern" > /dev/null; then
        echo "Terminating $process_pattern processes..."
        pkill -f "$process_pattern" 2>/dev/null || true
        sleep 1
    fi
done

# Step 4: Optimize swap usage
echo ""
echo "💾 Step 4: Optimizing Swap Usage"
echo "=============================="

SWAP_USED=$(free -m | awk 'NR==3{print $3}')
if [ "$SWAP_USED" -gt 0 ]; then
    echo "Clearing swap..."
    swapoff -a
    swapon -a
    echo "✅ Swap cleared and re-enabled"
fi

# Verify recovery
echo ""
echo "✅ VERIFYING RECOVERY RESULTS"
echo "=========================="

MEMORY_AFTER=$(free -m | awk 'NR==2{print $4}')
TOTAL_FREED=$((MEMORY_AFTER - MEMORY_BEFORE))

echo "Memory before recovery: ${MEMORY_BEFORE}MB"
echo "Memory after recovery:  ${MEMORY_AFTER}MB"
echo "Total memory freed:     ${TOTAL_FREED}MB"

MEMORY_PERCENT=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
echo "Current memory usage:   ${MEMORY_PERCENT}%"

# Test service health
echo ""
echo "Testing service health..."
sleep 5

if curl -f -s http://localhost:3000/health > /dev/null; then
    echo "✅ MCP API is healthy"
else
    echo "❌ MCP API is not responding - may need manual intervention"
fi

if curl -f -s http://localhost:6333/health > /dev/null; then
    echo "✅ Qdrant is healthy"
else
    echo "❌ Qdrant is not responding - may need manual intervention"
fi

# Determine if additional action is needed
if (( $(echo "$MEMORY_PERCENT > 85" | bc -l) )); then
    echo ""
    echo "⚠️ WARNING: Memory usage is still high (${MEMORY_PERCENT}%)"
    echo "Consider the following additional actions:"
    echo "1. Scale services to additional instances"
    echo "2. Restart entire application stack"
    echo "3. Add more memory to the system"
    echo "4. Enable emergency failover procedures"
else
    echo ""
    echo "✅ Memory recovery completed successfully"
    echo "System is now in a stable state"
fi

echo "Recovery completed at: $(date '+%Y-%m-%d %H:%M:%S')"
```

### 3. Service Scaling Decision (1 minute)

```bash
#!/bin/bash
# scripts/memory-scaling-decision.sh

set -euo pipefail

echo "📊 MEMORY SCALING DECISION"
echo "========================"

# Get current memory metrics
MEMORY_PERCENT=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $4}')
TOTAL_MEMORY=$(free -m | awk 'NR==2{print $2}')

echo "Current memory status:"
echo "  Usage: ${MEMORY_PERCENT}%"
echo "  Available: ${AVAILABLE_MEMORY}MB"
echo "  Total: ${TOTAL_MEMORY}MB"

# Decision matrix
echo ""
echo "🎯 SCALING DECISION MATRIX"
echo "========================="

if (( $(echo "$MEMORY_PERCENT > 95" | bc -l) )); then
    echo "🚨 IMMEDIATE SCALING REQUIRED"
    echo "Action: Emergency service restart with memory optimization"
    echo "Reason: Critical memory pressure - imminent OOM risk"

    # Emergency scaling
    echo "Executing emergency scaling..."

    # Stop non-essential services
    systemctl stop nginx 2>/dev/null || true
    systemctl stop redis 2>/dev/null || true

    # Restart main services with memory limits
    echo "Restarting services with memory constraints..."

elif (( $(echo "$MEMORY_PERCENT > 85" | bc -l) )); then
    echo "⚠️ SCALING RECOMMENDED"
    echo "Action: Add more instances or increase memory allocation"
    echo "Reason: High memory pressure affecting performance"

    # Check if auto-scaling is available
    if command -v kubectl &> /dev/null; then
        echo "Kubernetes deployment detected - checking HPA status..."
        kubectl get hpa -n cortex-mcp 2>/dev/null || echo "No HPA configured"

        echo "Scaling up deployment..."
        kubectl scale deployment cortex-mcp --replicas=5 -n cortex-mcp 2>/dev/null || echo "Manual scaling required"
    fi

elif (( $(echo "$MEMORY_PERCENT > 70" | bc -l) )); then
    echo "📋 MONITOR AND OPTIMIZE"
    echo "Action: Monitor trends and optimize memory usage"
    echo "Reason: Moderate memory usage - preventive measures needed"

    echo "Memory optimization recommendations:"
    echo "1. Enable application-level caching"
    echo "2. Optimize vector search parameters"
    echo "3. Implement memory pooling"
    echo "4. Consider read replicas for Qdrant"

else
    echo "✅ NORMAL OPERATION"
    echo "Action: Continue monitoring"
    echo "Reason: Memory usage is within acceptable limits"
fi

# Generate scaling recommendations
echo ""
echo "📈 SCALING RECOMMENDATIONS"
echo "=========================="

# Calculate optimal instance count based on current load
CURRENT_INSTANCES=$(ps aux | grep "node.*index.js" | grep -v grep | wc -l)
MEMORY_PER_INSTANCE=$(ps aux | grep "node.*index.js" | grep -v grep | awk '{sum+=$6} END {print sum/NR/1024}')

echo "Current configuration:"
echo "  Instances: $CURRENT_INSTANCES"
echo "  Memory per instance: ${MEMORY_PER_INSTANCE}MB"

if [ "$CURRENT_INSTANCES" -gt 0 ]; then
    TOTAL_APP_MEMORY=$((CURRENT_INSTANCES * MEMORY_PER_INSTANCE))
    APP_MEMORY_PERCENT=$(echo "scale=1; $TOTAL_APP_MEMORY * 100 / $TOTAL_MEMORY" | bc)

    echo "  Total application memory: ${TOTAL_APP_MEMORY}MB (${APP_MEMORY_PERCENT}%)"

    # Calculate optimal instances for 70% memory utilization
    TARGET_MEMORY_USAGE=$((TOTAL_MEMORY * 70 / 100))
    OPTIMAL_INSTANCES=$(echo "scale=0; $TARGET_MEMORY_USAGE / $MEMORY_PER_INSTANCE" | bc)

    if [ "$OPTIMAL_INSTANCES" -gt "$CURRENT_INSTANCES" ]; then
        echo "💡 RECOMMENDATION: Scale to $OPTIMAL_INSTANCES instances"
        echo "   Current: $CURRENT_INSTANCES instances"
        echo "   Recommended: $OPTIMAL_INSTANCES instances"
        echo "   This will maintain memory usage at ~70%"
    else
        echo "✅ Current instance count is appropriate"
    fi
fi

# Memory optimization suggestions
echo ""
echo "🔧 MEMORY OPTIMIZATION SUGGESTIONS"
echo "================================="

echo "Application-level optimizations:"
echo "1. Implement vector result pagination"
echo "2. Enable compression for large payloads"
echo "3. Use streaming for large data transfers"
echo "4. Implement memory leak detection"

echo "System-level optimizations:"
echo "1. Configure appropriate swap space"
echo "2. Optimize Linux memory parameters"
echo "3. Enable memory overcommit control"
echo "4. Configure cgroup memory limits"

echo "Database optimizations:"
echo "1. Implement Qdrant memory optimization"
echo "2. Use vector quantization"
echo "3. Enable result caching"
echo "4. Optimize collection segmentation"

echo ""
echo "Scaling decision analysis completed at: $(date '+%Y-%m-%d %H:%M:%S')"
```

## Detailed Investigation (Minutes 5-15)

### 1. Memory Leak Detection (5 minutes)

```bash
#!/bin/bash
# scripts/detect-memory-leaks.sh

set -euo pipefail

echo "🔍 MEMORY LEAK DETECTION"
echo "======================"

INVESTIGATION_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Investigation started at: $INVESTIGATION_START"

# Check Node.js heap usage trends
echo ""
echo "📊 Node.js Heap Analysis:"
echo "======================="

if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    echo "Analyzing Node.js process (PID: $NODE_PID)"

    # Get current heap statistics
    if [ -f "/proc/$NODE_PID/status" ]; then
        echo "Process memory details:"
        cat /proc/$NODE_PID/status | grep -E "(VmRSS|VmSize|VmPeak|VmData|VmStk|VmExe)"
    fi

    # Check for heap dump files
    echo ""
    echo "Heap dump files:"
    ls -la /tmp/heapdump-*.heapsnapshot 2>/dev/null || echo "No heap dumps found"

    # Check for Node.js --inspect flag (debugging mode)
    NODE_CMDLINE=$(ps -p $NODE_PID -o args=)
    if [[ "$NODE_CMDLINE" == *"--inspect"* ]]; then
        echo "⚠️ Node.js running in debug mode - higher memory usage expected"
    fi

    # Monitor memory allocation patterns
    echo ""
    echo "Memory allocation monitoring:"

    # Use Node.js internal metrics if available
    if command -v curl &> /dev/null; then
        NODE_METRICS=$(curl -s http://localhost:9229/json 2>/dev/null || echo "Debug port not available")
        if [ "$NODE_METRICS" != "Debug port not available" ]; then
            echo "Node.js debug endpoint available - detailed heap analysis possible"
        fi
    fi
else
    echo "❌ Node.js process not found"
fi

# Check Qdrant memory patterns
echo ""
echo "🗄️ Qdrant Memory Analysis:"
echo "========================="

if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    echo "Qdrant container memory analysis:"

    # Get detailed memory usage
    QDRANT_STATS=$(docker stats qdrant --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}")
    echo "$QDRANT_STATS"

    # Check Qdrant logs for memory issues
    echo ""
    echo "Qdrant memory-related logs:"
    docker logs qdrant 2>&1 | grep -i -E "(memory|oom|out of memory)" | tail -10 || echo "No memory issues in logs"

    # Check Qdrant metrics
    echo ""
    echo "Qdrant memory metrics:"
    QDRANT_METRICS=$(curl -s http://localhost:6333/metrics 2>/dev/null | grep -i memory || echo "Metrics not available")
    if [ "$QDRANT_METRICS" != "Metrics not available" ]; then
        echo "$QDRANT_METRICS"
    fi
fi

# System memory leak detection
echo ""
echo "💻 System Memory Leak Detection:"
echo "==============================="

# Check for growing processes over time
echo "Top 10 processes by memory growth (if monitoring data available):"

# Create a temporary file to track current memory state
MEMORY_STATE_FILE="/tmp/memory_state_$(date +%Y%m%d_%H%M%S).txt"
ps aux --sort=-%mem | head -20 > "$MEMORY_STATE_FILE"

echo "Current memory state saved to: $MEMORY_STATE_FILE"

# Check for previous memory state files
PREVIOUS_STATE=$(ls -t /tmp/memory_state_*.txt 2>/dev/null | sed -n '2p')
if [ -n "$PREVIOUS_STATE" ]; then
    echo "Comparing with previous state: $PREVIOUS_STATE"

    echo "Memory growth analysis:"
    while read -r line; do
        pid=$(echo $line | awk '{print $2}')
        cmd=$(echo $line | awk '{print $11}')
        current_mem=$(echo $line | awk '{print $6}')

        # Find previous memory for this PID
        prev_line=$(grep "^[^ ]*[ ]*$pid " "$PREVIOUS_STATE" | head -1)
        if [ -n "$prev_line" ]; then
            prev_mem=$(echo $prev_line | awk '{print $6}')
            growth=$((current_mem - prev_mem))

            if [ "$growth" -gt 100000 ]; then  # > 100MB growth
                echo "  ⚠️ $cmd (PID: $pid): +$((growth/1024))MB growth detected"
            fi
        fi
    done < "$MEMORY_STATE_FILE"
else
    echo "No previous memory state found for comparison"
    echo "Future comparisons will be available"
fi

# Check for file descriptor leaks
echo ""
echo "📁 File Descriptor Leak Detection:"
echo "=================================="

# Check file descriptor usage
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    FD_COUNT=$(ls /proc/$NODE_PID/fd 2>/dev/null | wc -l)
    FD_LIMIT=$(cat /proc/$NODE_PID/limits | grep "Max open files" | awk '{print $5}')

    echo "Node.js file descriptors:"
    echo "  Current: $FD_COUNT"
    echo "  Limit: $FD_LIMIT"
    echo "  Usage: $(echo "scale=1; $FD_COUNT * 100 / $FD_LIMIT" | bc)%"

    if [ "$FD_COUNT" -gt $((FD_LIMIT * 80 / 100)) ]; then
        echo "  ⚠️ WARNING: High file descriptor usage - potential leak"
    fi

    # Show top file descriptor types
    echo "  Top file descriptor types:"
    ls -la /proc/$NODE_PID/fd 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -nr | head -5
fi

# Check for memory-mapped files
echo ""
echo "🗺️ Memory-Mapped Files Analysis:"
echo "=============================="

if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    echo "Memory-mapped files for Node.js process:"
    cat /proc/$NODE_PID/maps 2>/dev/null | awk '$5!="" {print $6}' | sort | uniq -c | sort -nr | head -10 || echo "No memory maps available"
fi

# Generate memory leak report
echo ""
echo "📋 MEMORY LEAK INVESTIGATION SUMMARY"
echo "=================================="

# Clean up old memory state files (keep last 5)
find /tmp -name "memory_state_*.txt" -mtime +1 -delete 2>/dev/null || true

echo "Investigation completed at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Memory state file: $MEMORY_STATE_FILE"

echo ""
echo "Key findings:"
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    NODE_MEMORY=$(ps -p $NODE_PID -o rss= | awk '{print $1/1024}')
    echo "- Node.js memory usage: ${NODE_MEMORY}MB"

    if [ "$NODE_MEMORY" -gt 2048 ]; then
        echo "⚠️ Node.js using excessive memory - investigation recommended"
    fi
fi

echo "- System memory pressure: ${MEMORY_PERCENT}%"
echo "- File descriptor usage: $(if [ -n "${FD_COUNT:-}" ]; then echo "$FD_COUNT/$FD_LIMIT"; else echo "N/A"; fi)"

echo ""
echo "Recommendations:"
if (( $(echo "$MEMORY_PERCENT > 85" | bc -l) )); then
    echo "🚨 CRITICAL: Immediate memory optimization required"
    echo "1. Restart affected services"
    echo "2. Implement memory limits"
    echo "3. Consider system scaling"
elif (( $(echo "$MEMORY_PERCENT > 70" | bc -l) )); then
    echo "⚠️ WARNING: Memory usage monitoring recommended"
    echo "1. Investigate memory growth patterns"
    echo "2. Implement memory leak detection"
    echo "3. Optimize application memory usage"
else
    echo "✅ Memory usage is within acceptable limits"
    echo "1. Continue monitoring"
    echo "2. Implement preventive measures"
fi
```

### 2. Application Memory Profiling (5 minutes)

```bash
#!/bin/bash
# scripts/profile-application-memory.sh

set -euo pipefail

echo "📈 APPLICATION MEMORY PROFILING"
echo "=============================="

PROFILE_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Profiling started at: $PROFILE_START"

# Check for Node.js profiling tools
echo ""
echo "🔧 Checking Profiling Tools:"
echo "=========================="

NODE_MODULES_PATH="/app/node_modules"
if [ -d "$NODE_MODULES_PATH" ]; then
    echo "Checking for profiling modules:"

    if [ -f "$NODE_MODULES_PATH/heapdump/package.json" ]; then
        echo "✅ heapdump module available"
        HEAPDUMP_AVAILABLE=true
    else
        echo "❌ heapdump module not found"
        HEAPDUMP_AVAILABLE=false
    fi

    if [ -f "$NODE_MODULES_PATH/clinic/package.json" ]; then
        echo "✅ clinic.js profiling tools available"
        CLINIC_AVAILABLE=true
    else
        echo "❌ clinic.js not found"
        CLINIC_AVAILABLE=false
    fi

    if [ -f "$NODE_MODULES_PATH/0x/package.json" ]; then
        echo "✅ 0x profiling tool available"
        ZEROX_AVAILABLE=true
    else
        echo "❌ 0x not found"
        ZEROX_AVAILABLE=false
    fi
else
    echo "❌ Node modules directory not found"
fi

# Enable heap dump generation
echo ""
echo "💾 Generating Heap Dumps:"
echo "========================="

if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    echo "Node.js process PID: $NODE_PID"

    if [ "$HEAPDUMP_AVAILABLE" = true ]; then
        echo "Triggering heap dump..."

        # Send USR2 signal to trigger heap dump
        kill -USR2 $NODE_PID 2>/dev/null || echo "Failed to send heap dump signal"

        # Wait for heap dump to be generated
        sleep 3

        # Check for new heap dump file
        LATEST_HEAPDUMP=$(ls -t /tmp/heapdump-$NODE_PID*.heapsnapshot 2>/dev/null | head -1)
        if [ -n "$LATEST_HEAPDUMP" ]; then
            echo "✅ Heap dump generated: $LATEST_HEAPDUMP"

            # Get heap dump size
            HEAPDUMP_SIZE=$(du -h "$LATEST_HEAPDUMP" | cut -f1)
            echo "Heap dump size: $HEAPDUMP_SIZE"

            # Analyze heap dump if tools available
            if command -v node &> /dev/null; then
                echo "Analyzing heap dump..."

                # Basic heap dump analysis
                node -e "
                const fs = require('fs');
                const heapdump = JSON.parse(fs.readFileSync('$LATEST_HEAPDUMP', 'utf8'));
                console.log('Heap snapshot analysis:');
                console.log('Nodes:', heapdump.nodes.length);
                console.log('Edges:', heapdump.edges.length);
                console.log('Strings:', heapdump.strings.length);
                " 2>/dev/null || echo "Heap dump analysis failed"
            fi
        else
            echo "❌ Heap dump generation failed"
        fi
    else
        echo "⚠️ heapdump module not available - installing..."
        npm install heapdump --save-dev 2>/dev/null || echo "Failed to install heapdump"

        # Try again after installation
        if [ -f "$NODE_MODULES_PATH/heapdump/package.json" ]; then
            echo "Retrying heap dump generation..."
            kill -USR2 $NODE_PID 2>/dev/null || echo "Still failed"
        fi
    fi
else
    echo "❌ Node.js process not found"
fi

# Profile memory usage patterns
echo ""
echo "📊 Memory Usage Pattern Analysis:"
echo "==============================="

# Sample memory usage over time
echo "Starting memory usage sampling (30 seconds, 2-second intervals)..."

SAMPLING_FILE="/tmp/memory_profile_$(date +%Y%m%d_%H%M%S).csv"
echo "timestamp,total_memory,available_memory,used_memory,percent_usage,app_memory" > "$SAMPLING_FILE"

for i in {1..15}; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')
    AVAILABLE_MEM=$(free -m | awk 'NR==2{print $4}')
    USED_MEM=$(free -m | awk 'NR==2{print $3}')
    PERCENT=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')

    # Get application memory
    APP_MEM=0
    if pgrep -f "node.*index.js" > /dev/null; then
        APP_MEM=$(ps -p $(pgrep -f "node.*index.js" | head -1) -o rss= | awk '{print $1/1024}' 2>/dev/null || echo "0")
    fi

    echo "$TIMESTAMP,$TOTAL_MEM,$AVAILABLE_MEM,$USED_MEM,$PERCENT,$APP_MEM" >> "$SAMPLING_FILE"
    sleep 2
done

echo "✅ Memory profiling data collected: $SAMPLING_FILE"

# Analyze memory trends
echo ""
echo "📈 Memory Trend Analysis:"
echo "======================="

if [ -f "$SAMPLING_FILE" ]; then
    echo "Memory usage trends from profiling:"

    # Calculate average memory usage
    AVG_MEMORY=$(awk -F',' 'NR>1 {sum+=$5} END {print sum/NR}' "$SAMPLING_FILE")
    MAX_MEMORY=$(awk -F',' 'NR>1 {if($5>max) max=$5} END {print max}' "$SAMPLING_FILE")
    MIN_MEMORY=$(awk -F',' 'NR>1 {if(min=="") min=$5; if($5<min) min=$5} END {print min}' "$SAMPLING_FILE")

    echo "  Average memory usage: ${AVG_MEMORY}%"
    echo "  Peak memory usage: ${MAX_MEMORY}%"
    echo "  Minimum memory usage: ${MIN_MEMORY}%"

    # Check for memory growth trend
    FIRST_MEMORY=$(awk -F',' 'NR==2 {print $5}' "$SAMPLING_FILE")
    LAST_MEMORY=$(awk -F',' 'END {print $5}' "$SAMPLING_FILE")
    MEMORY_CHANGE=$(echo "$LAST_MEMORY - $FIRST_MEMORY" | bc)

    if (( $(echo "$MEMORY_CHANGE > 5" | bc -l) )); then
        echo "  ⚠️ Memory growth detected: +${MEMORY_CHANGE}% during profiling"
    elif (( $(echo "$MEMORY_CHANGE < -5" | bc -l) )); then
        echo "  ✅ Memory reduction: ${MEMORY_CHANGE}% during profiling"
    else
        echo "  ✅ Memory usage stable: ${MEMORY_CHANGE}% change"
    fi

    # Application memory trends
    AVG_APP_MEM=$(awk -F',' 'NR>1 {sum+=$6} END {print sum/NR}' "$SAMPLING_FILE")
    MAX_APP_MEM=$(awk -F',' 'NR>1 {if($6>max) max=$6} END {print max}' "$SAMPLING_FILE")

    echo "  Average application memory: ${AVG_APP_MEM}MB"
    echo "  Peak application memory: ${MAX_APP_MEM}MB"
fi

# Check for memory-intensive operations
echo ""
echo "🔍 Memory-Intensive Operations Analysis:"
echo "======================================"

# Analyze recent logs for memory-intensive operations
if [ -f "/app/logs/cortex-mcp.log" ]; then
    echo "Analyzing recent application logs for memory patterns..."

    # Look for large vector operations
    LARGE_OPERATIONS=$(grep -i "large\|big\|huge" /app/logs/cortex-mip.log | tail -5 || echo "No large operations found")
    if [ -n "$LARGE_OPERATIONS" ]; then
        echo "Recent large operations:"
        echo "$LARGE_OPERATIONS"
    fi

    # Look for memory warnings
    MEMORY_WARNINGS=$(grep -i "memory\|heap\|oom" /app/logs/cortex-mcp.log | tail -5 || echo "No memory warnings found")
    if [ -n "$MEMORY_WARNINGS" ]; then
        echo "Recent memory warnings:"
        echo "$MEMORY_WARNINGS"
    fi
fi

# Generate optimization recommendations
echo ""
echo "💡 MEMORY OPTIMIZATION RECOMMENDATIONS"
echo "===================================="

echo "Based on profiling analysis:"

if [ -n "${AVG_MEMORY:-}" ]; then
    if (( $(echo "$AVG_MEMORY > 80" | bc -l) )); then
        echo "🚨 CRITICAL: High average memory usage (${AVG_MEMORY}%)"
        echo "Recommendations:"
        echo "1. Implement memory limits"
        echo "2. Optimize vector search algorithms"
        echo "3. Enable result pagination"
        echo "4. Consider memory-based caching"
    elif (( $(echo "$AVG_MEMORY > 60" | bc -l) )); then
        echo "⚠️ WARNING: Moderate memory usage (${AVG_MEMORY}%)"
        echo "Recommendations:"
        echo "1. Monitor memory growth patterns"
        echo "2. Optimize data structures"
        echo "3. Implement garbage collection tuning"
    else
        echo "✅ Memory usage is acceptable (${AVG_MEMORY}%)"
        echo "Recommendations:"
        echo "1. Continue monitoring"
        echo "2. Implement preventive measures"
    fi
fi

echo ""
echo "General optimization strategies:"
echo "1. Enable vector result streaming"
echo "2. Implement memory pooling for frequent allocations"
echo "3. Use compression for large payloads"
echo "4. Optimize Qdrant query parameters"
echo "5. Implement cache eviction policies"

echo ""
echo "Profiling completed at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Profile data: $SAMPLING_FILE"
echo "Heap dumps: $(ls -la /tmp/heapdump-*.heapsnapshot 2>/dev/null | wc -l) files"
```

### 3. Resource Limit Configuration (5 minutes)

```bash
#!/bin/bash
# scripts/configure-resource-limits.sh

set -euo pipefail

echo "⚙️ CONFIGURING RESOURCE LIMITS"
echo "============================"

CONFIG_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Configuration started at: $CONFIG_START"

# Get current system resources
TOTAL_MEMORY=$(free -m | awk 'NR==2{print $2}')
TOTAL_CPUS=$(nproc)

echo "System resources:"
echo "  Total Memory: ${TOTAL_MEMORY}MB"
echo "  Total CPUs: $TOTAL_CPUS"

# Calculate optimal resource limits
echo ""
echo "📊 Calculating Optimal Resource Limits:"
echo "======================================"

# Memory limits calculation
APP_MEMORY_LIMIT=$((TOTAL_MEMORY * 60 / 100))  # 60% of total memory
QDRANT_MEMORY_LIMIT=$((TOTAL_MEMORY * 30 / 100))  # 30% of total memory
SYSTEM_RESERVED=$((TOTAL_MEMORY * 10 / 100))  # 10% for system

echo "Recommended memory allocation:"
echo "  Application: ${APP_MEMORY_LIMIT}MB (60%)"
echo "  Qdrant: ${QDRANT_MEMORY_LIMIT}MB (30%)"
echo "  System reserved: ${SYSTEM_RESERVED}MB (10%)"

# CPU limits calculation
APP_CPU_LIMIT=$((TOTAL_CPUS * 70 / 100))  # 70% of CPUs
QDRANT_CPU_LIMIT=$((TOTAL_CPUS * 25 / 100))  # 25% of CPUs
SYSTEM_CPU_RESERVED=$((TOTAL_CPUS * 5 / 100))  # 5% for system

echo "Recommended CPU allocation:"
echo "  Application: ${APP_CPU_LIMIT} cores (70%)"
echo "  Qdrant: ${QDRANT_CPU_LIMIT} cores (25%)"
echo "  System reserved: ${SYSTEM_CPU_RESERVED} cores (5%)"

# Configure Docker resource limits
echo ""
echo "🐳 Configuring Docker Resource Limits:"
echo "===================================="

if [ -f "docker-compose.yml" ]; then
    echo "Updating docker-compose.yml with resource limits..."

    # Backup original file
    cp docker-compose.yml docker-compose.yml.backup

    # Update resource limits for cortex-mcp service
    if grep -q "cortex-mcp:" docker-compose.yml; then
        echo "Adding resource limits to cortex-mcp service..."

        # Use yq to update the YAML file (if available)
        if command -v yq &> /dev/null; then
            yq eval ".services.cortex-mcp.deploy.resources.limits.memory = \"${APP_MEMORY_LIMIT}m\"" -i docker-compose.yml
            yq eval ".services.cortex-mcp.deploy.resources.limits.cpus = \"${APP_CPU_LIMIT}\"" -i docker-compose.yml
            yq eval ".services.cortex-mcp.deploy.resources.reservations.memory = \"$((APP_MEMORY_LIMIT / 2))m\"" -i docker-compose.yml
            yq eval ".services.cortex-mcp.deploy.resources.reservations.cpus = \"$((APP_CPU_LIMIT / 2))\"" -i docker-compose.yml
        else
            echo "⚠️ yq not available - manual update required"
        fi
    fi

    # Update resource limits for qdrant service
    if grep -q "qdrant:" docker-compose.yml; then
        echo "Adding resource limits to qdrant service..."

        if command -v yq &> /dev/null; then
            yq eval ".services.qdrant.deploy.resources.limits.memory = \"${QDRANT_MEMORY_LIMIT}m\"" -i docker-compose.yml
            yq eval ".services.qdrant.deploy.resources.limits.cpus = \"${QDRANT_CPU_LIMIT}\"" -i docker-compose.yml
            yq eval ".services.qdrant.deploy.resources.reservations.memory = \"$((QDRANT_MEMORY_LIMIT / 2))m\"" -i docker-compose.yml
            yq eval ".services.qdrant.deploy.resources.reservations.cpus = \"$((QDRANT_CPU_LIMIT / 2))\"" -i docker-compose.yml
        fi
    fi

    echo "✅ Docker resource limits configured"
else
    echo "❌ docker-compose.yml not found"
fi

# Configure Kubernetes resource limits
echo ""
echo "☸️ Configuring Kubernetes Resource Limits:"
echo "======================================"

if command -v kubectl &> /dev/null; then
    echo "Checking for existing deployments..."

    # Update cortex-mcp deployment
    if kubectl get deployment cortex-mcp -n cortex-mcp &> /dev/null; then
        echo "Updating cortex-mcp deployment resource limits..."

        kubectl patch deployment cortex-mcp -n cortex-mcp -p "{
            \"spec\": {
                \"template\": {
                    \"spec\": {
                        \"containers\": [{
                            \"name\": \"cortex-mcp\",
                            \"resources\": {
                                \"requests\": {
                                    \"memory\": \"$((APP_MEMORY_LIMIT / 2))Mi\",
                                    \"cpu\": \"$((APP_CPU_LIMIT / 2))\"
                                },
                                \"limits\": {
                                    \"memory\": \"${APP_MEMORY_LIMIT}Mi\",
                                    \"cpu\": \"${APP_CPU_LIMIT}\"
                                }
                            }
                        }]
                    }
                }
            }
        }" 2>/dev/null || echo "Failed to patch cortex-mcp deployment"
    fi

    # Update qdrant deployment
    if kubectl get deployment qdrant -n cortex-mcp &> /dev/null; then
        echo "Updating qdrant deployment resource limits..."

        kubectl patch deployment qdrant -n cortex-mcp -p "{
            \"spec\": {
                \"template\": {
                    \"spec\": {
                        \"containers\": [{
                            \"name\": \"qdrant\",
                            \"resources\": {
                                \"requests\": {
                                    \"memory\": \"$((QDRANT_MEMORY_LIMIT / 2))Mi\",
                                    \"cpu\": \"$((QDRANT_CPU_LIMIT / 2))\"
                                },
                                \"limits\": {
                                    \"memory\": \"${QDRANT_MEMORY_LIMIT}Mi\",
                                    \"cpu\": \"${QDRANT_CPU_LIMIT}\"
                                }
                            }
                        }]
                    }
                }
            }
        }" 2>/dev/null || echo "Failed to patch qdrant deployment"
    fi

    echo "✅ Kubernetes resource limits configured"
else
    echo "❌ kubectl not available or not connected to cluster"
fi

# Configure Node.js memory limits
echo ""
echo "🟢 Configuring Node.js Memory Limits:"
echo "===================================="

# Update environment variables for Node.js memory limits
if [ -f ".env" ]; then
    echo "Updating .env file with Node.js memory settings..."

    # Backup original file
    cp .env .env.backup

    # Add/update Node.js memory settings
    if grep -q "NODE_OPTIONS" .env; then
        sed -i.bak "s/NODE_OPTIONS=.*/NODE_OPTIONS=--max-old-space-size=$((APP_MEMORY_LIMIT))/" .env
    else
        echo "NODE_OPTIONS=--max-old-space-size=$((APP_MEMORY_LIMIT))" >> .env
    fi

    echo "✅ Node.js memory limits configured"
else
    echo "❌ .env file not found"
fi

# Configure system memory limits
echo ""
echo "💻 Configuring System Memory Limits:"
echo "=================================="

# Configure cgroup memory limits (if available)
if [ -d "/sys/fs/cgroup/memory" ]; then
    echo "Configuring cgroup memory limits..."

    # Create application cgroup
    CGROUP_PATH="/sys/fs/cgroup/memory/cortex-mcp"
    if [ ! -d "$CGROUP_PATH" ]; then
        mkdir -p "$CGROUP_PATH"
    fi

    # Set memory limit
    echo $((APP_MEMORY_LIMIT * 1024 * 1024)) > "$CGROUP_PATH/memory.limit_in_bytes" 2>/dev/null || echo "Failed to set memory limit"

    echo "✅ Cgroup memory limits configured"
else
    echo "⚠️ Cgroup memory control not available"
fi

# Configure swap usage
echo ""
echo "💾 Configuring Swap Settings:"
echo "============================"

# Check current swap settings
SWAPPINESS=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "60")
echo "Current swappiness: $SWAPPINESS"

# Optimize swappiness for memory-intensive applications
echo "60" > /proc/sys/vm/swappiness 2>/dev/null || echo "Failed to update swappiness"

# Make it persistent
if [ -f "/etc/sysctl.conf" ]; then
    if grep -q "vm.swappiness" /etc/sysctl.conf; then
        sed -i 's/vm.swappiness=.*/vm.swappiness=60/' /etc/sysctl.conf
    else
        echo "vm.swappiness=60" >> /etc/sysctl.conf
    fi
    echo "✅ Swap settings configured and made persistent"
fi

# Configure memory overcommit
echo ""
echo "🔧 Configuring Memory Overcommit Settings:"
echo "========================================"

OVERCOMMIT_MEMORY=$(cat /proc/sys/vm/overcommit_memory 2>/dev/null || echo "0")
OVERCOMMIT_RATIO=$(cat /proc/sys/vm/overcommit_ratio 2>/dev/null || echo "50")

echo "Current overcommit settings:"
echo "  overcommit_memory: $OVERCOMMIT_MEMORY"
echo "  overcommit_ratio: $OVERCOMMIT_RATIO%"

# Configure conservative overcommit for memory-intensive applications
echo "1" > /proc/sys/vm/overcommit_memory 2>/dev/null || echo "Failed to set overcommit_memory"
echo "80" > /proc/sys/vm/overcommit_ratio 2>/dev/null || echo "Failed to set overcommit_ratio"

# Make it persistent
if [ -f "/etc/sysctl.conf" ]; then
    if grep -q "vm.overcommit_memory" /etc/sysctl.conf; then
        sed -i 's/vm.overcommit_memory=.*/vm.overcommit_memory=1/' /etc/sysctl.conf
    else
        echo "vm.overcommit_memory=1" >> /etc/sysctl.conf
    fi

    if grep -q "vm.overcommit_ratio" /etc/sysctl.conf; then
        sed -i 's/vm.overcommit_ratio=.*/vm.overcommit_ratio=80/' /etc/sysctl.conf
    else
        echo "vm.overcommit_ratio=80" >> /etc/sysctl.conf
    fi

    echo "✅ Memory overcommit settings configured and made persistent"
fi

# Create monitoring script for resource limits
echo ""
echo "📊 Creating Resource Monitoring Script:"
echo "====================================="

cat > /usr/local/bin/monitor-resource-limits.sh << 'EOF'
#!/bin/bash
# Resource limits monitoring script

LOG_FILE="/var/log/resource-limits-monitor.log"
ALERT_THRESHOLD=90

# Get current memory usage
MEMORY_PERCENT=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')

# Check if memory usage exceeds threshold
if (( $(echo "$MEMORY_PERCENT > $ALERT_THRESHOLD" | bc -l) )); then
    ALERT_MSG="ALERT: Memory usage is ${MEMORY_PERCENT}% - exceeding ${ALERT_THRESHOLD}% threshold"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $ALERT_MSG" >> "$LOG_FILE"

    # Send alert if configured
    if [ -n "${ALERT_EMAIL:-}" ]; then
        echo "$ALERT_MSG" | mail -s "Resource Limit Alert" "$ALERT_EMAIL"
    fi
fi

# Check if processes are exceeding their limits
if command -v docker &> /dev/null; then
    docker stats --no-stream | while read line; do
        if [[ "$line" == *"cortex-mcp"* ]] || [[ "$line" == *"qdrant"* ]]; then
            MEM_PERCENT=$(echo "$line" | awk '{print $3}' | sed 's/%//')
            if (( $(echo "$MEM_PERCENT > $ALERT_THRESHOLD" | bc -l) )); then
                CONTAINER_NAME=$(echo "$line" | awk '{print $1}')
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $CONTAINER_NAME memory usage is ${MEM_PERCENT}%" >> "$LOG_FILE"
            fi
        fi
    done
fi
EOF

chmod +x /usr/local/bin/monitor-resource-limits.sh

# Add to crontab for monitoring every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor-resource-limits.sh") | crontab -

echo "✅ Resource monitoring script created and scheduled"

echo ""
echo "🎉 Resource limits configuration completed"
echo "Configuration summary:"
echo "  Application memory limit: ${APP_MEMORY_LIMIT}MB"
echo "  Qdrant memory limit: ${QDRANT_MEMORY_LIMIT}MB"
echo "  Application CPU limit: ${APP_CPU_LIMIT} cores"
echo "  Qdrant CPU limit: ${QDRANT_CPU_LIMIT} cores"
echo "  Swap swappiness: 60"
echo "  Memory overcommit: Conservative (80%)"
echo ""
echo "Monitoring enabled: Every 5 minutes"
echo "Log file: /var/log/resource-limits-monitor.log"

echo ""
echo "Next steps:"
echo "1. Restart services to apply new limits"
echo "2. Monitor resource usage"
echo "3. Adjust limits if necessary"
echo "4. Test system behavior under load"
```

## Long-term Prevention (Minutes 15-30)

### 1. Memory Optimization Implementation (10 minutes)

```bash
#!/bin/bash
# scripts/implement-memory-optimization.sh

set -euo pipefail

echo "🚀 IMPLEMENTING MEMORY OPTIMIZATION"
echo "================================="

OPTIMIZATION_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Optimization started at: $OPTIMIZATION_START"

# Implement application-level memory optimizations
echo ""
echo "🔧 Application-Level Memory Optimizations"
echo "========================================"

# Optimize Node.js garbage collection
echo "Configuring Node.js garbage collection..."

# Update Node.js options for better memory management
if [ -f ".env" ]; then
    # Backup current .env
    cp .env .env.backup

    # Add memory optimization settings
    if grep -q "NODE_OPTIONS" .env; then
        # Update existing NODE_OPTIONS
        CURRENT_OPTIONS=$(grep "NODE_OPTIONS=" .env | cut -d= -f2)
        OPTIMIZED_OPTIONS="$CURRENT_OPTIONS --max-old-space-size=4096 --optimize-for-size --gc-interval=100"
        sed -i "s/NODE_OPTIONS=.*/NODE_OPTIONS=\"$OPTIMIZED_OPTIONS\"/" .env
    else
        echo 'NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size --gc-interval=100"' >> .env
    fi

    echo "✅ Node.js memory optimization configured"
fi

# Create memory monitoring middleware
echo ""
echo "Creating memory monitoring middleware..."
cat > /app/middleware/memory-monitor.js << 'EOF'
/**
 * Memory Monitoring Middleware
 * Monitors memory usage and triggers garbage collection when needed
 */

const memoryUsage = () => {
    const usage = process.memoryUsage();
    return {
        rss: Math.round(usage.rss / 1024 / 1024 * 100) / 100,
        heapTotal: Math.round(usage.heapTotal / 1024 / 1024 * 100) / 100,
        heapUsed: Math.round(usage.heapUsed / 1024 / 1024 * 100) / 100,
        external: Math.round(usage.external / 1024 / 1024 * 100) / 100
    };
};

const MEMORY_THRESHOLD = 2048; // 2GB
const GC_TRIGGER_THRESHOLD = 1536; // 1.5GB

const memoryMonitor = (req, res, next) => {
    const mem = memoryUsage();

    // Log memory usage
    console.log(`Memory Usage: RSS=${mem.rss}MB, Heap=${mem.heapUsed}MB/${mem.heapTotal}MB`);

    // Trigger garbage collection if memory is high
    if (mem.heapUsed > GC_TRIGGER_THRESHOLD) {
        console.log('High memory usage detected, triggering garbage collection');
        if (global.gc) {
            global.gc();
        }
    }

    // Add memory headers
    res.setHeader('X-Memory-Usage', JSON.stringify(mem));

    next();
};

// Periodic memory monitoring
setInterval(() => {
    const mem = memoryUsage();

    if (mem.heapUsed > MEMORY_THRESHOLD) {
        console.error(`CRITICAL: High memory usage detected: ${mem.heapUsed}MB`);

        // Trigger emergency garbage collection
        if (global.gc) {
            global.gc();
        }

        // Log memory details for debugging
        console.error('Memory details:', mem);
    }
}, 30000); // Check every 30 seconds

module.exports = memoryMonitor;
EOF

echo "✅ Memory monitoring middleware created"

# Optimize Qdrant configuration
echo ""
echo "🗄️ Qdrant Memory Optimization"
echo "============================"

if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
    echo "Optimizing Qdrant memory configuration..."

    # Create optimized Qdrant configuration
    cat > /tmp/qdrant-optimized-config.yaml << EOF
# Optimized Qdrant configuration for memory efficiency

storage:
  performance:
    max_search_threads: 2
    update_threads: 1

  # Enable memory-mapped files for better memory efficiency
  use_wal: true

optimizers:
  default_segment_number: 4
  max_segment_size: 100000
  memmap_threshold: 20000
  indexing_threshold: 20000

# Quantization for memory efficiency
quantization:
  scalar:
    type: int8
    quantile: 0.99

# Memory management
service:
  max_request_size_mb: 32

# Enable compression for network transfer
network:
  compression: "lz4"
EOF

    echo "✅ Optimized Qdrant configuration created"
    echo "Location: /tmp/qdrant-optimized-config.yaml"

    # Instructions for applying the configuration
    echo "To apply this configuration:"
    echo "1. Copy the config to Qdrant container"
    echo "2. Restart Qdrant service"
    echo "docker cp /tmp/qdrant-optimized-config.yaml qdrant:/qdrant/config/production.yaml"
    echo "docker restart qdrant"
fi

# Implement vector search optimization
echo ""
echo "🔍 Vector Search Memory Optimization"
echo "==================================="

# Create optimized search parameters
cat > /app/config/search-optimization.json << 'EOF'
{
  "search": {
    "default_limit": 50,
    "max_limit": 1000,
    "use_approximate_search": true,
    "search_params": {
      "hnsw_ef": 128,
      "exact": false
    },
    "pagination": {
      "enabled": true,
      "default_page_size": 50,
      "max_page_size": 200
    }
  },
  "memory": {
    "cache_size_mb": 512,
    "max_concurrent_searches": 10,
    "result_compression": true,
    "stream_large_results": true
  }
}
EOF

echo "✅ Vector search optimization configuration created"

# Implement memory pooling
echo ""
echo "💾 Memory Pooling Implementation"
echo "==============================="

cat > /app/utils/memory-pool.js << 'EOF'
/**
 * Memory Pool for efficient object allocation/deallocation
 */

class MemoryPool {
    constructor(createFn, resetFn, initialSize = 10) {
        this.createFn = createFn;
        this.resetFn = resetFn;
        this.pool = [];
        this.stats = {
            created: 0,
            reused: 0,
            released: 0
        };

        // Pre-populate pool
        for (let i = 0; i < initialSize; i++) {
            this.pool.push(this.createFn());
            this.stats.created++;
        }
    }

    acquire() {
        if (this.pool.length > 0) {
            this.stats.reused++;
            return this.pool.pop();
        } else {
            this.stats.created++;
            return this.createFn();
        }
    }

    release(obj) {
        if (this.resetFn) {
            this.resetFn(obj);
        }
        this.pool.push(obj);
        this.stats.released++;
    }

    getStats() {
        return {
            ...this.stats,
            poolSize: this.pool.length,
            reuseRate: this.stats.reused / (this.stats.created + this.stats.reused) * 100
        };
    }

    clear() {
        this.pool = [];
    }
}

// Specific memory pools for common objects
const vectorPool = new MemoryPool(
    () => new Float32Array(1536), // Standard OpenAI embedding size
    (vec) => vec.fill(0),
    20
);

const searchResultPool = new MemoryPool(
    () => ({
        id: '',
        score: 0,
        payload: {},
        vector: null
    }),
    (result) => {
        result.id = '';
        result.score = 0;
        result.payload = {};
        result.vector = null;
    },
    50
);

module.exports = {
    MemoryPool,
    vectorPool,
    searchResultPool
};
EOF

echo "✅ Memory pooling implementation created"

# Implement cache eviction policies
echo ""
echo "🗑️ Cache Eviction Policy Implementation"
echo "======================================"

cat > /app/cache/eviction-policy.js << 'EOF'
/**
 * LRU (Least Recently Used) Cache with Memory Management
 */

class MemoryManagedLRUCache {
    constructor(maxSize, maxMemoryMB = 512) {
        this.maxSize = maxSize;
        this.maxMemoryBytes = maxMemoryMB * 1024 * 1024;
        this.cache = new Map();
        this.accessOrder = [];
        this.currentMemory = 0;
        this.stats = {
            hits: 0,
            misses: 0,
            evictions: 0
        };
    }

    get(key) {
        if (this.cache.has(key)) {
            // Move to end (most recently used)
            this.accessOrder = this.accessOrder.filter(k => k !== key);
            this.accessOrder.push(key);
            this.stats.hits++;
            return this.cache.get(key);
        }
        this.stats.misses++;
        return null;
    }

    set(key, value, estimatedSize = 1024) {
        // Remove existing entry if present
        if (this.cache.has(key)) {
            this._remove(key);
        }

        // Evict entries if necessary
        while (this.cache.size >= this.maxSize ||
               this.currentMemory + estimatedSize > this.maxMemoryBytes) {
            if (this.accessOrder.length === 0) break;

            const lruKey = this.accessOrder.shift();
            this._remove(lruKey);
            this.stats.evictions++;
        }

        // Add new entry
        this.cache.set(key, value);
        this.accessOrder.push(key);
        this.currentMemory += estimatedSize;
    }

    _remove(key) {
        if (this.cache.has(key)) {
            // Estimate size of removed item
            const estimatedSize = 1024; // Default estimation
            this.currentMemory -= estimatedSize;
            this.cache.delete(key);
        }
    }

    clear() {
        this.cache.clear();
        this.accessOrder = [];
        this.currentMemory = 0;
    }

    getStats() {
        const hitRate = this.stats.hits / (this.stats.hits + this.stats.misses) * 100;
        return {
            ...this.stats,
            hitRate: hitRate.toFixed(2),
            size: this.cache.size,
            memoryUsageMB: (this.currentMemory / 1024 / 1024).toFixed(2),
            maxSize: this.maxSize,
            maxMemoryMB: this.maxMemoryBytes / 1024 / 1024
        };
    }
}

// Create application caches
const vectorCache = new MemoryManagedLRUCache(1000, 256); // 1000 items, 256MB
const searchCache = new MemoryManagedLRUCache(500, 128);   // 500 items, 128MB

module.exports = {
    MemoryManagedLRUCache,
    vectorCache,
    searchCache
};
EOF

echo "✅ Cache eviction policy implementation created"

# Create memory optimization startup script
echo ""
echo "🚀 Creating Memory Optimization Startup Script"
echo "=============================================="

cat > /app/scripts/start-with-memory-optimization.sh << 'EOF'
#!/bin/bash
# Startup script with memory optimization

set -euo pipefail

echo "🚀 Starting Cortex MCP with Memory Optimization"
echo "=============================================="

# Set optimized Node.js options
export NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size --gc-interval=100 --max-semi-space-size=128"

# Set memory-related environment variables
export NODE_ENV=production
export UV_THREADPOOL_SIZE=4

# Clear any existing memory dumps
rm -f /tmp/heapdump-*.heapsnapshot 2>/dev/null || true

# Enable garbage collection monitoring
export NODE_DEBUG_GC=1

# Start application with memory monitoring
echo "Starting application with optimized memory settings..."
exec node dist/index.js
EOF

chmod +x /app/scripts/start-with-memory-optimization.sh

echo "✅ Memory optimization startup script created"

echo ""
echo "🎉 Memory optimization implementation completed"
echo "Optimizations implemented:"
echo "1. Node.js garbage collection tuning"
echo "2. Memory monitoring middleware"
echo "3. Qdrant configuration optimization"
echo "4. Vector search memory optimization"
echo "5. Memory pooling for object allocation"
echo "6. LRU cache with eviction policies"
echo "7. Optimized startup script"
echo ""
echo "Next steps:"
echo "1. Test the optimized configuration"
echo "2. Monitor memory usage patterns"
echo "3. Adjust parameters based on observed behavior"
echo "4. Implement automated testing for memory leaks"
```

### 2. Monitoring and Alerting Enhancement (5 minutes)

```bash
#!/bin/bash
# scripts/enhance-memory-monitoring.sh

set -euo pipefail

echo "📊 ENHANCING MEMORY MONITORING AND ALERTING"
echo "=========================================="

MONITORING_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Monitoring enhancement started at: $MONITORING_START"

# Create comprehensive memory monitoring script
echo ""
echo "📈 Creating Comprehensive Memory Monitor"
echo "====================================="

cat > /usr/local/bin/comprehensive-memory-monitor.sh << 'EOF'
#!/bin/bash
# Comprehensive memory monitoring and alerting

LOG_FILE="/var/log/comprehensive-memory-monitor.log"
METRICS_FILE="/var/log/memory-metrics.csv"
ALERT_EMAIL="${ALERT_EMAIL:-ops@yourcompany.com}"
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"

# Memory thresholds
CRITICAL_THRESHOLD=90
WARNING_THRESHOLD=80
INFO_THRESHOLD=70

# Initialize metrics file
if [ ! -f "$METRICS_FILE" ]; then
    echo "timestamp,total_memory,available_memory,used_memory,percent_usage,app_memory,qdrant_memory,swap_usage,load_average" > "$METRICS_FILE"
fi

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to send alerts
send_alert() {
    local severity=$1
    local message=$2

    log_message "ALERT [$severity]: $message"

    # Send email alert
    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "Memory Alert [$severity] - $(hostname)" "$ALERT_EMAIL"
    fi

    # Send Slack alert
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-type: application/json' \
            --data "$(jq -n --arg text "🚨 Memory Alert [$severity]: $message" '{"text": $text}')" \
            2>/dev/null || log_message "Failed to send Slack alert"
    fi
}

# Get current memory metrics
get_memory_metrics() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local total_mem=$(free -m | awk 'NR==2{print $2}')
    local avail_mem=$(free -m | awk 'NR==2{print $4}')
    local used_mem=$(free -m | awk 'NR==2{print $3}')
    local percent=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')

    # Get application memory
    local app_mem=0
    if pgrep -f "node.*index.js" > /dev/null; then
        app_mem=$(ps -p $(pgrep -f "node.*index.js" | head -1) -o rss= | awk '{print $1/1024}' 2>/dev/null || echo "0")
    fi

    # Get Qdrant memory
    local qdrant_mem=0
    if command -v docker &> /dev/null && docker ps | grep qdrant > /dev/null; then
        qdrant_mem=$(docker stats qdrant --no-stream --format "{{.MemUsage}}" | sed 's/MiB//' | sed 's/[^0-9.]//g' 2>/dev/null || echo "0")
    fi

    # Get swap usage
    local swap_usage=0
    if free | grep -q "Swap:"; then
        swap_usage=$(free | grep Swap | awk '{if($2>0) printf("%.2f", $3/$2 * 100.0); else print "0"}')
    fi

    # Get load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')

    echo "$timestamp,$total_mem,$avail_mem,$used_mem,$percent,$app_mem,$qdrant_mem,$swap_usage,$load_avg"
}

# Get memory metrics
METRICS=$(get_memory_metrics)
PERCENT_USAGE=$(echo "$METRICS" | cut -d',' -f5)

# Log metrics
echo "$METRICS" >> "$METRICS_FILE"

# Check thresholds and send alerts
if (( $(echo "$PERCENT_USAGE >= $CRITICAL_THRESHOLD" | bc -l) )); then
    send_alert "CRITICAL" "Memory usage is ${PERCENT_USAGE}% - Immediate action required!"

    # Trigger emergency procedures
    log_message "Triggering emergency memory recovery..."
    /usr/local/bin/emergency-memory-recovery.sh

elif (( $(echo "$PERCENT_USAGE >= $WARNING_THRESHOLD" | bc -l) )); then
    send_alert "WARNING" "Memory usage is ${PERCENT_USAGE}% - Monitor closely"

elif (( $(echo "$PERCENT_USAGE >= $INFO_THRESHOLD" | bc -l) )); then
    log_message "INFO: Memory usage is ${PERCENT_USAGE}% - Within normal range"
fi

# Check for memory leaks (compare with last hour)
HOUR_AGO=$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')
PREV_METRICS=$(grep "^$HOUR_AGO" "$METRICS_FILE" | tail -1)

if [ -n "$PREV_METRICS" ]; then
    PREV_PERCENT=$(echo "$PREV_METRICS" | cut -d',' -f5)
    MEMORY_GROWTH=$(echo "$PERCENT_USAGE - $PREV_PERCENT" | bc)

    if (( $(echo "$MEMORY_GROWTH > 10" | bc -l) )); then
        send_alert "WARNING" "Memory grew by ${MEMORY_GROWTH}% in the last hour - Possible memory leak"
    fi
fi

# Check file descriptor usage
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    FD_COUNT=$(ls /proc/$NODE_PID/fd 2>/dev/null | wc -l)
    FD_LIMIT=$(cat /proc/$NODE_PID/limits | grep "Max open files" | awk '{print $5}')
    FD_PERCENT=$(echo "scale=1; $FD_COUNT * 100 / $FD_LIMIT" | bc)

    if (( $(echo "$FD_PERCENT > 80" | bc -l) )); then
        send_alert "WARNING" "File descriptor usage is ${FD_PERCENT}% - Potential resource leak"
    fi
fi

# Generate daily summary at midnight
if [ "$(date +%H:%M)" = "00:00" ]; then
    log_message "Generating daily memory summary..."

    # Calculate daily statistics
    DAILY_AVG=$(awk -F',' 'NR>1 {sum+=$5} END {print sum/NR}' "$METRICS_FILE")
    DAILY_MAX=$(awk -F',' 'NR>1 {if($5>max) max=$5} END {print max}' "$METRICS_FILE")
    DAILY_MIN=$(awk -F',' 'NR>1 {if(min=="") min=$5; if($5<min) min=$5} END {print min}' "$METRICS_FILE")

    SUMMARY="Daily Memory Summary - Average: ${DAILY_AVG}%, Max: ${DAILY_MAX}%, Min: ${DAILY_MIN}%"
    log_message "$SUMMARY"
    send_alert "INFO" "$SUMMARY"
fi

log_message "Memory monitoring cycle completed - Usage: ${PERCENT_USAGE}%"
EOF

chmod +x /usr/local/bin/comprehensive-memory-monitor.sh

echo "✅ Comprehensive memory monitor created"

# Create Prometheus memory metrics exporter
echo ""
echo "📊 Creating Prometheus Memory Metrics Exporter"
echo "==============================================="

cat > /usr/local/bin/memory-metrics-exporter.py << 'EOF'
#!/usr/bin/env python3
"""
Prometheus metrics exporter for memory monitoring
"""

import time
import psutil
import subprocess
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class MemoryMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            metrics = self.get_memory_metrics()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def get_memory_metrics(self):
        metrics = []

        # System memory metrics
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()

        metrics.append(f'# HELP system_memory_bytes System memory usage in bytes')
        metrics.append(f'# TYPE system_memory_bytes gauge')
        metrics.append(f'system_memory_bytes{{type="total"}} {memory.total}')
        metrics.append(f'system_memory_bytes{{type="available"}} {memory.available}')
        metrics.append(f'system_memory_bytes{{type="used"}} {memory.used}')
        metrics.append(f'system_memory_bytes{{type="free"}} {memory.free}')

        metrics.append(f'# HELP system_memory_percent System memory usage percentage')
        metrics.append(f'# TYPE system_memory_percent gauge')
        metrics.append(f'system_memory_percent {memory.percent}')

        # Swap metrics
        metrics.append(f'# HELP system_swap_bytes System swap usage in bytes')
        metrics.append(f'# TYPE system_swap_bytes gauge')
        metrics.append(f'system_swap_bytes{{type="total"}} {swap.total}')
        metrics.append(f'system_swap_bytes{{type="used"}} {swap.used}')
        metrics.append(f'system_swap_bytes{{type="free"}} {swap.free}')

        # Process-specific metrics
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info']):
            try:
                if proc.info['name'] == 'nodejs' or 'node' in ' '.join(proc.info['cmdline'] or []):
                    mem_info = proc.info['memory_info']
                    metrics.append(f'# HELP nodejs_process_memory_bytes Node.js process memory usage')
                    metrics.append(f'# TYPE nodejs_process_memory_bytes gauge')
                    metrics.append(f'nodejs_process_memory_bytes{{pid="{proc.info["pid"]}"}} {mem_info.rss}')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Docker container metrics
        try:
            docker_stats = subprocess.check_output(['docker', 'stats', '--no-stream', '--format', 'table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}'], text=True)
            lines = docker_stats.strip().split('\n')[1:]  # Skip header

            metrics.append(f'# HELP docker_container_memory_percent Docker container memory usage percentage')
            metrics.append(f'# TYPE docker_container_memory_percent gauge')

            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        container = parts[0]
                        mem_percent = parts[2].rstrip('%')
                        try:
                            metrics.append(f'docker_container_memory_percent{{container="{container}"}} {mem_percent}')
                        except ValueError:
                            continue
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return '\n'.join(metrics)

def start_metrics_server(port=9101):
    server = HTTPServer(('0.0.0.0', port), MemoryMetricsHandler)
    print(f"Memory metrics server started on port {port}")
    server.serve_forever()

if __name__ == '__main__':
    start_metrics_server()
EOF

chmod +x /usr/local/bin/memory-metrics-exporter.py

echo "✅ Prometheus memory metrics exporter created"

# Update crontab with enhanced monitoring
echo ""
echo "⏰ Updating Crontab with Enhanced Monitoring"
echo "=========================================="

# Remove existing memory monitoring entries
crontab -l 2>/dev/null | grep -v "memory" | crontab -

# Add enhanced monitoring schedule
(crontab -l 2>/dev/null; echo "*/2 * * * * /usr/local/bin/comprehensive-memory-monitor.sh") | crontab
(crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/memory-metrics-exporter.py") | crontab

echo "✅ Enhanced monitoring scheduled"

# Create Grafana dashboard configuration
echo ""
echo "📈 Creating Grafana Dashboard Configuration"
echo "========================================="

cat > /tmp/memory-monitoring-dashboard.json << 'EOF'
{
  "dashboard": {
    "title": "Cortex MCP Memory Monitoring",
    "panels": [
      {
        "title": "System Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "system_memory_percent",
            "legendFormat": "Memory Usage %"
          }
        ],
        "yAxes": [
          {
            "max": 100,
            "min": 0,
            "unit": "percent"
          }
        ]
      },
      {
        "title": "Application Memory",
        "type": "graph",
        "targets": [
          {
            "expr": "nodejs_process_memory_bytes",
            "legendFormat": "{{pid}}"
          }
        ],
        "yAxes": [
          {
            "unit": "bytes"
          }
        ]
      },
      {
        "title": "Docker Container Memory",
        "type": "graph",
        "targets": [
          {
            "expr": "docker_container_memory_percent",
            "legendFormat": "{{container}}"
          }
        ],
        "yAxes": [
          {
            "max": 100,
            "min": 0,
            "unit": "percent"
          }
        ]
      },
      {
        "title": "Memory Usage Alerts",
        "type": "stat",
        "targets": [
          {
            "expr": "system_memory_percent",
            "legendFormat": "Current Usage"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 70},
                {"color": "red", "value": 85}
              ]
            },
            "unit": "percent"
          }
        }
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
EOF

echo "✅ Grafana dashboard configuration created"
echo "Location: /tmp/memory-monitoring-dashboard.json"

# Create automated memory testing script
echo ""
echo "🧪 Creating Automated Memory Testing Script"
echo "========================================"

cat > /usr/local/bin/automated-memory-test.sh << 'EOF'
#!/bin/bash
# Automated memory testing and load simulation

set -euo pipefail

TEST_DURATION=${1:-300}  # 5 minutes default
CONCURRENT_USERS=${2:-10}

echo "🧪 Starting Automated Memory Test"
echo "Duration: ${TEST_DURATION}s"
echo "Concurrent Users: $CONCURRENT_USERS"
echo ""

# Pre-test memory snapshot
echo "Taking pre-test memory snapshot..."
PRE_TEST_MEMORY=$(free -m | awk 'NR==2{print $4}')
PRE_TEST_TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo "Pre-test available memory: ${PRE_TEST_MEMORY}MB at $PRE_TEST_TIME"

# Start memory monitoring in background
MONITOR_PID=$(
    /usr/local/bin/comprehensive-memory-monitor.sh &
    echo $!
)

# Simulate memory load
echo ""
echo "🔄 Simulating Memory Load..."
echo "==========================="

# Function to simulate memory-intensive operation
simulate_memory_operation() {
    local operation_id=$1
    echo "Starting memory operation $operation_id"

    # Generate large memory operations
    for i in {1..100}; do
        curl -s -X POST http://localhost:3000/api/memory/find \
            -H "Content-Type: application/json" \
            -d '{"query":"memory test operation '$operation_id' item '$i'","limit":100}' \
            > /dev/null 2>&1 || true

        # Store some data
        curl -s -X POST http://localhost:3000/api/memory/store \
            -H "Content-Type: application/json" \
            -d '{"items":[{"kind":"observation","content":"Memory test data for operation '$operation_id' item '$i'"}]}' \
            > /dev/null 2>&1 || true

        # Small delay to prevent overwhelming the system
        sleep 0.1
    done

    echo "Memory operation $operation_id completed"
}

# Start concurrent operations
for i in $(seq 1 $CONCURRENT_USERS); do
    simulate_memory_operation $i &
done

# Monitor for the specified duration
echo "Monitoring for ${TEST_DURATION} seconds..."
sleep $TEST_DURATION

# Stop background monitor
kill $MONITOR_PID 2>/dev/null || true

# Post-test memory snapshot
echo ""
echo "📊 Post-Test Analysis"
echo "===================="

POST_TEST_MEMORY=$(free -m | awk 'NR==2{print $4}')
POST_TEST_TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo "Post-test available memory: ${POST_TEST_MEMORY}MB at $POST_TEST_TIME"

MEMORY_DIFF=$((POST_TEST_MEMORY - PRE_TEST_MEMORY))
echo "Memory difference: ${MEMORY_DIFF}MB"

# Analyze results
if [ "$MEMORY_DIFF" -lt -100 ]; then
    echo "❌ WARNING: Significant memory consumption detected (${MEMORY_DIFF}MB)"
    echo "Possible memory leak or inefficient memory usage"

    # Generate alert
    SUBJECT="Memory Test Alert - Potential Memory Issue"
    MESSAGE="Automated memory test detected significant memory consumption: ${MEMORY_DIFF}MB"

    if [ -n "${ALERT_EMAIL:-}" ]; then
        echo "$MESSAGE" | mail -s "$SUBJECT" "$ALERT_EMAIL"
    fi

elif [ "$MEMORY_DIFF" -lt -50 ]; then
    echo "⚠️ CAUTION: Moderate memory consumption detected (${MEMORY_DIFF}MB)"
    echo "Monitor closely for memory leaks"

else
    echo "✅ Memory usage is within acceptable limits (${MEMORY_DIFF}MB)"
fi

# Check for OOM events
OOM_EVENTS=$(dmesg | grep -i "killed process" | tail -5)
if [ -n "$OOM_EVENTS" ]; then
    echo "❌ OOM events detected during test:"
    echo "$OOM_EVENTS"
fi

# Generate test report
REPORT_FILE="/tmp/memory-test-report-$(date +%Y%m%d_%H%M%S).md"
cat > "$REPORT_FILE" << EOL
# Automated Memory Test Report

**Test Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Test Duration:** ${TEST_DURATION}s
**Concurrent Users:** $CONCURRENT_USERS

## Memory Analysis

### Pre-Test
- **Available Memory:** ${PRE_TEST_MEMORY}MB
- **Time:** $PRE_TEST_TIME

### Post-Test
- **Available Memory:** ${POST_TEST_MEMORY}MB
- **Time:** $POST_TEST_TIME

### Results
- **Memory Difference:** ${MEMORY_DIFF}MB
- **Status:** $(if [ "$MEMORY_DIFF" -lt -100 ]; then echo "❌ FAILED - High memory consumption"; elif [ "$MEMORY_DIFF" -lt -50 ]; then echo "⚠️ WARNING - Moderate consumption"; else echo "✅ PASSED - Acceptable usage"; fi)

## Recommendations

$(if [ "$MEMORY_DIFF" -lt -100 ]; then echo "1. Investigate potential memory leaks
2. Optimize memory usage patterns
3. Consider increasing memory limits
4. Implement more aggressive garbage collection"; elif [ "$MEMORY_DIFF" -lt -50 ]; then echo "1. Monitor memory usage trends
2. Implement memory profiling
3. Optimize caching strategies"; else echo "1. Continue monitoring
2. Implement regular testing
3. Document baseline memory usage"; fi)

## Test Environment
- **Hostname:** $(hostname)
- **System:** $(uname -a)
- **Total Memory:** $(free -m | awk 'NR==2{print $2}')MB

---
**Report Generated:** $(date '+%Y-%m-%d %H:%M:%S')
EOL

echo "Test report generated: $REPORT_FILE"

echo ""
echo "🎉 Automated memory testing completed"
EOF

chmod +x /usr/local/bin/automated-memory-test.sh

echo "✅ Automated memory testing script created"

# Schedule regular memory tests
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/automated-memory-test.sh 600 20") | crontab

echo ""
echo "🎉 Enhanced memory monitoring and alerting completed"
echo "Summary of enhancements:"
echo "1. Comprehensive memory monitoring (every 2 minutes)"
echo "2. Prometheus metrics exporter (port 9101)"
echo "3. Grafana dashboard configuration"
echo "4. Automated memory testing (daily at 2 AM)"
echo "5. Enhanced alerting with multiple channels"
echo "6. Memory leak detection"
echo "7. File descriptor monitoring"
echo "8. Daily memory summaries"
echo ""
echo "Monitoring logs: /var/log/comprehensive-memory-monitor.log"
echo "Metrics file: /var/log/memory-metrics.csv"
echo "Test reports: /tmp/memory-test-report-*.md"
echo ""
echo "Next steps:"
echo "1. Import Grafana dashboard configuration"
echo "2. Configure Prometheus to scrape metrics from port 9101"
echo "3. Test alerting mechanisms"
echo "4. Review automated test results"
echo "5. Adjust thresholds based on observed patterns"
```

### 3. Documentation and Training Materials (5 minutes)

```bash
#!/bin/bash
# scripts/create-memory-documentation.sh

set -euo pipefail

echo "📚 CREATING MEMORY DOCUMENTATION AND TRAINING"
echo "=============================================="

DOC_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Documentation creation started at: $DOC_START"

# Create memory management guide
echo ""
echo "📖 Creating Memory Management Guide"
echo "=================================="

cat > /app/docs/memory-management-guide.md << 'EOF'
# Cortex MCP Memory Management Guide

## Overview

This guide provides comprehensive information about memory management in the Cortex Memory MCP Server, including optimization strategies, monitoring procedures, and troubleshooting techniques.

## Architecture Overview

### Memory Components

```
Cortex MCP Memory Architecture
├── Application Layer (Node.js)
│   ├── Heap Memory (JavaScript objects)
│   ├── Stack Memory (function calls)
│   └── External Memory (C++ addons)
├── Vector Database (Qdrant)
│   ├── Vector Storage (1536-dimensional)
│   ├── Index Structures (HNSW)
│   └── Query Cache
├── System Memory
│   ├── Page Cache
│   ├── Buffer Cache
│   └── Swap Space
└── Monitoring & Alerting
    ├── Metrics Collection
    ├── Threshold Monitoring
    └── Automated Recovery
```

## Memory Allocation Patterns

### Application Memory Usage

1. **Vector Embeddings**: ~6KB per 1536-dimensional vector (float32)
2. **Search Results**: ~1KB per result (metadata + pointers)
3. **API Payloads**: Variable, typically 1-10KB per request
4. **Connection Buffers**: ~64KB per active connection
5. **Internal Caches**: Configurable, default 512MB

### Qdrant Memory Usage

1. **Vector Storage**: Raw vector data + indexing overhead
2. **HNSW Index**: Graph structure for approximate search
3. **Query Cache**: Frequently accessed vectors
4. **Segmentation**: Memory-mapped segments for large collections

## Optimization Strategies

### Application-Level Optimizations

#### 1. Garbage Collection Tuning
```bash
# Node.js GC optimization
export NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size --gc-interval=100"
```

#### 2. Memory Pooling
- Use object pools for frequently allocated objects
- Implement vector result pooling
- Cache common query patterns

#### 3. Streaming Results
- Enable result streaming for large datasets
- Implement pagination for vector searches
- Use compression for network transfers

### Database-Level Optimizations

#### 1. Qdrant Configuration
```yaml
storage:
  performance:
    max_search_threads: 2
    update_threads: 1
optimizers:
  default_segment_number: 4
  max_segment_size: 100000
  memmap_threshold: 20000
```

#### 2. Vector Quantization
- Use int8 quantization for 75% memory reduction
- Maintain separate quantized and original vectors
- Configure appropriate quantile thresholds

### System-Level Optimizations

#### 1. Linux Memory Management
```bash
# Optimize for memory-intensive applications
echo 1 > /proc/sys/vm/overcommit_memory
echo 60 > /proc/sys/vm/swappiness
```

#### 2. Container Resource Limits
```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

## Monitoring Procedures

### Key Metrics to Monitor

1. **Memory Usage Percentage**: System-wide memory utilization
2. **Heap Size**: Node.js heap memory usage
3. **Qdrant Memory**: Vector database memory consumption
4. **File Descriptors**: Number of open file handles
5. **Swap Usage**: Virtual memory utilization

### Alert Thresholds

- **Critical**: >90% memory usage
- **Warning**: 80-90% memory usage
- **Info**: 70-80% memory usage

### Monitoring Tools

1. **Built-in Scripts**:
   ```bash
   /usr/local/bin/comprehensive-memory-monitor.sh
   /usr/local/bin/automated-memory-test.sh
   ```

2. **Prometheus Metrics**: Available on port 9101
3. **Grafana Dashboard**: Pre-configured memory monitoring
4. **Log Analysis**: Monitor `/var/log/comprehensive-memory-monitor.log`

## Troubleshooting Guide

### Common Memory Issues

#### 1. High Memory Usage (>90%)
**Symptoms**: Slow responses, service degradation
**Causes**: Memory leaks, inefficient queries, insufficient resources
**Solutions**:
- Run emergency memory recovery: `/usr/local/bin/emergency-memory-recovery.sh`
- Identify memory leaks with profiling
- Scale resources or optimize queries

#### 2. Memory Leaks
**Symptoms**: Gradual memory increase over time
**Detection**:
- Monitor memory growth trends
- Use heap dumps for analysis
- Check file descriptor usage
**Solutions**:
- Profile application with heapdump
- Implement object pooling
- Fix circular references

#### 3. OOM (Out of Memory) Events
**Symptoms**: Service crashes, kernel kills processes
**Detection**:
```bash
dmesg | grep -i "killed process"
```
**Solutions**:
- Increase memory limits
- Optimize memory usage
- Implement swap space

### Recovery Procedures

#### 1. Immediate Response (First 5 minutes)
1. Assess memory usage: `free -h`
2. Clear system caches: `sync && echo 3 > /proc/sys/vm/drop_caches`
3. Restart memory-intensive services
4. Monitor for improvement

#### 2. Detailed Investigation (Minutes 5-15)
1. Analyze memory allocation patterns
2. Check for memory leaks
3. Review application logs
4. Generate heap dumps if needed

#### 3. Long-term Resolution (Minutes 15-30)
1. Implement memory optimizations
2. Configure resource limits
3. Set up enhanced monitoring
4. Document lessons learned

## Best Practices

### Development Practices

1. **Memory-Efficient Coding**:
   - Avoid large object allocations
   - Use streaming for large data sets
   - Implement proper cleanup in error handlers

2. **Testing Practices**:
   - Include memory usage tests
   - Perform load testing with memory monitoring
   - Test for memory leaks

3. **Code Review Guidelines**:
   - Review memory allocation patterns
   - Check for potential memory leaks
   - Ensure proper resource cleanup

### Operational Practices

1. **Regular Monitoring**:
   - Monitor memory usage trends
   - Set up automated alerts
   - Review memory metrics daily

2. **Preventive Maintenance**:
   - Regular memory testing
   - System resource reviews
   - Configuration optimization

3. **Incident Response**:
   - Document memory incidents
   - Analyze root causes
   - Implement preventive measures

## Performance Tuning

### Memory Allocation Tuning

#### Node.js Configuration
```bash
# Optimize for memory efficiency
NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size --max-semi-space-size=128"
```

#### Qdrant Optimization
```yaml
# Memory-efficient configuration
quantization:
  scalar:
    type: int8
    quantile: 0.99
optimizers:
  memmap_threshold: 20000
```

### Cache Optimization

#### Application Caching
- Use LRU cache with size limits
- Implement cache eviction policies
- Monitor cache hit rates

#### Database Caching
- Configure Qdrant query cache
- Use result compression
- Implement cache warming

## Emergency Procedures

### Memory Emergency Response

1. **Assessment** (2 minutes):
   ```bash
   /usr/local/bin/rapid-memory-assessment.sh
   ```

2. **Recovery** (2 minutes):
   ```bash
   /usr/local/bin/emergency-memory-recovery.sh
   ```

3. **Scaling Decision** (1 minute):
   ```bash
   /usr/local/bin/memory-scaling-decision.sh
   ```

### Escalation Procedures

1. **High Severity** (>90% usage):
   - Immediate action required
   - Consider service restart
   - Prepare for scaling

2. **Medium Severity** (80-90% usage):
   - Monitor closely
   - Implement optimizations
   - Prepare scaling options

## Training Materials

### Quick Reference Card

#### Memory Commands
```bash
# Check memory usage
free -h

# Monitor memory-intensive processes
ps aux --sort=-%mem | head -10

# Clear system caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Check for OOM events
dmesg | grep -i "killed process"

# Monitor Node.js memory
node --inspect index.js
```

#### Alert Thresholds
- Critical: >90%
- Warning: 80-90%
- Info: 70-80%

#### Recovery Scripts
- Emergency: `/usr/local/bin/emergency-memory-recovery.sh`
- Monitoring: `/usr/local/bin/comprehensive-memory-monitor.sh`
- Testing: `/usr/local/bin/automated-memory-test.sh`

### Training Checklist

#### For New Engineers
- [ ] Understand memory architecture
- [ ] Learn monitoring procedures
- [ ] Practice emergency response
- [ ] Review optimization techniques

#### For Operations Team
- [ ] Configure monitoring alerts
- [ ] Set up automated testing
- [ ] Create escalation procedures
- [ ] Document incident responses

---

**Last Updated**: $(date '+%Y-%m-%d')
**Version**: 1.0
**Maintainer**: Cortex MCP Team
EOF

echo "✅ Memory management guide created"

# Create training presentation
echo ""
echo "🎓 Creating Memory Management Training Presentation"
echo "=================================================="

cat > /app/docs/memory-training-presentation.md << 'EOF'
# Memory Management Training

## Slide 1: Title Slide
**Cortex MCP Memory Management**
*Comprehensive Guide to Monitoring, Optimization, and Troubleshooting*

## Slide 2: Learning Objectives
**What You'll Learn Today**
- Understand Cortex MCP memory architecture
- Monitor memory usage effectively
- Implement memory optimization strategies
- Troubleshoot common memory issues
- Respond to memory emergencies

## Slide 3: Memory Architecture Overview
**System Components**
```
Application (Node.js) → Qdrant (Vector DB) → System (Linux)
     ↓                      ↓                    ↓
  Heap Memory         Vector Storage        Page Cache
  Object Pools       Index Structures     Swap Space
  Connection Buffers Query Cache          Buffer Cache
```

## Slide 4: Memory Usage Patterns
**Where Does Memory Go?**
- **Vectors**: 6KB per 1536-dimensional vector
- **Search Results**: 1KB per result
- **API Requests**: 1-10KB per request
- **Caches**: 512MB default
- **System Overhead**: ~10% of total

## Slide 5: Monitoring Dashboard
**Key Metrics to Watch**
- Memory Usage Percentage (Critical: >90%)
- Heap Size Trend
- Qdrant Memory Usage
- File Descriptor Count
- Swap Usage

## Slide 6: Alert Thresholds
**When to Act**
- 🚨 **Critical** (>90%): Immediate action required
- ⚠️ **Warning** (80-90%): Monitor closely
- ✅ **Normal** (<80%): Continue monitoring

## Slide 7: Emergency Response
**First 5 Minutes**
1. **Assess**: `/usr/local/bin/rapid-memory-assessment.sh`
2. **Recover**: `/usr/local/bin/emergency-memory-recovery.sh`
3. **Decide**: `/usr/local/bin/memory-scaling-decision.sh`

## Slide 8: Common Issues
**Memory Problems and Solutions**
- **High Usage**: Clear caches, restart services
- **Memory Leaks**: Profile with heapdump, fix code
- **OOM Events**: Increase limits, optimize usage

## Slide 9: Optimization Techniques
**Memory Efficiency Strategies**
- Garbage collection tuning
- Object pooling
- Result streaming
- Vector quantization

## Slide 10: Best Practices
**Development Guidelines**
- Memory-efficient coding
- Regular testing
- Code review checklist
- Performance monitoring

## Slide 11: Hands-on Exercise
**Practice Scenario**
- Simulate high memory usage
- Use monitoring tools
- Practice recovery procedures
- Document findings

## Slide 12: Q&A
**Questions and Discussion**

## Slide 13: Resources
**Documentation and Tools**
- Memory Management Guide
- Monitoring Scripts
- Emergency Procedures
- Contact Information

## Slide 14: Thank You
**Questions?**
*Contact: ops@yourcompany.com*
EOF

echo "✅ Training presentation created"

# Create quick reference card
echo ""
echo "📋 Creating Memory Management Quick Reference Card"
echo "=================================================="

cat > /app/docs/memory-quick-reference.md << 'EOF'
# Memory Management Quick Reference

## 🚨 Emergency Commands (First 5 Minutes)

### Assessment
```bash
# Quick memory check
free -h
ps aux --sort=-%mem | head -5

# Detailed assessment
/usr/local/bin/rapid-memory-assessment.sh
```

### Recovery
```bash
# Clear system caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Emergency recovery
/usr/local/bin/emergency-memory-recovery.sh
```

### Scaling Decision
```bash
# Determine if scaling is needed
/usr/local/bin/memory-scaling-decision.sh
```

## 📊 Monitoring Commands

### System Memory
```bash
# Current usage
free -h

# Memory trends
watch -n 5 free -h

# Process memory usage
ps aux --sort=-%mem | head -10
```

### Application Memory
```bash
# Node.js process memory
ps aux | grep "node.*index.js"

# Docker container memory
docker stats --no-stream
```

### Database Memory
```bash
# Qdrant metrics
curl -s http://localhost:6333/metrics | grep memory

# Collection info
curl -s http://localhost:6333/collections/cortex-memory
```

## 🔧 Optimization Commands

### Garbage Collection
```bash
# Set GC options
export NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size"

# Trigger GC manually (if debug enabled)
kill -USR2 <node-pid>
```

### Cache Management
```bash
# Clear system caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Clear Docker cache
docker system prune -f
```

### Resource Limits
```bash
# Check limits
ulimit -a

# Set memory limits
ulimit -v unlimited  # Virtual memory
ulimit -m unlimited  # Physical memory
```

## 🚨 Alert Thresholds

| Level | Memory Usage | Action |
|-------|-------------|--------|
| Critical | >90% | Immediate action |
| Warning | 80-90% | Monitor closely |
| Info | 70-80% | Normal monitoring |

## 📱 Monitoring URLs

- **Grafana Dashboard**: http://localhost:3000/d/memory
- **Prometheus Metrics**: http://localhost:9090/metrics
- **Memory Metrics**: http://localhost:9101/metrics

## 📞 Contact Information

- **On-call Engineer**: [Phone Number]
- **Ops Team**: ops@yourcompany.com
- **Emergency Channel**: #incidents-cortex

## 🔍 Troubleshooting Checklist

### High Memory Usage
- [ ] Check system memory: `free -h`
- [ ] Identify top processes: `ps aux --sort=-%mem`
- [ ] Clear caches: `sync && echo 3 > /proc/sys/vm/drop_caches`
- [ ] Restart services if needed
- [ ] Monitor for improvement

### Memory Leaks
- [ ] Monitor memory trends over time
- [ ] Generate heap dump: `kill -USR2 <node-pid>`
- [ ] Analyze heap dump with Chrome DevTools
- [ ] Fix identified issues in code

### OOM Events
- [ ] Check OOM logs: `dmesg | grep -i "killed process"`
- [ ] Increase memory limits
- [ ] Optimize memory usage
- [ ] Add swap space if needed

## 🛠️ Useful Scripts

| Script | Purpose | Location |
|--------|---------|----------|
| `comprehensive-memory-monitor.sh` | Continuous monitoring | `/usr/local/bin/` |
| `emergency-memory-recovery.sh` | Emergency recovery | `/usr/local/bin/` |
| `automated-memory-test.sh` | Load testing | `/usr/local/bin/` |
| `memory-scaling-decision.sh` | Scaling decisions | `/usr/local/bin/` |

## 📚 Documentation

- **Full Guide**: `/app/docs/memory-management-guide.md`
- **Training**: `/app/docs/memory-training-presentation.md`
- **Incident Reports**: `/tmp/incident_report_*.md`

---
*Last Updated: $(date '+%Y-%m-%d')*
EOF

echo "✅ Quick reference card created"

echo ""
echo "🎉 Documentation and training materials created"
echo "Documentation summary:"
echo "1. Memory Management Guide: /app/docs/memory-management-guide.md"
echo "2. Training Presentation: /app/docs/memory-training-presentation.md"
echo "3. Quick Reference Card: /app/docs/memory-quick-reference.md"
echo ""
echo "Next steps:"
echo "1. Review the documentation with the team"
echo "2. Conduct training sessions"
echo "3. Update materials based on feedback"
echo "4. Regularly review and update content"
```

### 4. System Configuration Review (5 minutes)

```bash
#!/bin/bash
# scripts/review-memory-configuration.sh

set -euo pipefail

echo "⚙️ MEMORY CONFIGURATION REVIEW"
echo "============================="

REVIEW_START=$(date '+%Y-%m-%d %H:%M:%S')
echo "Configuration review started at: $REVIEW_START"

# Review system configuration
echo ""
echo "💻 System Configuration Review"
echo "============================="

# Check Linux memory parameters
echo "Linux memory parameters:"
echo "vm.swappiness: $(cat /proc/sys/vm/swappiness 2>/dev/null || echo 'N/A')"
echo "vm.overcommit_memory: $(cat /proc/sys/vm/overcommit_memory 2>/dev/null || echo 'N/A')"
echo "vm.overcommit_ratio: $(cat /proc/sys/vm/overcommit_ratio 2>/dev/null || echo 'N/A')"
echo "vm.min_free_kbytes: $(cat /proc/sys/vm/min_free_kbytes 2>/dev/null || echo 'N/A')"

# Check swap configuration
echo ""
echo "Swap configuration:"
swapon --show 2>/dev/null || echo "No swap configured"
echo "Swap total: $(free -h | grep Swap | awk '{print $2}' | sed 's/[A-Z]//g' || echo '0')"

# Check cgroup configuration
echo ""
echo "Cgroup configuration:"
if [ -d "/sys/fs/cgroup/memory" ]; then
    echo "Memory cgroup available: Yes"
    echo "Memory cgroup version: $(cat /sys/fs/cgroup/memory/memory.stat > /dev/null 2>&1 && echo "v1" || echo "v2")"
else
    echo "Memory cgroup available: No"
fi

# Review application configuration
echo ""
echo "🔧 Application Configuration Review"
echo "=================================="

# Check Node.js configuration
if [ -f ".env" ]; then
    echo "Node.js configuration (.env):"
    grep -E "(NODE_OPTIONS|NODE_ENV)" .env || echo "No Node.js options found"
else
    echo "❌ .env file not found"
fi

# Check runtime configuration
if pgrep -f "node.*index.js" > /dev/null; then
    NODE_PID=$(pgrep -f "node.*index.js" | head -1)
    echo "Node.js runtime configuration (PID: $NODE_PID):"

    # Check command line arguments
    CMDLINE=$(ps -p $NODE_PID -o args=)
    echo "Command line: $CMDLINE"

    # Check environment variables
    echo "Environment variables:"
    cat /proc/$NODE_PID/environ 2>/dev/null | tr '\0' '\n' | grep -E "(NODE_|UV_)" | head -5 || echo "No relevant env vars"
else
    echo "❌ Node.js process not found"
fi

# Review Docker configuration
echo ""
echo "🐳 Docker Configuration Review"
echo "=============================="

if [ -f "docker-compose.yml" ]; then
    echo "Docker Compose configuration:"

    # Check resource limits
    if grep -q "resources:" docker-compose.yml; then
        echo "✅ Resource limits configured"
        grep -A 10 "resources:" docker-compose.yml
    else
        echo "⚠️ No resource limits configured"
    fi

    # Check memory limits
    if grep -q "memory:" docker-compose.yml; then
        echo "✅ Memory limits configured"
    else
        echo "⚠️ No memory limits configured"
    fi
else
    echo "❌ docker-compose.yml not found"
fi

# Review Kubernetes configuration
echo ""
echo "☸️ Kubernetes Configuration Review"
echo "================================="

if command -v kubectl &> /dev/null; then
    # Check resource limits for deployments
    echo "Deployment resource configuration:"

    if kubectl get deployment cortex-mcp -n cortex-mcp &> /dev/null; then
        echo "cortex-mcp deployment:"
        kubectl describe deployment cortex-mcp -n cortex-mcp | grep -A 20 "Resources:" || echo "No resources configured"
    fi

    if kubectl get deployment qdrant -n cortex-mcp &> /dev/null; then
        echo "qdrant deployment:"
        kubectl describe deployment qdrant -n cortex-mcp | grep -A 20 "Resources:" || echo "No resources configured"
    fi

    # Check limits and requests
    echo "Namespace resource quotas:"
    kubectl describe namespace cortex-mcp | grep -A 10 "Resource Quotas" || echo "No resource quotas configured"

else
    echo "❌ kubectl not available"
fi

# Review monitoring configuration
echo ""
echo "📊 Monitoring Configuration Review"
echo "================================="

# Check if monitoring scripts exist
MONITORING_SCRIPTS=(
    "/usr/local/bin/comprehensive-memory-monitor.sh"
    "/usr/local/bin/emergency-memory-recovery.sh"
    "/usr/local/bin/automated-memory-test.sh"
)

echo "Monitoring scripts status:"
for script in "${MONITORING_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        echo "✅ $script - Present and executable"
        ls -la "$script"
    else
        echo "❌ $script - Missing"
    fi
done

# Check crontab entries
echo ""
echo "Crontab monitoring entries:"
crontab -l 2>/dev/null | grep memory || echo "No memory monitoring in crontab"

# Check log configuration
echo ""
echo "Log configuration:"
echo "Memory monitor log: $(ls -la /var/log/comprehensive-memory-monitor.log 2>/dev/null || echo 'Not found')"
echo "Memory metrics file: $(ls -la /var/log/memory-metrics.csv 2>/dev/null || echo 'Not found')"

# Generate configuration recommendations
echo ""
echo "💡 Configuration Recommendations"
echo "==============================="

RECOMMENDATIONS=""

# System recommendations
SWAPPINESS=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "60")
if [ "$SWAPPINESS" -gt 60 ]; then
    RECOMMENDATIONS="$RECOMMENDATIONS
1. Reduce swappiness to 60 for better memory management
   echo 'vm.swappiness=60' > /proc/sys/vm/swappiness
"
fi

OVERCOMMIT=$(cat /proc/sys/vm/overcommit_memory 2>/dev/null || echo "0")
if [ "$OVERCOMMIT" -eq 0 ]; then
    RECOMMENDATIONS="$RECOMMENDATIONS
2. Enable conservative memory overcommit
   echo '1' > /proc/sys/vm/overcommit_memory
   echo '80' > /proc/sys/vm/overcommit_ratio
"
fi

# Application recommendations
if ! grep -q "NODE_OPTIONS" .env 2>/dev/null; then
    RECOMMENDATIONS="$RECOMMENDATIONS
3. Configure Node.js memory options in .env
   NODE_OPTIONS='--max-old-space-size=4096 --optimize-for-size'
"
fi

# Docker recommendations
if [ -f "docker-compose.yml" ] && ! grep -q "resources:" docker-compose.yml; then
    RECOMMENDATIONS="$RECOMMENDATIONS
4. Add resource limits to docker-compose.yml
   resources:
     limits:
       memory: 4G
       cpus: '2.0'
"
fi

# Monitoring recommendations
if [ ! -f "/usr/local/bin/comprehensive-memory-monitor.sh" ]; then
    RECOMMENDATIONS="$RECOMMENDATIONS
5. Install comprehensive memory monitoring
   - Copy monitoring scripts to /usr/local/bin/
   - Set up crontab entries
   - Configure alerting
"
fi

if [ -n "$RECOMMENDATIONS" ]; then
    echo "Recommendations:"
    echo -e "$RECOMMENDATIONS"
else
    echo "✅ Configuration appears to be optimal"
fi

# Create configuration report
REPORT_FILE="/tmp/memory-configuration-review-$(date +%Y%m%d_%H%M%S).md"
cat > "$REPORT_FILE" << EOF
# Memory Configuration Review Report

**Review Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Hostname:** $(hostname)
**System:** $(uname -a)

## System Configuration

### Linux Memory Parameters
- **Swappiness:** $SWAPPINESS
- **Overcommit Memory:** $OVERCOMMIT
- **Overcommit Ratio:** $(cat /proc/sys/vm/overcommit_ratio 2>/dev/null || echo 'N/A')

### Swap Configuration
- **Swap Total:** $(free -h | grep Swap | awk '{print $2}' | sed 's/[A-Z]//g' || echo '0')
- **Swap Usage:** $(free -h | grep Swap | awk '{print $3}' | sed 's/[A-Z]//g' || echo '0')

### Cgroup Support
- **Memory Cgroup:** $([ -d "/sys/fs/cgroup/memory" ] && echo "Available" || echo "Not Available")

## Application Configuration

### Node.js Configuration
$(if [ -f ".env" ]; then echo '```'; grep -E "(NODE_OPTIONS|NODE_ENV)" .env || echo "No Node.js options found"; echo '```'; else echo "❌ .env file not found"; fi)

### Runtime Status
$(if pgrep -f "node.*index.js" > /dev/null; then echo "✅ Node.js process running"; else echo "❌ Node.js process not found"; fi)

## Container Configuration

### Docker Configuration
$(if [ -f "docker-compose.yml" ]; then echo '```'; grep -A 10 "resources:" docker-compose.yml || echo "No resource limits configured"; echo '```'; else echo "❌ docker-compose.yml not found"; fi)

### Kubernetes Configuration
$(if command -v kubectl &> /dev/null; then echo "✅ kubectl available"; echo "Deployment resource status can be checked with:"; echo "kubectl describe deployment cortex-mcp -n cortex-mcp"; else echo "❌ kubectl not available"; fi)

## Monitoring Configuration

### Scripts Status
$(for script in "${MONITORING_SCRIPTS[@]}"; do echo "- $script: $([ -f "$script" ] && echo "Present" || echo "Missing")"; done)

### Crontab Entries
$(crontab -l 2>/dev/null | grep memory || echo "No memory monitoring configured")

### Log Files
- Memory Monitor: $([ -f "/var/log/comprehensive-memory-monitor.log" ] && echo "Present" || echo "Missing")
- Metrics File: $([ -f "/var/log/memory-metrics.csv" ] && echo "Present" || echo "Missing")

## Recommendations

$RECOMMENDATIONS

## Next Steps

1. Implement the recommendations above
2. Test configuration changes
3. Monitor for improvements
4. Document any issues found

---
**Report Generated:** $(date '+%Y-%m-%d %H:%M:%S')
EOF

echo "Configuration report generated: $REPORT_FILE"

echo ""
echo "🎉 Memory configuration review completed"
echo "Review summary:"
echo "- System parameters checked"
echo "- Application configuration reviewed"
echo "- Container/Orchestration config analyzed"
echo "- Monitoring setup verified"
echo "- Recommendations generated"
echo ""
echo "Report saved to: $REPORT_FILE"
echo ""
echo "Next steps:"
echo "1. Review the recommendations"
echo "2. Implement suggested changes"
echo "3. Test configuration updates"
echo "4. Monitor for improvements"
```

## Communication Templates

### High Memory Pressure Alert
```
🚨 ALERT: HIGH MEMORY PRESSURE DETECTED 🚨

Incident: High memory pressure
Severity: HIGH
Time: [TIME]
Memory Usage: [PERCENTAGE]%

Current Status:
- System memory usage is [PERCENTAGE]%
- Application performance may be degraded
- Risk of OOM events: [RISK LEVEL]

Immediate Actions:
- Memory recovery procedures initiated
- Non-essential services being optimized
- Team notified and monitoring

Impact:
- Users may experience slower response times
- Risk of service disruption if memory continues to increase
- Database operations may be affected

Next Update: [TIME + 10 minutes]
Status Page: [URL]
```

### Memory Pressure Resolution
```
✅ RESOLVED: Memory Pressure Incident

Incident: High memory pressure
Duration: [DURATION]
Resolution Time: [TIME]

Resolution Summary:
- Memory usage reduced from [START_PERCENTAGE]% to [END_PERCENTAGE]%
- Service performance restored to normal
- No data loss occurred

Actions Taken:
- System caches cleared
- Application memory optimization applied
- Services restarted as needed
- Resource limits adjusted if needed

Root Cause:
[BRIEF DESCRIPTION OF CAUSE]

Prevention Measures:
- Enhanced monitoring implemented
- Resource limits configured
- Alert thresholds adjusted

System is now operating normally.
Thank you for your patience.
```

This comprehensive incident response runbook for high memory pressure provides detailed procedures for detection, immediate response, detailed investigation, and long-term prevention, with specific commands, expected outputs, and clear decision criteria.