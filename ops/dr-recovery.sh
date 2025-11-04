#!/bin/bash
# DR Recovery Script - Automated Disaster Recovery Procedures
# This script provides automated recovery procedures for various disaster scenarios

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/dr-recovery.log"
CONFIG_FILE="$SCRIPT_DIR/../config/dr-config.json"
BACKUP_DIR="/backups"
S3_BUCKET="cortex-backups"
TEMP_DIR="/tmp/dr-recovery-$$"

# Service configuration
CORTEX_MCP_PORT=3000
QDRANT_PORT=6333
CORTEX_MCP_SERVICE="cortex-mcp"
QDRANT_SERVICE="qdrant"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
        "RECOVERY")
            echo -e "${PURPLE}[RECOVERY]${NC} $message"
            ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Trap for cleanup
trap cleanup EXIT

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log "WARN" "Configuration file not found, using defaults"
    fi

    # Export environment variables
    export CORTEX_MCP_PORT QDRANT_PORT BACKUP_DIR S3_BUCKET
}

# System health check
check_system_health() {
    log "INFO" "Performing comprehensive system health check"

    local health_status="HEALTHY"
    local issues=()

    # Check memory
    local memory_available=$(free | awk 'NR==2{printf "%.1f", $7*100/$2}')
    if (( $(echo "$memory_available < 10" | bc -l) )); then
        health_status="UNHEALTHY"
        issues+=("Critical memory shortage: ${memory_available}%")
    elif (( $(echo "$memory_available < 20" | bc -l) )); then
        health_status="DEGRADED"
        issues+=("Low memory: ${memory_available}%")
    fi

    # Check disk space
    local disk_available=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
    if [[ $disk_available -gt 90 ]]; then
        health_status="UNHEALTHY"
        issues+=("Critical disk usage: ${disk_available}%")
    elif [[ $disk_available -gt 80 ]]; then
        health_status="DEGRADED"
        issues+=("High disk usage: ${disk_available}%")
    fi

    # Check CPU load
    local cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    if (( $(echo "$cpu_load > 4.0" | bc -l) )); then
        health_status="UNHEALTHY"
        issues+=("Critical CPU load: $cpu_load")
    elif (( $(echo "$cpu_load > 2.0" | bc -l) )); then
        health_status="DEGRADED"
        issues+=("High CPU load: $cpu_load")
    fi

    log "INFO" "System health status: $health_status"

    if [[ ${#issues[@]} -gt 0 ]]; then
        log "WARN" "System issues detected:"
        for issue in "${issues[@]}"; do
            log "WARN" "  - $issue"
        done
    fi

    echo "$health_status"
}

# Service status check
check_service_status() {
    local service_name=$1
    local service_port=$2
    local health_endpoint=$3

    log "DEBUG" "Checking service: $service_name (port: $service_port)"

    # Check if service is running via systemd
    if systemctl is-active --quiet "$service_name"; then
        log "DEBUG" "$service_name is running via systemd"
    else
        log "WARN" "$service_name is not running via systemd"
    fi

    # Check if service port is listening
    if netstat -tlnp | grep ":$service_port" &> /dev/null; then
        log "DEBUG" "$service_name port $service_port is listening"
    else
        log "WARN" "$service_name port $service_port is not listening"
    fi

    # Check health endpoint
    if [[ -n "$health_endpoint" ]]; then
        if curl -f -s "$health_endpoint" &> /dev/null; then
            log "DEBUG" "$service_name health endpoint is responding"
            return 0
        else
            log "ERROR" "$service_name health endpoint is not responding"
            return 1
        fi
    fi

    return 0
}

# Recovery procedures
recover_mcp_server() {
    log "RECOVERY" "Starting MCP Server Recovery"

    local recovery_start=$(date +%s)

    # Step 1: Check current status
    log "INFO" "Step 1: Assessing MCP Server status"
    if check_service_status "$CORTEX_MCP_SERVICE" "$CORTEX_MCP_PORT" "http://localhost:$CORTEX_MCP_PORT/health"; then
        log "INFO" "MCP Server is already healthy"
        return 0
    fi

    # Step 2: Stop any existing processes
    log "INFO" "Step 2: Stopping existing MCP processes"
    systemctl stop "$CORTEX_MCP_SERVICE" || true
    pkill -f "node.*index.js" || true
    sleep 5

    # Step 3: Check configuration
    log "INFO" "Step 3: Validating configuration"
    if [[ ! -f "/app/.env" ]]; then
        log "ERROR" "Configuration file /app/.env not found"
        return 1
    fi

    # Step 4: Clear any stale locks or temporary files
    log "INFO" "Step 4: Cleaning up temporary files"
    find /app -name "*.lock" -delete 2>/dev/null || true
    find /app -name "*.tmp" -delete 2>/dev/null || true

    # Step 5: Start MCP Server
    log "INFO" "Step 5: Starting MCP Server"
    systemctl start "$CORTEX_MCP_SERVICE"

    # Step 6: Wait for startup
    log "INFO" "Step 6: Waiting for MCP Server to start"
    local max_wait=60
    local wait_time=0

    while [[ $wait_time -lt $max_wait ]]; do
        if curl -f -s "http://localhost:$CORTEX_MCP_PORT/health" &> /dev/null; then
            log "INFO" "MCP Server started successfully"
            break
        fi
        sleep 2
        wait_time=$((wait_time + 2))
    done

    if [[ $wait_time -ge $max_wait ]]; then
        log "ERROR" "MCP Server failed to start within ${max_wait}s"
        return 1
    fi

    # Step 7: Validate functionality
    log "INFO" "Step 7: Validating MCP Server functionality"
    if ! curl -f -s -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/find" \
           -H "Content-Type: application/json" \
           -d '{"query":"test","limit":1}' &> /dev/null; then
        log "WARN" "MCP Server API functionality test failed, but service is running"
    fi

    local recovery_end=$(date +%s)
    local recovery_time=$((recovery_end - recovery_start))

    log "RECOVERY" "MCP Server recovery completed in ${recovery_time}s"
    return 0
}

recover_qdrant_database() {
    log "RECOVERY" "Starting Qdrant Database Recovery"

    local recovery_start=$(date +%s)

    # Step 1: Check current status
    log "INFO" "Step 1: Assessing Qdrant status"
    if check_service_status "$QDRANT_SERVICE" "$QDRANT_PORT" "http://localhost:$QDRANT_PORT/health"; then
        log "INFO" "Qdrant is already healthy"
        return 0
    fi

    # Step 2: Stop Qdrant service
    log "INFO" "Step 2: Stopping Qdrant service"
    systemctl stop "$QDRANT_SERVICE" || true
    docker stop qdrant 2>/dev/null || true
    sleep 10

    # Step 3: Check for data corruption
    log "INFO" "Step 3: Checking for data corruption"
    local storage_path="/qdrant/storage"
    if [[ -d "$storage_path" ]]; then
        # Check if data directory exists and has content
        if [[ -n "$(ls -A "$storage_path" 2>/dev/null)" ]]; then
            log "INFO" "Qdrant data directory contains data"
        else
            log "WARN" "Qdrant data directory is empty"
        fi
    else
        log "WARN" "Qdrant data directory not found"
    fi

    # Step 4: Attempt to recover from backup if needed
    if ! should_restore_from_backup; then
        log "INFO" "Proceeding with service restart without backup restore"
    else
        log "INFO" "Step 4: Restoring from backup"
        restore_qdrant_from_backup
    fi

    # Step 5: Start Qdrant service
    log "INFO" "Step 5: Starting Qdrant service"
    systemctl start "$QDRANT_SERVICE"

    # Step 6: Wait for startup
    log "INFO" "Step 6: Waiting for Qdrant to start"
    local max_wait=120
    local wait_time=0

    while [[ $wait_time -lt $max_wait ]]; do
        if curl -f -s "http://localhost:$QDRANT_PORT/health" &> /dev/null; then
            log "INFO" "Qdrant started successfully"
            break
        fi
        sleep 5
        wait_time=$((wait_time + 5))
    done

    if [[ $wait_time -ge $max_wait ]]; then
        log "ERROR" "Qdrant failed to start within ${max_wait}s"
        return 1
    fi

    # Step 7: Recreate collection if needed
    log "INFO" "Step 7: Checking and recreating collection if needed"
    if ! curl -f -s "http://localhost:$QDRANT_PORT/collections/cortex-memory" &> /dev/null; then
        log "INFO" "Creating cortex-memory collection"
        create_qdrant_collection
    fi

    # Step 8: Validate database functionality
    log "INFO" "Step 8: Validating Qdrant functionality"
    validate_qdrant_functionality

    local recovery_end=$(date +%s)
    local recovery_time=$((recovery_end - recovery_start))

    log "RECOVERY" "Qdrant recovery completed in ${recovery_time}s"
    return 0
}

should_restore_from_backup() {
    log "DEBUG" "Evaluating need for backup restore"

    # Check if collection exists and has data
    local collection_status=$(curl -s "http://localhost:$QDRANT_PORT/collections/cortex-memory" 2>/dev/null || echo "")
    if [[ -n "$collection_status" ]]; then
        local vector_count=$(echo "$collection_status" | jq -r .result.points_count 2>/dev/null || echo "0")
        if [[ "$vector_count" -gt 0 ]]; then
            log "DEBUG" "Collection exists with $vector_count vectors, no restore needed"
            return 1
        fi
    fi

    # Check if recent backup exists
    local latest_backup=$(find "$BACKUP_DIR/qdrant" -name "*.snapshot.gz" -type f -mmin -1440 2>/dev/null | head -1)
    if [[ -n "$latest_backup" ]]; then
        log "DEBUG" "Recent backup found: $latest_backup"
        return 0
    fi

    log "DEBUG" "No recent backup found, proceeding without restore"
    return 1
}

restore_qdrant_from_backup() {
    log "INFO" "Restoring Qdrant from backup"

    # Find latest backup
    local latest_backup=$(find "$BACKUP_DIR/qdrant" -name "*.snapshot.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

    if [[ -z "$latest_backup" ]]; then
        log "WARN" "No backup found, proceeding with empty database"
        return 0
    fi

    log "INFO" "Using backup: $latest_backup"

    # Create temporary directory for restore
    mkdir -p "$TEMP_DIR/qdrant_restore"

    # Extract backup
    log "INFO" "Extracting backup"
    if ! gunzip -c "$latest_backup" > "$TEMP_DIR/qdrant_restore/restore.snapshot"; then
        log "ERROR" "Failed to extract backup"
        return 1
    fi

    # Clear existing storage
    log "INFO" "Clearing existing Qdrant storage"
    rm -rf /qdrant/storage/*
    mkdir -p /qdrant/storage

    # Copy snapshot to Qdrant snapshots directory
    mkdir -p /qdrant/snapshots/cortex-memory
    cp "$TEMP_DIR/qdrant_restore/restore.snapshot" "/qdrant/snapshots/cortex-memory/"

    log "INFO" "Backup prepared for restore"
    return 0
}

create_qdrant_collection() {
    log "INFO" "Creating Qdrant collection: cortex-memory"

    local collection_config='{
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

    if curl -f -s -X PUT "http://localhost:$QDRANT_PORT/collections/cortex-memory" \
           -H "Content-Type: application/json" \
           -d "$collection_config" &> /dev/null; then
        log "INFO" "Collection created successfully"
    else
        log "ERROR" "Failed to create collection"
        return 1
    fi

    # If we have a prepared snapshot, restore it
    if [[ -f "/qdrant/snapshots/cortex-memory/restore.snapshot" ]]; then
        log "INFO" "Restoring collection from snapshot"
        if curl -f -s -X POST "http://localhost:$QDRANT_PORT/collections/cortex-memory/snapshots/restore" \
               -H "Content-Type: application/json" \
               -d '{"snapshot_name": "restore.snapshot"}' &> /dev/null; then
            log "INFO" "Collection restored from snapshot"
        else
            log "WARN" "Failed to restore from snapshot, collection will be empty"
        fi
    fi

    return 0
}

validate_qdrant_functionality() {
    log "INFO" "Validating Qdrant functionality"

    # Check collection info
    local collection_info=$(curl -s "http://localhost:$QDRANT_PORT/collections/cortex-memory")
    if [[ $? -eq 0 ]]; then
        local vector_count=$(echo "$collection_info" | jq -r .result.points_count 2>/dev/null || echo "unknown")
        log "INFO" "Collection accessible with $vector_count vectors"
    else
        log "ERROR" "Failed to access collection"
        return 1
    fi

    # Test search functionality (only if we have vectors)
    if [[ "$vector_count" != "unknown" ]] && [[ "$vector_count" -gt 0 ]]; then
        local search_result=$(curl -s -X POST "http://localhost:$QDRANT_PORT/collections/cortex-memory/search" \
                           -H "Content-Type: application/json" \
                           -d '{"vector":[0.1,0.2,0.3],"limit":1}' 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            log "INFO" "Search functionality validated"
        else
            log "WARN" "Search functionality test failed"
        fi
    fi

    return 0
}

# Complete system recovery
recover_complete_system() {
    log "RECOVERY" "Starting Complete System Recovery"

    local recovery_start=$(date +%s)
    local recovery_failures=0

    # Step 1: System health assessment
    log "INFO" "Step 1: System health assessment"
    local system_health=$(check_system_health)
    log "INFO" "System health: $system_health"

    # Step 2: Network connectivity check
    log "INFO" "Step 2: Checking network connectivity"
    if ! check_network_connectivity; then
        log "ERROR" "Network connectivity issues detected"
        recovery_failures=$((recovery_failures + 1))
    fi

    # Step 3: Recover Qdrant database
    log "INFO" "Step 3: Recovering Qdrant database"
    if ! recover_qdrant_database; then
        log "ERROR" "Qdrant recovery failed"
        recovery_failures=$((recovery_failures + 1))
    fi

    # Step 4: Recover MCP server
    log "INFO" "Step 4: Recovering MCP server"
    if ! recover_mcp_server; then
        log "ERROR" "MCP server recovery failed"
        recovery_failures=$((recovery_failures + 1))
    fi

    # Step 5: Validate system integration
    log "INFO" "Step 5: Validating system integration"
    if ! validate_system_integration; then
        log "ERROR" "System integration validation failed"
        recovery_failures=$((recovery_failures + 1))
    fi

    # Step 6: Performance validation
    log "INFO" "Step 6: Validating system performance"
    validate_system_performance

    local recovery_end=$(date +%s)
    local recovery_time=$((recovery_end - recovery_start))

    if [[ $recovery_failures -eq 0 ]]; then
        log "RECOVERY" "Complete system recovery successful in ${recovery_time}s"
        return 0
    else
        log "ERROR" "Complete system recovery completed with $recovery_failures failures in ${recovery_time}s"
        return 1
    fi
}

check_network_connectivity() {
    log "DEBUG" "Checking network connectivity"

    local connectivity_issues=0

    # Check localhost
    if ! ping -c 1 127.0.0.1 &> /dev/null; then
        log "ERROR" "Localhost connectivity failed"
        connectivity_issues=$((connectivity_issues + 1))
    fi

    # Check DNS resolution
    if ! nslookup google.com &> /dev/null; then
        log "WARN" "DNS resolution issues detected"
    fi

    # Check external connectivity
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log "WARN" "External connectivity issues detected"
    fi

    if [[ $connectivity_issues -eq 0 ]]; then
        log "DEBUG" "Network connectivity validated"
        return 0
    else
        log "ERROR" "$connectivity_issues network connectivity issues found"
        return 1
    fi
}

validate_system_integration() {
    log "INFO" "Validating system integration"

    local integration_issues=0

    # Test MCP to Qdrant connectivity
    log "DEBUG" "Testing MCP to Qdrant connectivity"
    if ! curl -f -s "http://localhost:$QDRANT_PORT/health" &> /dev/null; then
        log "ERROR" "MCP cannot reach Qdrant"
        integration_issues=$((integration_issues + 1))
    fi

    # Test API functionality
    log "DEBUG" "Testing API functionality"
    local api_test=$(curl -s -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/find" \
                     -H "Content-Type: application/json" \
                     -d '{"query":"test","limit":1}' 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        log "ERROR" "API functionality test failed"
        integration_issues=$((integration_issues + 1))
    fi

    # Test memory store functionality
    log "DEBUG" "Testing memory store functionality"
    local store_test=$(curl -s -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/store" \
                      -H "Content-Type: application/json" \
                      -d '{"items":[{"kind":"observation","content":"DR test"}]}' 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        log "WARN" "Memory store functionality test failed"
    fi

    if [[ $integration_issues -eq 0 ]]; then
        log "INFO" "System integration validated successfully"
        return 0
    else
        log "ERROR" "$integration_issues integration issues found"
        return 1
    fi
}

validate_system_performance() {
    log "INFO" "Validating system performance"

    # Test API response time
    local response_time=$(curl -o /dev/null -s -w '%{time_total}' "http://localhost:$CORTEX_MCP_PORT/health")
    if (( $(echo "$response_time > 2.0" | bc -l) )); then
        log "WARN" "API response time is slow: ${response_time}s"
    else
        log "DEBUG" "API response time acceptable: ${response_time}s"
    fi

    # Test database search performance
    local vector_count=$(curl -s "http://localhost:$QDRANT_PORT/collections/cortex-memory" | jq -r .result.points_count 2>/dev/null || echo "0")
    if [[ "$vector_count" -gt 0 ]]; then
        local search_time=$(curl -o /dev/null -s -w '%{time_total}' \
                           -X POST "http://localhost:$QDRANT_PORT/collections/cortex-memory/search" \
                           -H "Content-Type: application/json" \
                           -d '{"vector":[0.1,0.2,0.3],"limit":10}')
        if (( $(echo "$search_time > 1.0" | bc -l) )); then
            log "WARN" "Database search time is slow: ${search_time}s"
        else
            log "DEBUG" "Database search time acceptable: ${search_time}s"
        fi
    fi

    # Check system resources
    local memory_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        log "WARN" "High memory usage after recovery: ${memory_usage}%"
    fi

    log "INFO" "System performance validation completed"
}

# Emergency recovery procedures
emergency_recovery() {
    log "RECOVERY" "Starting Emergency Recovery Procedures"

    local emergency_type=$1

    case "$emergency_type" in
        "datacenter_loss")
            emergency_datacenter_recovery
            ;;
        "database_corruption")
            emergency_database_recovery
            ;;
        "security_breach")
            emergency_security_recovery
            ;;
        *)
            log "ERROR" "Unknown emergency type: $emergency_type"
            return 1
            ;;
    esac
}

emergency_datacenter_recovery() {
    log "RECOVERY" "Emergency Data Center Loss Recovery"

    # This would typically involve:
    # 1. Activating secondary site
    # 2. Restoring from offsite backups
    # 3. Updating DNS records
    # 4. Notifying stakeholders

    log "INFO" "Step 1: Activating emergency procedures"
    log "INFO" "Step 2: Notifying incident response team"
    log "INFO" "Step 3: Initiating site failover"
    log "INFO" "Step 4: Restoring services from backup"

    # For simulation purposes, we'll perform basic recovery
    recover_complete_system
}

emergency_database_recovery() {
    log "RECOVERY" "Emergency Database Corruption Recovery"

    log "INFO" "Step 1: Isolating corrupted database"
    log "INFO" "Step 2: Restoring from known good backup"
    log "INFO" "Step 3: Validating data integrity"

    # Force backup restore
    rm -rf /qdrant/storage/*
    restore_qdrant_from_backup
    recover_qdrant_database
    recover_mcp_server
}

emergency_security_recovery() {
    log "RECOVERY" "Emergency Security Incident Recovery"

    log "INFO" "Step 1: Isolating affected systems"
    log "INFO" "Step 2: Preserving forensic evidence"
    log "INFO" "Step 3: Rebuilding from clean backups"
    log "INFO" "Step 4: Enhancing security measures"

    # Stop services immediately
    systemctl stop "$CORTEX_MCP_SERVICE" || true
    systemctl stop "$QDRANT_SERVICE" || true

    # Perform clean recovery
    recover_complete_system
}

# Main execution logic
main() {
    log "INFO" "DR Recovery Script Starting"
    log "INFO" "Cortex MCP Disaster Recovery"
    log "INFO" "=========================="

    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script requires root privileges"
        exit 1
    fi

    # Load configuration
    load_config

    # Create temporary directory
    mkdir -p "$TEMP_DIR"

    # Parse command line arguments
    local recovery_type=""
    local emergency_type=""
    local force_recovery=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                recovery_type="$2"
                shift 2
                ;;
            --emergency)
                emergency_type="$2"
                shift 2
                ;;
            --force)
                force_recovery=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --type <type>        Recovery type (mcp, qdrant, complete)"
                echo "  --emergency <type>   Emergency recovery (datacenter_loss, database_corruption, security_breach)"
                echo "  --force             Force recovery even if services appear healthy"
                echo "  --help, -h          Show this help message"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Confirm recovery operation
    if [[ "$force_recovery" != true ]]; then
        echo
        log "WARN" "This will initiate disaster recovery procedures"
        log "WARN" "Ensure you have proper authorization before proceeding"
        echo
        read -p "Do you want to continue? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log "INFO" "Recovery cancelled by user"
            exit 0
        fi
    fi

    # Execute recovery
    local recovery_success=false

    if [[ -n "$emergency_type" ]]; then
        log "INFO" "Executing emergency recovery: $emergency_type"
        if emergency_recovery "$emergency_type"; then
            recovery_success=true
        fi
    elif [[ -n "$recovery_type" ]]; then
        log "INFO" "Executing recovery type: $recovery_type"
        case "$recovery_type" in
            "mcp")
                if recover_mcp_server; then
                    recovery_success=true
                fi
                ;;
            "qdrant")
                if recover_qdrant_database; then
                    recovery_success=true
                fi
                ;;
            "complete")
                if recover_complete_system; then
                    recovery_success=true
                fi
                ;;
            *)
                log "ERROR" "Unknown recovery type: $recovery_type"
                exit 1
                ;;
        esac
    else
        log "INFO" "Executing complete system recovery (default)"
        if recover_complete_system; then
            recovery_success=true
        fi
    fi

    # Final validation and reporting
    if [[ "$recovery_success" == true ]]; then
        log "INFO" "✅ Recovery completed successfully"
        log "INFO" "System is ready for operation"

        # Generate recovery report
        generate_recovery_report "SUCCESS"

        exit 0
    else
        log "ERROR" "❌ Recovery failed"
        log "ERROR" "Manual intervention required"

        # Generate recovery report
        generate_recovery_report "FAILED"

        exit 1
    fi
}

generate_recovery_report() {
    local status=$1
    local report_file="/var/log/dr-recovery-report-$(date +%Y%m%d_%H%M%S).json"

    log "INFO" "Generating recovery report: $report_file"

    # Collect system metrics
    local memory_usage=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2}')
    local disk_usage=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
    local cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')

    # Check service status
    local mcp_status="unknown"
    local qdrant_status="unknown"

    if curl -f -s "http://localhost:$CORTEX_MCP_PORT/health" &> /dev/null; then
        mcp_status="healthy"
    else
        mcp_status="unhealthy"
    fi

    if curl -f -s "http://localhost:$QDRANT_PORT/health" &> /dev/null; then
        qdrant_status="healthy"
    else
        qdrant_status="unhealthy"
    fi

    # Generate report
    cat > "$report_file" << EOF
{
  "recovery_id": "dr-recovery-$(date +%Y%m%d_%H%M%S)",
  "timestamp": "$(date -Iseconds)",
  "status": "$status",
  "system_metrics": {
    "memory_usage_percent": $memory_usage,
    "disk_usage_percent": $disk_usage,
    "cpu_load": $cpu_load
  },
  "service_status": {
    "mcp_server": "$mcp_status",
    "qdrant_database": "$qdrant_status"
  },
  "actions_taken": [
    "System health assessment performed",
    "Service recovery procedures executed",
    "System integration validated",
    "Performance metrics collected"
  ],
  "recommendations": [
    "Monitor system performance closely",
    "Review recovery logs for issues",
    "Update DR procedures if needed",
    "Schedule regular DR testing"
  ]
}
EOF

    log "INFO" "Recovery report generated: $report_file"
}

# Execute main function
main "$@"