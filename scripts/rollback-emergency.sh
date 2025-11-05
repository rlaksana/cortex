#!/bin/bash
# Cortex Memory MCP - Emergency Rollback Script
# This script performs emergency rollback procedures

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="/backups"
LOG_FILE="/tmp/rollback-emergency.log"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    local status=$1
    local message=$2

    case $status in
        "OK")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "FAIL")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
    esac
}

# Check if running as root/sudo
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        print_status "WARN" "Running as root - be careful!"
    fi
}

# Create emergency backup
create_emergency_backup() {
    print_status "INFO" "Creating emergency backup..."

    local emergency_dir="$BACKUP_DIR/emergency-$TIMESTAMP"
    mkdir -p "$emergency_dir"

    # Backup current configuration
    if [ -f "$PROJECT_ROOT/.env" ]; then
        cp "$PROJECT_ROOT/.env" "$emergency_dir/.env.emergency"
        print_status "OK" "Backed up .env file"
    fi

    # Backup configuration files
    if [ -f "$PROJECT_ROOT/src/config/production-config.json" ]; then
        cp "$PROJECT_ROOT/src/config/production-config.json" "$emergency_dir/"
        print_status "OK" "Backed up production configuration"
    fi

    # Backup current git state
    cd "$PROJECT_ROOT"
    git rev-parse HEAD > "$emergency_dir/git-commit.emergency"
    git diff > "$emergency_dir/git-changes.emergency.diff" 2>/dev/null || true
    print_status "OK" "Backed up git state"

    # Backup Qdrant data
    if docker ps | grep -q qdrant; then
        docker exec cortex-qdrant qdrant-cli snapshot create --collection-name cortex-memory || true
        docker cp cortex-qdrant:/qdrant/snapshots "$emergency_dir/qdrant-snapshots" 2>/dev/null || true
        print_status "OK" "Backed up Qdrant snapshots"
    fi

    log "Emergency backup created at $emergency_dir"
    echo "$emergency_dir"
}

# Stop current services
stop_services() {
    print_status "INFO" "Stopping current services..."

    # Stop MCP server
    if systemctl is-active --quiet cortex-mcp 2>/dev/null; then
        sudo systemctl stop cortex-mcp
        print_status "OK" "Stopped Cortex MCP service"
    else
        print_status "WARN" "Cortex MCP service was not running"
    fi

    # Stop Qdrant
    if docker ps | grep -q qdrant; then
        cd "$PROJECT_ROOT"
        docker-compose -f docker/docker-compose.yml down qdrant
        print_status "OK" "Stopped Qdrant container"
    else
        print_status "WARN" "Qdrant container was not running"
    fi

    # Kill any remaining processes
    if pgrep -f "node.*cortex" > /dev/null; then
        sudo pkill -f "node.*cortex" || true
        print_status "OK" "Terminated remaining Cortex processes"
    fi
}

# Restore application from backup
restore_application() {
    local target_version=${1:-"v2.0.0"}

    print_status "INFO" "Restoring application to version $target_version..."

    cd "$PROJECT_ROOT"

    # Stash any uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        git stash push -m "Emergency rollback stash $TIMESTAMP"
        print_status "OK" "Stashed uncommitted changes"
    fi

    # Checkout target version
    if git checkout "$target_version"; then
        print_status "OK" "Checked out version $target_version"
    else
        print_status "FAIL" "Failed to checkout version $target_version"
        return 1
    fi

    # Clean and rebuild
    npm run clean:build
    npm run build

    print_status "OK" "Application restored to version $target_version"
}

# Restore database from backup
restore_database() {
    local backup_file=${1:-""}

    if [ -z "$backup_file" ]; then
        # Find latest backup
        backup_file=$(ls -t "$BACKUP_DIR/qdrant/qdrant-backup-"*.tar.gz 2>/dev/null | head -1)
    fi

    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        print_status "FAIL" "No Qdrant backup file found"
        return 1
    fi

    print_status "INFO" "Restoring database from $backup_file..."

    cd "$PROJECT_ROOT/docker"

    # Remove corrupted volume
    docker volume rm cortex-mcp_qdrant_data 2>/dev/null || true
    print_status "OK" "Removed corrupted Qdrant volume"

    # Restore from backup
    if tar -xzf "$backup_file" -C /var/lib/docker/volumes/; then
        print_status "OK" "Database restored from backup"
    else
        print_status "FAIL" "Failed to restore database from backup"
        return 1
    fi
}

# Restore configuration from backup
restore_configuration() {
    local backup_dir=${1:-""}

    if [ -z "$backup_dir" ]; then
        # Find latest config backup
        backup_dir=$(ls -t "$BACKUP_DIR/config" 2>/dev/null | head -1)
        backup_dir="$BACKUP_DIR/config/$backup_dir"
    fi

    if [ -z "$backup_dir" ] || [ ! -d "$backup_dir" ]; then
        print_status "FAIL" "No configuration backup directory found"
        return 1
    fi

    print_status "INFO" "Restoring configuration from $backup_dir..."

    # Restore .env file
    if [ -f "$backup_dir/.env.production" ]; then
        cp "$backup_dir/.env.production" "$PROJECT_ROOT/.env"
        print_status "OK" "Restored .env file"
    fi

    # Restore production configuration
    if [ -f "$backup_dir/production-config.json" ]; then
        cp "$backup_dir/production-config.json" "$PROJECT_ROOT/src/config/"
        print_status "OK" "Restored production configuration"
    fi

    # Validate configuration
    cd "$PROJECT_ROOT"
    if npm run prod:validate >/dev/null 2>&1; then
        print_status "OK" "Configuration validation passed"
    else
        print_status "WARN" "Configuration validation failed - manual review required"
    fi
}

# Start services
start_services() {
    print_status "INFO" "Starting services..."

    cd "$PROJECT_ROOT/docker"

    # Start Qdrant
    docker-compose up -d qdrant
    print_status "OK" "Started Qdrant container"

    # Wait for Qdrant to be ready
    print_status "INFO" "Waiting for Qdrant to be ready..."
    local max_wait=60
    local wait_time=0

    while [ $wait_time -lt $max_wait ]; do
        if curl -s http://localhost:6333/health >/dev/null 2>&1; then
            print_status "OK" "Qdrant is ready"
            break
        fi
        sleep 2
        wait_time=$((wait_time + 2))
    done

    if [ $wait_time -ge $max_wait ]; then
        print_status "FAIL" "Qdrant failed to become ready within $max_wait seconds"
        return 1
    fi

    # Start MCP server
    sudo systemctl start cortex-mcp
    print_status "OK" "Started Cortex MCP service"

    # Wait for MCP server to be ready
    print_status "INFO" "Waiting for MCP server to be ready..."
    max_wait=30
    wait_time=0

    while [ $wait_time -lt $max_wait ]; do
        if curl -s http://localhost:3000/health >/dev/null 2>&1; then
            print_status "OK" "MCP server is ready"
            break
        fi
        sleep 2
        wait_time=$((wait_time + 2))
    done

    if [ $wait_time -ge $max_wait ]; then
        print_status "FAIL" "MCP server failed to become ready within $max_wait seconds"
        return 1
    fi
}

# Verify rollback
verify_rollback() {
    print_status "INFO" "Verifying rollback..."

    # Run smoke test
    if "$SCRIPT_DIR/rollback-smoke-test.sh" >/dev/null 2>&1; then
        print_status "OK" "Rollback verification passed"
        return 0
    else
        print_status "FAIL" "Rollback verification failed"
        return 1
    fi
}

# Full rollback procedure
full_rollback() {
    local target_version=${1:-"v2.0.0"}

    print_status "INFO" "Starting full emergency rollback to version $target_version..."

    # Create emergency backup
    local emergency_backup
    emergency_backup=$(create_emergency_backup)

    # Stop services
    stop_services

    # Restore components
    if ! restore_application "$target_version"; then
        print_status "FAIL" "Failed to restore application"
        return 1
    fi

    if ! restore_database; then
        print_status "FAIL" "Failed to restore database"
        return 1
    fi

    if ! restore_configuration; then
        print_status "FAIL" "Failed to restore configuration"
        return 1
    fi

    # Start services
    if ! start_services; then
        print_status "FAIL" "Failed to start services"
        return 1
    fi

    # Verify rollback
    if verify_rollback; then
        print_status "OK" "Full rollback completed successfully"
        log "Full rollback to $target_version completed successfully"
        log "Emergency backup stored at: $emergency_backup"
        return 0
    else
        print_status "FAIL" "Rollback verification failed"
        log "Rollback verification failed - manual intervention required"
        return 1
    fi
}

# Database-only rollback
database_rollback() {
    local backup_file=${1:-""}

    print_status "INFO" "Starting database-only rollback..."

    # Create emergency backup
    create_emergency_backup

    # Stop services
    stop_services

    # Restore database only
    if ! restore_database "$backup_file"; then
        print_status "FAIL" "Failed to restore database"
        return 1
    fi

    # Start services
    if ! start_services; then
        print_status "FAIL" "Failed to start services"
        return 1
    fi

    # Verify rollback
    if verify_rollback; then
        print_status "OK" "Database rollback completed successfully"
        log "Database rollback completed successfully"
        return 0
    else
        print_status "FAIL" "Database rollback verification failed"
        return 1
    fi
}

# Configuration-only rollback
config_rollback() {
    local backup_dir=${1:-""}

    print_status "INFO" "Starting configuration-only rollback..."

    # Create emergency backup
    create_emergency_backup

    # Restore configuration only
    if ! restore_configuration "$backup_dir"; then
        print_status "FAIL" "Failed to restore configuration"
        return 1
    fi

    # Restart service
    sudo systemctl restart cortex-mcp
    print_status "OK" "Restarted Cortex MCP service"

    # Wait for service to be ready
    sleep 10

    # Verify rollback
    if verify_rollback; then
        print_status "OK" "Configuration rollback completed successfully"
        log "Configuration rollback completed successfully"
        return 0
    else
        print_status "FAIL" "Configuration rollback verification failed"
        return 1
    fi
}

# Show help
show_help() {
    echo "Cortex Memory MCP - Emergency Rollback Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  full [VERSION]        Perform full rollback to specified version (default: v2.0.0)"
    echo "  database [BACKUP]     Perform database-only rollback from backup file"
    echo "  config [BACKUP_DIR]   Perform configuration-only rollback from backup directory"
    echo "  backup                Create emergency backup only"
    echo "  verify                Verify current system state"
    echo ""
    echo "Options:"
    echo "  -h, --help            Show this help message"
    echo "  -v, --verbose         Enable verbose output"
    echo "  -l, --log FILE        Set log file path"
    echo ""
    echo "Examples:"
    echo "  $0 full v2.0.0                    # Full rollback to version 2.0.0"
    echo "  $0 database /backups/qdrant.tar.gz  # Database rollback from specific backup"
    echo "  $0 config /backups/config/20231105-120000  # Config rollback from backup"
    echo "  $0 backup                          # Create emergency backup only"
    echo ""
    echo "Exit Codes:"
    echo "  0    Success"
    echo "  1    Rollback failed"
    echo "  2    Invalid arguments"
    echo "  3    System error"
}

# Main function
main() {
    # Check privileges
    check_privileges

    # Parse arguments
    case "${1:-}" in
        "full")
            full_rollback "${2:-v2.0.0}"
            ;;
        "database")
            database_rollback "${2:-}"
            ;;
        "config")
            config_rollback "${2:-}"
            ;;
        "backup")
            create_emergency_backup
            ;;
        "verify")
            if verify_rollback; then
                print_status "OK" "System verification passed"
                exit 0
            else
                print_status "FAIL" "System verification failed"
                exit 1
            fi
            ;;
        "-h"|"--help"|"help"|"")
            show_help
            ;;
        *)
            print_status "FAIL" "Unknown command: $1"
            show_help
            exit 2
            ;;
    esac
}

# Run main function
main "$@"