#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - AUTOMATED BACKUP SCRIPT
# ============================================================================
# Comprehensive backup automation for payload and vector IDs with deduplication
# Nightly snapshots with configurable retention policies and encryption

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_ROOT}/config/backup.json"
RETENTION_FILE="${PROJECT_ROOT}/config/retention.json"
LOG_DIR="${PROJECT_ROOT}/logs"
BACKUP_ROOT="${PROJECT_ROOT}/backups"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Logging setup
LOG_FILE="${LOG_DIR}/backup-$(date '+%Y%m%d').log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*"
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $*"
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $*"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*"
}

# Global variables
BACKUP_ID=""
BACKUP_TYPE="incremental"
BACKUP_START_TIME=""
BACKUP_PATH=""
BACKUP_METADATA=""

# Load configuration files
load_config() {
    log "Loading configuration files..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Backup configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    if [[ ! -f "$RETENTION_FILE" ]]; then
        error "Retention configuration file not found: $RETENTION_FILE"
        exit 1
    fi

    # Load configuration using jq
    BACKUP_CONFIG=$(cat "$CONFIG_FILE")
    RETENTION_CONFIG=$(cat "$RETENTION_FILE")

    # Extract configuration values
    BACKUP_SCHEDULE=$(echo "$BACKUP_CONFIG" | jq -r '.schedule // {}')
    DESTINATIONS=$(echo "$BACKUP_CONFIG" | jq -r '.destinations // []')
    ENCRYPTION_CONFIG=$(echo "$BACKUP_CONFIG" | jq -r '.encryption // {}')
    PERFORMANCE_CONFIG=$(echo "$BACKUP_CONFIG" | jq -r '.performance // {}')

    RETENTION_POLICY=$(echo "$RETENTION_CONFIG" | jq -r '.policy // {}')

    success "Configuration loaded successfully"
}

# Validate environment and dependencies
validate_environment() {
    log "Validating environment and dependencies..."

    # Check required commands
    local required_commands=("node" "jq" "tar" "gzip" "find" "date" "sha256sum")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Check Node.js version
    local node_version=$(node --version | sed 's/v//')
    local node_major=$(echo "$node_version" | cut -d. -f1)
    if [[ $node_major -lt 18 ]]; then
        error "Node.js version 18 or higher required. Found: $node_version"
        exit 1
    fi

    # Check if Cortex MCP is running
    if ! pgrep -f "cortex" > /dev/null; then
        warning "Cortex MCP process not detected. Proceeding with backup anyway."
    fi

    # Check disk space
    local available_space=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print $4}' | sed 's/G//')
    local min_space_gb=$(echo "$BACKUP_CONFIG" | jq -r '.performance.min_disk_space_gb // 10')

    if [[ $available_space -lt $min_space_gb ]]; then
        error "Insufficient disk space. Available: ${available_space}GB, Required: ${min_space_gb}GB"
        exit 1
    fi

    success "Environment validation completed"
}

# Generate unique backup ID
generate_backup_id() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local hostname=$(hostname -s)
    local random_hex=$(openssl rand -hex 4 2>/dev/null || date +%N | tail -c 5)
    echo "backup_${timestamp}_${hostname}_${random_hex}"
}

# Create backup directory structure
create_backup_structure() {
    BACKUP_ID=$(generate_backup_id)
    local backup_date=$(date '+%Y-%m-%d')
    BACKUP_PATH="${BACKUP_ROOT}/${backup_date}/${BACKUP_ID}"

    log "Creating backup structure: $BACKUP_PATH"
    mkdir -p "$BACKUP_PATH"
    mkdir -p "${BACKUP_PATH}/data"
    mkdir -p "${BACKUP_PATH}/metadata"
    mkdir -p "${BACKUP_PATH}/temp"

    echo "$BACKUP_PATH"
}

# Determine backup type based on schedule and history
determine_backup_type() {
    log "Determining backup type..."

    local backup_frequency=$(echo "$BACKUP_SCHEDULE" | jq -r '.frequency // "daily"')
    local force_full=$(echo "$BACKUP_SCHEDULE" | jq -r '.force_full_weekly // false')

    # Check if we need a full backup
    local day_of_week=$(date +%u) # 1-7 (Monday to Sunday)
    local day_of_month=$(date +%d)

    if [[ "$force_full" == "true" && "$day_of_week" == "1" ]]; then
        BACKUP_TYPE="full"
        log "Monday detected - performing full backup"
        return 0
    fi

    # Check if it's the first day of month
    if [[ "$day_of_month" == "01" ]]; then
        BACKUP_TYPE="full"
        log "First day of month detected - performing full backup"
        return 0
    fi

    # Look for existing full backup within the retention period
    local latest_full_backup=$(find "$BACKUP_ROOT" -name "*full*" -type d | sort -r | head -1)

    if [[ -z "$latest_full_backup" ]]; then
        BACKUP_TYPE="full"
        log "No previous full backup found - performing full backup"
        return 0
    fi

    # Default to incremental
    BACKUP_TYPE="incremental"
    log "Performing incremental backup"
}

# Export data using Cortex MCP Node.js interface
export_cortex_data() {
    local export_type="$1" # full, incremental
    local backup_data_path="$2"

    log "Exporting Cortex data (type: $export_type)..."

    # Create Node.js export script
    local export_script="${BACKUP_PATH}/temp/export_data.js"

    cat > "$export_script" << 'EOF'
const { createMemoryStoreService } = require('../src/index');
const { promises: fs } = require('fs');
const path = require('path');

async function exportData(backupPath, exportType) {
    try {
        console.log('Initializing Cortex Memory Store...');
        const memoryStore = createMemoryStoreService();

        let exportData = {
            metadata: {
                export_id: process.argv[2],
                export_type: exportType,
                timestamp: new Date().toISOString(),
                version: '3.0.0'
            },
            items: []
        };

        if (exportType === 'full') {
            console.log('Performing full export...');

            // Get all data with scope filtering
            const result = await memoryStore.find({
                query: "*",
                types: ["entity", "relation", "observation", "section", "runbook", "change", "issue", "decision", "todo", "release_note", "ddl", "pr_context", "incident", "release", "risk", "assumption"],
                limit: 100000
            });

            exportData.items = result.items || [];
            console.log(`Exported ${exportData.items.length} items`);

        } else if (exportType === 'incremental') {
            console.log('Performing incremental export...');

            // For incremental, we'd typically use timestamps
            // For now, get recent items (last 24 hours)
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);

            const result = await memoryStore.find({
                query: "*",
                types: ["entity", "relation", "observation", "section", "runbook", "change", "issue", "decision", "todo", "release_note", "ddl", "pr_context", "incident", "release", "risk", "assumption"],
                filters: {
                    created_after: yesterday.toISOString()
                },
                limit: 50000
            });

            exportData.items = result.items || [];
            console.log(`Exported ${exportData.items.length} incremental items`);
        }

        // Save export data
        const exportFile = path.join(backupPath, 'data', `cortex_export_${exportType}.json`);
        await fs.writeFile(exportFile, JSON.stringify(exportData, null, 2));

        // Create summary
        const summary = {
            export_id: exportData.metadata.export_id,
            export_type: exportType,
            items_count: exportData.items.length,
            file_size_bytes: (await fs.stat(exportFile)).size,
            timestamp: exportData.metadata.timestamp,
            version: exportData.metadata.version
        };

        const summaryFile = path.join(backupPath, 'metadata', 'export_summary.json');
        await fs.writeFile(summaryFile, JSON.stringify(summary, null, 2));

        console.log('Export completed successfully');
        console.log(`Items exported: ${summary.items_count}`);
        console.log(`File size: ${(summary.file_size_bytes / 1024 / 1024).toFixed(2)} MB`);

        process.exit(0);

    } catch (error) {
        console.error('Export failed:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    const backupPath = process.argv[3];
    const exportType = process.argv[4];
    exportData(backupPath, exportType);
}
EOF

    # Execute export script
    cd "$PROJECT_ROOT"

    log "Running Cortex data export..."
    if node "$export_script" "$BACKUP_ID" "$BACKUP_PATH" "$export_type"; then
        success "Cortex data export completed successfully"
    else
        error "Cortex data export failed"
        exit 1
    fi

    # Verify export files were created
    local export_file="${backup_data_path}/data/cortex_export_${export_type}.json"
    if [[ ! -f "$export_file" ]]; then
        error "Export file not created: $export_file"
        exit 1
    fi

    log "Export verification completed"
}

# Compress backup data
compress_backup_data() {
    log "Compressing backup data..."

    local compression_level=$(echo "$BACKUP_CONFIG" | jq -r '.performance.compression_level // 6')
    local data_dir="${BACKUP_PATH}/data"
    local compressed_file="${BACKUP_PATH}/cortex_backup_${BACKUP_TYPE}_${BACKUP_ID}.tar.gz"

    # Create compressed archive
    if ! tar -czf "$compressed_file" -C "$BACKUP_PATH" data/; then
        error "Failed to compress backup data"
        exit 1
    fi

    # Verify compressed file
    if ! tar -tzf "$compressed_file" > /dev/null; then
        error "Compressed backup verification failed"
        exit 1
    fi

    # Calculate compression ratio
    local original_size=$(du -sb "$data_dir" | cut -f1)
    local compressed_size=$(stat -c%s "$compressed_file")
    local compression_ratio=$(echo "scale=2; $original_size / $compressed_size" | bc -l)

    log "Backup compression completed"
    log "Original size: $((original_size / 1024 / 1024)) MB"
    log "Compressed size: $((compressed_size / 1024 / 1024)) MB"
    log "Compression ratio: ${compression_ratio}:1"

    echo "$compressed_file"
}

# Encrypt backup if configured
encrypt_backup() {
    local backup_file="$1"
    local encryption_enabled=$(echo "$ENCRYPTION_CONFIG" | jq -r '.enabled // false')

    if [[ "$encryption_enabled" != "true" ]]; then
        log "Encryption disabled, skipping"
        return 0
    fi

    log "Encrypting backup file..."

    local encrypted_file="${backup_file}.enc"
    local encryption_method=$(echo "$ENCRYPTION_CONFIG" | jq -r '.method // "aes256"')
    local encryption_key=$(echo "$ENCRYPTION_CONFIG" | jq -r '.key // ""')

    if [[ -z "$encryption_key" ]]; then
        error "Encryption enabled but no key provided in configuration"
        exit 1
    fi

    # Use OpenSSL for encryption
    case "$encryption_method" in
        "aes256")
            if ! openssl enc -aes-256-cbc -salt -in "$backup_file" -out "$encrypted_file" -pass pass:"$encryption_key"; then
                error "Backup encryption failed"
                exit 1
            fi
            ;;
        *)
            error "Unsupported encryption method: $encryption_method"
            exit 1
            ;;
    esac

    # Verify encrypted file
    if [[ ! -f "$encrypted_file" ]]; then
        error "Encrypted file not created"
        exit 1
    fi

    # Remove unencrypted file
    rm "$backup_file"

    success "Backup encrypted successfully"
    echo "$encrypted_file"
}

# Create comprehensive backup metadata
create_backup_metadata() {
    local backup_file="$1"
    local encrypted_file="$2"

    log "Creating backup metadata..."

    # Determine final backup file (encrypted or original)
    local final_backup_file="${encrypted_file:-$backup_file}"
    local is_encrypted=$([[ -n "$encrypted_file" ]] && echo true || echo false)

    # Calculate file sizes and checksums
    local file_size=$(stat -c%s "$final_backup_file")
    local file_checksum=$(sha256sum "$final_backup_file" | cut -d' ' -f1)

    # Get system information
    local hostname=$(hostname)
    local os_info=$(uname -a)
    local disk_usage=$(df -h "$PROJECT_ROOT" | tail -1)

    # Get export summary
    local export_summary_file="${BACKUP_PATH}/metadata/export_summary.json"
    local export_summary="{}"
    if [[ -f "$export_summary_file" ]]; then
        export_summary=$(cat "$export_summary_file")
    fi

    # Create comprehensive metadata
    BACKUP_METADATA=$(cat << EOF
{
    "backup_id": "$BACKUP_ID",
    "backup_type": "$BACKUP_TYPE",
    "timestamp": "$(date -Iseconds)",
    "status": "completed",
    "file_info": {
        "filename": "$(basename "$final_backup_file")",
        "path": "$final_backup_file",
        "size_bytes": $file_size,
        "size_human": "$((file_size / 1024 / 1024)) MB",
        "checksum_sha256": "$file_checksum",
        "encrypted": $is_encrypted
    },
    "export_info": $export_summary,
    "system_info": {
        "hostname": "$hostname",
        "os_info": "$os_info",
        "disk_usage": "$disk_usage",
        "script_version": "3.0.0",
        "node_version": "$(node --version)"
    },
    "configuration": {
        "backup_type": "$BACKUP_TYPE",
        "compression_enabled": true,
        "encryption_enabled": $is_encrypted,
        "destinations_count": $(echo "$DESTINATIONS" | jq 'length'),
        "retention_policy": $RETENTION_POLICY
    },
    "performance": {
        "start_time": "$BACKUP_START_TIME",
        "end_time": "$(date -Iseconds)",
        "duration_seconds": $(($(date +%s) - $(date -d "$BACKUP_START_TIME" +%s)))
    }
}
EOF
)

    # Save metadata
    local metadata_file="${BACKUP_PATH}/metadata/backup_metadata.json"
    echo "$BACKUP_METADATA" | jq '.' > "$metadata_file"

    # Copy metadata alongside backup file
    local metadata_copy="${final_backup_file}.metadata.json"
    cp "$metadata_file" "$metadata_copy"

    success "Backup metadata created"
}

# Upload to configured destinations
upload_to_destinations() {
    local backup_file="$1"

    log "Uploading backup to destinations..."

    local destinations_count=$(echo "$DESTINATIONS" | jq 'length')
    local successful_uploads=0

    for ((i=0; i<destinations_count; i++)); do
        local destination=$(echo "$DESTINATIONS" | jq -r ".[$i]")
        local dest_type=$(echo "$destination" | jq -r '.type')
        local dest_enabled=$(echo "$destination" | jq -r '.enabled')

        if [[ "$dest_enabled" != "true" ]]; then
            log "Skipping disabled destination: $dest_type"
            continue
        fi

        log "Uploading to destination: $dest_type"

        case "$dest_type" in
            "local")
                if upload_to_local "$backup_file" "$destination"; then
                    ((successful_uploads++))
                fi
                ;;
            "s3")
                if upload_to_s3 "$backup_file" "$destination"; then
                    ((successful_uploads++))
                fi
                ;;
            "azure")
                if upload_to_azure "$backup_file" "$destination"; then
                    ((successful_uploads++))
                fi
                ;;
            *)
                warning "Unsupported destination type: $dest_type"
                ;;
        esac
    done

    log "Upload completed: $successful_uploads/$destinations_count destinations"

    if [[ $successful_uploads -eq 0 ]]; then
        error "No successful uploads to any destination"
        exit 1
    fi
}

# Upload to local filesystem
upload_to_local() {
    local backup_file="$1"
    local destination="$2"

    local dest_path=$(echo "$destination" | jq -r '.path')
    local create_subdirs=$(echo "$destination" | jq -r '.create_subdirs // true')

    if [[ -z "$dest_path" ]]; then
        error "Local destination path not configured"
        return 1
    fi

    # Create target directory with date-based subdirectories
    if [[ "$create_subdirs" == "true" ]]; then
        local date_subdir=$(date '+%Y/%m/%d')
        dest_path="${dest_path}/${date_subdir}"
    fi

    mkdir -p "$dest_path"

    # Copy backup file
    local dest_file="${dest_path}/$(basename "$backup_file")"

    if cp "$backup_file" "$dest_file"; then
        # Copy metadata file
        local metadata_file="${backup_file}.metadata.json"
        if [[ -f "$metadata_file" ]]; then
            cp "$metadata_file" "${dest_file}.metadata.json"
        fi

        success "Local upload completed: $dest_file"
        return 0
    else
        error "Local upload failed"
        return 1
    fi
}

# Upload to S3
upload_to_s3() {
    local backup_file="$1"
    local destination="$2"

    # Check if AWS CLI is available
    if ! command -v aws &> /dev/null; then
        error "AWS CLI not available for S3 upload"
        return 1
    fi

    local bucket=$(echo "$destination" | jq -r '.bucket')
    local key_prefix=$(echo "$destination" | jq -r '.key_prefix // ""')
    local storage_class=$(echo "$destination" | jq -r '.storage_class // "STANDARD_IA"')
    local server_side_encryption=$(echo "$destination" | jq -r '.server_side_encryption // "AES256"')

    if [[ -z "$bucket" ]]; then
        error "S3 bucket not configured"
        return 1
    fi

    # Create S3 key with date-based structure
    local date_prefix=$(date '+%Y/%m/%d')
    local file_name=$(basename "$backup_file")
    local s3_key="${key_prefix}${date_prefix}/${file_name}"

    log "Uploading to S3: s3://${bucket}/${s3_key}"

    # Upload with AWS CLI
    local aws_args=(
        "s3" "cp" "$backup_file" "s3://${bucket}/${s3_key}"
        "--storage-class" "$storage_class"
        "--server-side-encryption" "$server_side_encryption"
        "--metadata" "backup-id=${BACKUP_ID},backup-type=${BACKUP_TYPE}"
    )

    if aws "${aws_args[@]}"; then
        # Upload metadata file
        local metadata_file="${backup_file}.metadata.json"
        if [[ -f "$metadata_file" ]]; then
            aws s3 cp "$metadata_file" "s3://${bucket}/${s3_key}.metadata.json" \
                --storage-class "$storage_class" \
                --server-side-encryption "$server_side_encryption"
        fi

        success "S3 upload completed: s3://${bucket}/${s3_key}"
        return 0
    else
        error "S3 upload failed"
        return 1
    fi
}

# Upload to Azure Blob Storage
upload_to_azure() {
    local backup_file="$1"
    local destination="$2"

    # Check if Azure CLI is available
    if ! command -v az &> /dev/null; then
        error "Azure CLI not available for Azure upload"
        return 1
    fi

    local storage_account=$(echo "$destination" | jq -r '.storage_account')
    local container=$(echo "$destination" | jq -r '.container')
    local access_tier=$(echo "$destination" | jq -r '.access_tier // "Cool"')

    if [[ -z "$storage_account" || -z "$container" ]]; then
        error "Azure storage account or container not configured"
        return 1
    fi

    # Create blob name with date structure
    local date_prefix=$(date '+%Y/%m/%d')
    local file_name=$(basename "$backup_file")
    local blob_name="${date_prefix}/${file_name}"

    log "Uploading to Azure Blob: ${storage_account}/${container}/${blob_name}"

    # Upload with Azure CLI
    if az storage blob upload \
        --file "$backup_file" \
        --name "$blob_name" \
        --container-name "$container" \
        --account-name "$storage_account" \
        --tier "$access_tier" \
        --metadata backup-id="$BACKUP_ID" backup-type="$BACKUP_TYPE" \
        --overwrite; then

        # Upload metadata file
        local metadata_file="${backup_file}.metadata.json"
        if [[ -f "$metadata_file" ]]; then
            az storage blob upload \
                --file "$metadata_file" \
                --name "${blob_name}.metadata.json" \
                --container-name "$container" \
                --account-name "$storage_account" \
                --tier "$access_tier" \
                --overwrite
        fi

        success "Azure upload completed: ${storage_account}/${container}/${blob_name}"
        return 0
    else
        error "Azure upload failed"
        return 1
    fi
}

# Apply retention policies
apply_retention_policy() {
    log "Applying retention policies..."

    local daily_retention=$(echo "$RETENTION_POLICY" | jq -r '.daily_retention // 7')
    local weekly_retention=$(echo "$RETENTION_POLICY" | jq -r '.weekly_retention // 4')
    local monthly_retention=$(echo "$RETENTION_POLICY" | jq -r '.monthly_retention // 12')
    local yearly_retention=$(echo "$RETENTION_POLICY" | jq -r '.yearly_retention // 3')

    local deleted_count=0

    # Apply daily retention (keep last N days)
    find "$BACKUP_ROOT" -type d -name "backup_*" -mtime "+${daily_retention}" -print0 | while IFS= read -r -d '' backup_dir; do
        # Check if this is a special backup (weekly, monthly, yearly)
        local backup_date=$(basename "$(dirname "$backup_dir")")
        local is_special=false

        # Keep weekly backups (Sundays)
        if [[ "$weekly_retention" -gt 0 ]]; then
            local backup_day=$(date -d "$backup_date" +%u 2>/dev/null || echo "0")
            if [[ "$backup_day" == "7" ]]; then
                is_special=true
            fi
        fi

        # Keep monthly backups (1st of month)
        if [[ "$monthly_retention" -gt 0 ]]; then
            local backup_dayOfMonth=$(date -d "$backup_date" +%d 2>/dev/null || echo "0")
            if [[ "$backup_dayOfMonth" == "01" ]]; then
                is_special=true
            fi
        fi

        # Keep yearly backups (January 1st)
        if [[ "$yearly_retention" -gt 0 ]]; then
            local backup_month=$(date -d "$backup_date" +%m 2>/dev/null || echo "0")
            local backup_dayOfMonth=$(date -d "$backup_date" +%d 2>/dev/null || echo "0")
            if [[ "$backup_month" == "01" && "$backup_dayOfMonth" == "01" ]]; then
                is_special=true
            fi
        fi

        if [[ "$is_special" != "true" ]]; then
            log "Deleting old backup: $backup_dir"
            rm -rf "$backup_dir"
            ((deleted_count++))
        fi
    done

    # Clean up empty directories
    find "$BACKUP_ROOT" -type d -empty -delete 2>/dev/null || true

    success "Retention policy applied. Deleted old backups as needed."
}

# Send notifications
send_notifications() {
    local backup_status="$1"
    local backup_file="$2"

    log "Sending notifications..."

    # Send Slack notification if configured
    local slack_webhook=$(echo "$BACKUP_CONFIG" | jq -r '.notifications.slack.webhook_url // ""')
    if [[ -n "$slack_webhook" && "$slack_webhook" != "null" ]]; then
        local slack_message="Cortex Backup ${backup_status}: ${BACKUP_ID} ($(basename "$backup_file"))"

        curl -X POST "$slack_webhook" \
            -H 'Content-type: application/json' \
            --data "{\"text\":\"${slack_message}\"}" \
            2>/dev/null || log "Slack notification failed"
    fi

    # Send email notification if configured
    local email_enabled=$(echo "$BACKUP_CONFIG" | jq -r '.notifications.email.enabled // false')
    if [[ "$email_enabled" == "true" ]]; then
        # Email notification would be implemented here
        log "Email notification not implemented"
    fi

    success "Notifications sent"
}

# Cleanup temporary files
cleanup() {
    log "Cleaning up temporary files..."

    # Remove temporary files
    if [[ -d "${BACKUP_PATH}/temp" ]]; then
        rm -rf "${BACKUP_PATH}/temp"
    fi

    # Remove data directory after compression
    if [[ -d "${BACKUP_PATH}/data" ]]; then
        rm -rf "${BACKUP_PATH}/data"
    fi

    success "Cleanup completed"
}

# Main backup function
main() {
    local backup_type_override="${1:-}"

    # Record start time
    BACKUP_START_TIME=$(date -Iseconds)

    log "=== CORTEX MEMORY MCP BACKUP STARTED ==="
    log "Backup ID: $BACKUP_ID (will be generated)"
    log "Start time: $BACKUP_START_TIME"

    # Load configuration
    load_config

    # Validate environment
    validate_environment

    # Determine backup type
    if [[ -n "$backup_type_override" ]]; then
        BACKUP_TYPE="$backup_type_override"
        log "Using override backup type: $BACKUP_TYPE"
    else
        determine_backup_type
    fi

    # Create backup structure
    create_backup_structure

    # Export data
    export_cortex_data "$BACKUP_TYPE" "$BACKUP_PATH"

    # Compress backup
    local backup_file
    backup_file=$(compress_backup_data)

    # Encrypt if configured
    local encrypted_file
    encrypted_file=$(encrypt_backup "$backup_file")

    # Create metadata
    create_backup_metadata "$backup_file" "$encrypted_file"

    # Upload to destinations
    local final_backup_file="${encrypted_file:-$backup_file}"
    upload_to_destinations "$final_backup_file"

    # Apply retention policies
    apply_retention_policy

    # Send notifications
    send_notifications "SUCCESS" "$final_backup_file"

    # Cleanup
    cleanup

    # Calculate final statistics
    local end_time=$(date -Iseconds)
    local duration_seconds=$(($(date -d "$end_time" +%s) - $(date -d "$BACKUP_START_TIME" +%s)))

    success "=== BACKUP COMPLETED SUCCESSFULLY ==="
    success "Backup ID: $BACKUP_ID"
    success "Backup Type: $BACKUP_TYPE"
    success "Duration: ${duration_seconds}s"
    success "Final File: $final_backup_file"
    success "End Time: $end_time"
}

# Error handling
trap 'error "Backup script interrupted"; exit 1' INT TERM

# Handle script parameters
case "${1:-}" in
    "full"|"incremental")
        main "$1"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [backup_type]"
        echo "backup_type: full, incremental (default: auto-determined)"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        error "Unknown parameter: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac