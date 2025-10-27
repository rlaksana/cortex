#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - QDRANT VECTOR DATABASE BACKUP SCRIPT
# ============================================================================
# Comprehensive backup solution for Qdrant vector database with snapshots
# Supports local backups, S3 uploads, and retention management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../config/backup.conf"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Default configuration values
QDRANT_HOST="${QDRANT_HOST:-localhost}"
QDRANT_PORT="${QDRANT_PORT:-6333}"
QDRANT_API_KEY="${QDRANT_API_KEY:-}"
BACKUP_DIR="${BACKUP_DIR:-./backups/qdrant}"
S3_BUCKET="${S3_BUCKET:-cortex-mcp-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
ENCRYPT_BACKUP="${ENCRYPT_BACKUP:-true}"
GPG_RECIPIENT="${GPG_RECIPIENT:-backup@cortex-mcp.com}"
COLLECTIONS_TO_BACKUP="${COLLECTIONS_TO_BACKUP:-all}" # all, or comma-separated list
SNAPSHOT_TIMEOUT="${SNAPSHOT_TIMEOUT:-300}" # seconds
VERIFY_BACKUP="${VERIFY_BACKUP:-true}"

# Logging
LOG_FILE="${BACKUP_DIR}/backup.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    log "ERROR: $*"
    exit 1
}

success() {
    log "SUCCESS: $*"
}

check_dependencies() {
    local deps=("curl" "jq" "aws" "gpg" "find" "date" "tar")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' is not installed"
        fi
    done
}

check_qdrant_connection() {
    log "Checking Qdrant connection..."

    local url="http://${QDRANT_HOST}:${QDRANT_PORT}/health"
    local headers=()

    if [[ -n "$QDRANT_API_KEY" ]]; then
        headers+=("-H" "api-key: $QDRANT_API_KEY")
    fi

    if ! curl -s -f "${headers[@]}" "$url" > /dev/null; then
        error "Cannot connect to Qdrant at $url"
    fi

    success "Qdrant connection verified"
}

get_collection_list() {
    local url="http://${QDRANT_HOST}:${QDRANT_PORT}/collections"
    local headers=()

    if [[ -n "$QDRANT_API_KEY" ]]; then
        headers+=("-H" "api-key: $QDRANT_API_KEY")
    fi

    local collections_response
    if ! collections_response=$(curl -s "${headers[@]}" "$url"); then
        error "Failed to get collection list from Qdrant"
    fi

    if [[ "$COLLECTIONS_TO_BACKUP" == "all" ]]; then
        echo "$collections_response" | jq -r '.result.collections[].name' 2>/dev/null || \
            echo "$collections_response" | grep -o '"name":"[^"]*"' | cut -d'"' -f4
    else
        echo "$COLLECTIONS_TO_BACKUP" | tr ',' '\n'
    fi
}

create_backup_dir() {
    local backup_date=$(date '+%Y-%m-%d')
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    BACKUP_PATH="${BACKUP_DIR}/${backup_date}"
    BACKUP_FILE="cortex-qdrant-backup-${timestamp}"
    mkdir -p "$BACKUP_PATH"
    echo "$BACKUP_PATH/$BACKUP_FILE"
}

create_collection_snapshot() {
    local collection_name="$1"
    local backup_path="$2"

    log "Creating snapshot for collection: $collection_name"

    local url="http://${QDRANT_HOST}:${QDRANT_PORT}/collections/${collection_name}/snapshots"
    local headers=("-H" "Content-Type: application/json")

    if [[ -n "$QDRANT_API_KEY" ]]; then
        headers+=("-H" "api-key: $QDRANT_API_KEY")
    fi

    local snapshot_response
    if ! snapshot_response=$(curl -s -X POST "${headers[@]}" "$url"); then
        error "Failed to create snapshot for collection: $collection_name"
    fi

    local snapshot_name
    snapshot_name=$(echo "$snapshot_response" | jq -r '.result.name' 2>/dev/null || \
                   echo "$snapshot_response" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)

    if [[ -z "$snapshot_name" ]]; then
        error "No snapshot name returned for collection: $collection_name"
    fi

    log "Snapshot created: $snapshot_name"

    # Wait for snapshot to be created
    local snapshot_url="http://${QDRANT_HOST}:${QDRANT_PORT}/collections/${collection_name}/snapshots/${snapshot_name}"
    local wait_time=0

    while [[ $wait_time -lt $SNAPSHOT_TIMEOUT ]]; do
        if curl -s -f "${headers[@]}" "$snapshot_url" > /dev/null; then
            break
        fi
        log "Waiting for snapshot to be ready... (${wait_time}s/${SNAPSHOT_TIMEOUT}s)"
        sleep 5
        ((wait_time += 5))
    done

    if [[ $wait_time -ge $SNAPSHOT_TIMEOUT ]]; then
        error "Snapshot creation timeout for collection: $collection_name"
    fi

    # Download snapshot
    local download_url="http://${QDRANT_HOST}:${QDRANT_PORT}/collections/${collection_name}/snapshots/${snapshot_name}"
    local snapshot_file="${backup_path}_${collection_name}.snapshot"

    log "Downloading snapshot to: $snapshot_file"

    if ! curl -s -o "$snapshot_file" "${headers[@]}" "$download_url"; then
        error "Failed to download snapshot for collection: $collection_name"
    fi

    # Verify snapshot file
    if [[ ! -s "$snapshot_file" ]]; then
        error "Snapshot file is empty for collection: $collection_name"
    fi

    success "Snapshot downloaded: $snapshot_file"
    echo "$snapshot_file"
}

create_full_backup() {
    local backup_path="$1"
    local snapshot_files=()

    log "Starting full Qdrant backup..."

    # Get list of collections to backup
    local collections
    collections=$(get_collection_list)

    if [[ -z "$collections" ]]; then
        log "No collections found to backup"
        return 0
    fi

    # Create snapshots for each collection
    while IFS= read -r collection; do
        if [[ -n "$collection" ]]; then
            local snapshot_file
            snapshot_file=$(create_collection_snapshot "$collection" "$backup_path")
            snapshot_files+=("$snapshot_file")
        fi
    done <<< "$collections"

    # Create backup archive
    local archive_file="${backup_path}.tar.gz"
    log "Creating backup archive: $archive_file"

    # Create metadata file
    local metadata_file="${backup_path}.meta.json"
    create_backup_metadata "$snapshot_files" "$metadata_file"

    # Add metadata to archive
    snapshot_files+=("$metadata_file")

    # Create compressed archive
    if ! tar -czf "$archive_file" -C "$(dirname "${snapshot_files[0]}")" \
        $(basename "${snapshot_files[@]}"); then
        error "Failed to create backup archive"
    fi

    # Remove individual snapshot files
    for file in "${snapshot_files[@]}"; do
        rm "$file"
    done

    # Verify archive
    if ! tar -tzf "$archive_file" > /dev/null; then
        error "Backup archive verification failed"
    fi

    success "Full backup completed: $archive_file"
    echo "$archive_file"
}

create_incremental_backup() {
    local backup_path="$1"

    log "Starting incremental Qdrant backup..."

    # Find the most recent full backup
    local last_full_backup=$(find "$BACKUP_DIR" -name "*cortex-qdrant-backup*-full.tar.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

    if [[ -z "$last_full_backup" ]]; then
        log "No full backup found, performing full backup instead"
        create_full_backup "$backup_path"
        return 0
    fi

    log "Using base backup: $(basename "$last_full_backup")"

    # For incremental backup, we'll create snapshots of collections
    # that have been modified since the last backup
    local backup_file="${backup_path}-incremental.tar.gz"
    local snapshot_files=()

    # Get collections modified since last backup
    local last_backup_time=$(stat -c %Y "$last_full_backup" 2>/dev/null || stat -f %m "$last_full_backup")
    local collections
    collections=$(get_collection_list)

    while IFS= read -r collection; do
        if [[ -n "$collection" ]]; then
            # Check if collection has been modified (this is a simplified check)
            # In a real implementation, you'd check collection update timestamps
            local snapshot_file
            snapshot_file=$(create_collection_snapshot "$collection" "${backup_path}-${collection}")
            snapshot_files+=("$snapshot_file")
        fi
    done <<< "$collections"

    if [[ ${#snapshot_files[@]} -eq 0 ]]; then
        log "No changes detected, creating empty incremental backup"
        touch "${backup_path}-empty"
        snapshot_files+=("${backup_path}-empty")
    fi

    # Create incremental archive
    local metadata_file="${backup_path}.meta.json"
    create_backup_metadata "$snapshot_files" "$metadata_file"
    snapshot_files+=("$metadata_file")

    if ! tar -czf "$backup_file" -C "$(dirname "${snapshot_files[0]}")" \
        $(basename "${snapshot_files[@]}"); then
        error "Failed to create incremental backup archive"
    fi

    # Clean up temporary files
    for file in "${snapshot_files[@]}"; do
        rm "$file" 2>/dev/null || true
    done

    success "Incremental backup completed: $backup_file"
    echo "$backup_file"
}

compress_backup() {
    local backup_file="$1"
    # Backup is already compressed with tar.gz
    success "Backup already compressed: $backup_file"
}

encrypt_backup() {
    local backup_file="$1"
    local encrypted_file="${backup_file}.gpg"

    if [[ "$ENCRYPT_BACKUP" != "true" ]]; then
        return 0
    fi

    log "Encrypting backup file..."

    if ! gpg --batch --yes --encrypt --recipient "$GPG_RECIPIENT" --output "$encrypted_file" "$backup_file"; then
        error "Backup encryption failed"
    fi

    # Verify encrypted file
    if [[ ! -f "$encrypted_file" ]]; then
        error "Encrypted file not created"
    fi

    # Remove unencrypted backup
    rm "$backup_file"
    success "Backup encrypted successfully: $encrypted_file"
}

upload_to_s3() {
    local backup_file="$1"
    local s3_key="qdrant/$(date '+%Y/%m/%d')/$(basename "$backup_file")"

    if [[ -z "$S3_BUCKET" ]]; then
        log "S3 bucket not configured, skipping upload"
        return 0
    fi

    log "Uploading backup to S3: s3://$S3_BUCKET/$s3_key"

    local aws_opts=(
        "s3"
        "cp"
        "$backup_file"
        "s3://$S3_BUCKET/$s3_key"
        "--storage-class=STANDARD_IA"
        "--server-side-encryption=AES256"
    )

    # Add lifecycle configuration
    aws_opts+=("--metadata=backup-type=qdrant,created-date=$(date -Iseconds)")

    if ! aws "${aws_opts[@]}"; then
        error "S3 upload failed"
    fi

    # Verify upload
    if ! aws s3 ls "s3://$S3_BUCKET/$s3_key" &> /dev/null; then
        error "S3 upload verification failed"
    fi

    success "Backup uploaded to S3 successfully"
}

cleanup_old_backups() {
    log "Cleaning up old backups (retention: $RETENTION_DAYS days)..."

    # Clean local backups
    local deleted_count=0
    while IFS= read -r -d '' file; do
        log "Deleting old backup: $(basename "$file")"
        rm "$file"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR" -name "*cortex-qdrant-backup*" -type f -mtime "+$RETENTION_DAYS" -print0 2>/dev/null || true)

    # Clean empty directories
    find "$BACKUP_DIR" -type d -empty -delete 2>/dev/null || true

    success "Deleted $deleted_count old local backups"

    # Clean S3 backups if configured
    if [[ -n "$S3_BUCKET" ]]; then
        log "Cleaning up old S3 backups..."
        local cutoff_date=$(date -d "$RETENTION_DAYS days ago" '+%Y%m%d')

        aws s3 ls "s3://$S3_BUCKET/qdrant/" --recursive | while read -r line; do
            local s3_date=$(echo "$line" | awk '{print $1}')
            local s3_path=$(echo "$line" | awk '{print $4}')

            if [[ "$s3_date" < "$cutoff_date" ]]; then
                log "Deleting old S3 backup: $s3_path"
                aws s3 rm "s3://$S3_BUCKET/$s3_path" || true
            fi
        done
    fi
}

create_backup_metadata() {
    local snapshot_files=("$@")
    local metadata_file="${snapshot_files[-1]}"  # Last element is metadata file
    unset 'snapshot_files[-1]'  # Remove metadata file from list

    log "Creating backup metadata..."

    # Calculate total size
    local total_size=0
    for file in "${snapshot_files[@]}"; do
        if [[ -f "$file" ]]; then
            local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
            ((total_size += file_size))
        fi
    done

    # Get Qdrant version
    local qdrant_version
    qdrant_version=$(curl -s "http://${QDRANT_HOST}:${QDRANT_PORT}/version" | jq -r '.result.version' 2>/dev/null || echo "unknown")

    # Get collection info
    local collections_info
    collections_info=$(curl -s "http://${QDRANT_HOST}:${QDRANT_PORT}/collections" | jq '.result.collections | length' 2>/dev/null || echo "0")

    cat > "$metadata_file" << EOF
{
    "backup_info": {
        "filename": "$(basename "$metadata_file")",
        "created_at": "$(date -Iseconds)",
        "backup_type": "qdrant",
        "encrypted": $ENCRYPT_BACKUP,
        "environment": "${ENVIRONMENT:-development}",
        "collections_counted": $collections_info
    },
    "database_info": {
        "host": "$QDRANT_HOST",
        "port": "$QDRANT_PORT",
        "version": "$qdrant_version",
        "collections": [$(get_collection_list | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//')]
    },
    "file_info": {
        "snapshot_files": [$(printf '"%s",' "${snapshot_files[@]}" | sed 's/,$//')],
        "total_size_bytes": $total_size,
        "total_size_human": "$((total_size / 1024 / 1024))MB"
    },
    "system_info": {
        "hostname": "$(hostname)",
        "os": "$(uname -s)",
        "kernel": "$(uname -r)",
        "script_version": "2.0.0"
    }
}
EOF

    success "Backup metadata created: $metadata_file"
}

verify_backup() {
    local backup_file="$1"

    if [[ "$VERIFY_BACKUP" != "true" ]]; then
        return 0
    fi

    log "Verifying backup integrity..."

    # Test archive integrity
    if ! tar -tzf "$backup_file" > /dev/null; then
        error "Backup archive verification failed"
    fi

    # Extract and verify metadata
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    if ! tar -xzf "$backup_file" -C "$temp_dir" "*.meta.json"; then
        error "Failed to extract metadata for verification"
    fi

    local metadata_file=$(find "$temp_dir" -name "*.meta.json" | head -1)
    if [[ ! -f "$metadata_file" ]]; then
        error "Metadata file not found in backup"
    fi

    # Verify JSON structure
    if ! jq empty "$metadata_file" 2>/dev/null; then
        error "Invalid metadata JSON format"
    fi

    success "Backup verification completed successfully"
}

# Main execution
main() {
    local backup_type="${1:-full}"  # full or incremental

    log "Starting Qdrant backup process..."
    log "Configuration: Type=$backup_type, Retention=$RETENTION_DAYS days, Encrypt=$ENCRYPT_BACKUP"

    # Pre-flight checks
    check_dependencies
    check_qdrant_connection

    # Create backup directory and filename
    local backup_file
    backup_file=$(create_backup_dir)
    backup_file="${backup_file}-${backup_type}"

    # Perform backup based on type
    case "$backup_type" in
        "full")
            backup_file=$(create_full_backup "$backup_file")
            ;;
        "incremental")
            backup_file=$(create_incremental_backup "$backup_file")
            ;;
        *)
            error "Unsupported backup type: $backup_type"
            ;;
    esac

    # Process backup
    encrypt_backup "$backup_file"
    verify_backup "$backup_file"

    # Upload to S3
    upload_to_s3 "$backup_file"

    # Cleanup old backups
    cleanup_old_backups

    success "Qdrant backup process completed successfully"
    log "Backup file: $backup_file"

    # Send notification (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-type: application/json' \
            --data "{\"text\":\"✅ Qdrant backup completed: $(basename "$backup_file")\"}"
    fi
}

# Execute main function
main "$@"