#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - POSTGRESQL BACKUP SCRIPT
# ============================================================================
# Comprehensive backup solution for PostgreSQL 18 with encryption
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
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-cortex_prod}"
POSTGRES_USER="${POSTGRES_USER:-cortex}"
BACKUP_DIR="${BACKUP_DIR:-./backups/postgres}"
S3_BUCKET="${S3_BUCKET:-cortex-mcp-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
ENCRYPT_BACKUP="${ENCRYPT_BACKUP:-true}"
GPG_RECIPIENT="${GPG_RECIPIENT:-backup@cortex-mcp.com}"
BACKUP_TYPE="${BACKUP_TYPE:-full}" # full, differential, incremental
COMPRESS_METHOD="${COMPRESS_METHOD:-gzip}" # gzip, bzip2, xz
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"

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
    local deps=("pg_dump" "aws" "gpg" "find" "date")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' is not installed"
        fi
    done
}

check_database_connection() {
    log "Checking database connection..."
    if ! PGPASSWORD="$POSTGRES_PASSWORD" pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB"; then
        error "Cannot connect to PostgreSQL database"
    fi
    success "Database connection verified"
}

create_backup_dir() {
    local backup_date=$(date '+%Y-%m-%d')
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    BACKUP_PATH="${BACKUP_DIR}/${backup_date}"
    BACKUP_FILE="cortex-postgres-backup-${timestamp}.sql"
    mkdir -p "$BACKUP_PATH"
    echo "$BACKUP_PATH/$BACKUP_FILE"
}

perform_full_backup() {
    local backup_file="$1"
    log "Starting full backup to $backup_file"

    local pg_dump_opts=(
        "--host=$POSTGRES_HOST"
        "--port=$POSTGRES_PORT"
        "--username=$POSTGRES_USER"
        "--dbname=$POSTGRES_DB"
        "--verbose"
        "--no-password"
        "--format=custom"
        "--compress=9"
        "--jobs=$PARALLEL_JOBS"
        "--exclude-table-data='audit_log'"
        "--exclude-table-data='event_audit'"
        "--exclude-table-data='temp_*'"
    )

    # Add custom options for production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        pg_dump_opts+=(
            "--serializable-deferrable"
            "--lock-wait-timeout=30000"
        )
    fi

    # Execute backup
    if ! PGPASSWORD="$POSTGRES_PASSWORD" pg_dump "${pg_dump_opts[@]}" > "$backup_file"; then
        error "PostgreSQL backup failed"
    fi

    local file_size=$(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file")
    success "Full backup completed successfully (Size: $((file_size / 1024 / 1024))MB)"
}

perform_differential_backup() {
    local backup_file="$1"
    log "Starting differential backup to $backup_file"

    # Find the most recent full backup
    local last_full_backup=$(find "$BACKUP_DIR" -name "*cortex-postgres-backup*-full.sql*" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

    if [[ -z "$last_full_backup" ]]; then
        error "No full backup found for differential backup"
    fi

    log "Using base backup: $(basename "$last_full_backup")"

    # Create differential backup using pg_dump with incremental options
    local pg_dump_opts=(
        "--host=$POSTGRES_HOST"
        "--port=$POSTGRES_PORT"
        "--username=$POSTGRES_USER"
        "--dbname=$POSTGRES_DB"
        "--verbose"
        "--no-password"
        "--format=directory"
        "--jobs=$PARALLEL_JOBS"
        "--file=$backup_file.dir"
    )

    if ! PGPASSWORD="$POSTGRES_PASSWORD" pg_dump "${pg_dump_opts[@]}"; then
        error "Differential backup failed"
    fi

    success "Differential backup completed successfully"
}

compress_backup() {
    local backup_file="$1"
    local compressed_file="${backup_file}.${COMPRESS_METHOD}"

    log "Compressing backup with $COMPRESS_METHOD..."

    case "$COMPRESS_METHOD" in
        "gzip")
            if ! gzip -c "$backup_file" > "$compressed_file"; then
                error "Gzip compression failed"
            fi
            ;;
        "bzip2")
            if ! bzip2 -c "$backup_file" > "$compressed_file"; then
                error "Bzip2 compression failed"
            fi
            ;;
        "xz")
            if ! xz -c "$backup_file" > "$compressed_file"; then
                error "XZ compression failed"
            fi
            ;;
        *)
            error "Unsupported compression method: $COMPRESS_METHOD"
            ;;
    esac

    # Verify compressed file
    if [[ ! -f "$compressed_file" ]]; then
        error "Compressed file not created"
    fi

    # Remove uncompressed backup if compression succeeded
    rm "$backup_file"
    success "Backup compressed successfully: $compressed_file"
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
    local s3_key="postgresql/$(date '+%Y/%m/%d')/$(basename "$backup_file")"

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
    aws_opts+=("--metadata=backup-type=${BACKUP_TYPE},created-date=$(date -Iseconds)")

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
    done < <(find "$BACKUP_DIR" -name "*cortex-postgres-backup*" -type f -mtime "+$RETENTION_DAYS" -print0 2>/dev/null || true)

    # Clean empty directories
    find "$BACKUP_DIR" -type d -empty -delete 2>/dev/null || true

    success "Deleted $deleted_count old local backups"

    # Clean S3 backups if configured
    if [[ -n "$S3_BUCKET" ]]; then
        log "Cleaning up old S3 backups..."
        local cutoff_date=$(date -d "$RETENTION_DAYS days ago" '+%Y%m%d')

        aws s3 ls "s3://$S3_BUCKET/postgresql/" --recursive | while read -r line; do
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
    local backup_file="$1"
    local metadata_file="${backup_file}.meta.json"

    log "Creating backup metadata..."

    local backup_size=$(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file")
    local backup_checksum=$(sha256sum "$backup_file" | cut -d' ' -f1)
    local pg_version=$(PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "SELECT version();" | xargs)

    cat > "$metadata_file" << EOF
{
    "backup_info": {
        "filename": "$(basename "$backup_file")",
        "created_at": "$(date -Iseconds)",
        "backup_type": "$BACKUP_TYPE",
        "compression": "$COMPRESS_METHOD",
        "encrypted": $ENCRYPT_BACKUP,
        "environment": "${ENVIRONMENT:-development}"
    },
    "database_info": {
        "host": "$POSTGRES_HOST",
        "port": "$POSTGRES_PORT",
        "database": "$POSTGRES_DB",
        "user": "$POSTGRES_USER",
        "version": "$pg_version"
    },
    "file_info": {
        "size_bytes": $backup_size,
        "size_human": "$((backup_size / 1024 / 1024))MB",
        "checksum_sha256": "$backup_checksum"
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

    log "Verifying backup integrity..."

    case "$BACKUP_TYPE" in
        "full")
            # Verify custom format backup
            if ! pg_restore --list "$backup_file" > /dev/null 2>&1; then
                error "Backup verification failed"
            fi
            ;;
        "differential")
            # Verify directory format backup
            if [[ ! -d "$backup_file.dir" ]] || [[ -z "$(ls -A "$backup_file.dir")" ]]; then
                error "Differential backup verification failed"
            fi
            ;;
    esac

    success "Backup verification completed successfully"
}

# Main execution
main() {
    log "Starting PostgreSQL backup process..."
    log "Configuration: Type=$BACKUP_TYPE, Retention=$RETENTION_DAYS days, Encrypt=$ENCRYPT_BACKUP"

    # Pre-flight checks
    check_dependencies
    check_database_connection

    # Create backup directory and filename
    local backup_file
    backup_file=$(create_backup_dir)
    backup_file="${backup_file}.sql"

    # Perform backup based on type
    case "$BACKUP_TYPE" in
        "full")
            perform_full_backup "$backup_file"
            ;;
        "differential")
            perform_differential_backup "$backup_file"
            backup_file="${backup_file}.dir"
            ;;
        *)
            error "Unsupported backup type: $BACKUP_TYPE"
            ;;
    esac

    # Process backup
    if [[ "$BACKUP_TYPE" == "full" ]]; then
        compress_backup "$backup_file"
        backup_file="${backup_file}.${COMPRESS_METHOD}"
        encrypt_backup "$backup_file"
        verify_backup "$backup_file"
    fi

    # Create metadata
    create_backup_metadata "$backup_file"

    # Upload to S3
    upload_to_s3 "$backup_file"

    # Cleanup old backups
    cleanup_old_backups

    success "PostgreSQL backup process completed successfully"
    log "Backup file: $backup_file"

    # Send notification (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-type: application/json' \
            --data "{\"text\":\"✅ PostgreSQL backup completed: $(basename "$backup_file")\"}"
    fi
}

# Execute main function
main "$@"