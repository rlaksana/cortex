#!/bin/bash

# ============================================================================
# CORTEX MEMORY MCP - DEPLOYMENT SCRIPT
# ============================================================================
# Automated deployment script for Cortex Memory MCP
#
# Usage:
#   ./scripts/deploy/deploy.sh [environment] [options]
#
# Environments:
#   dev     - Development environment
#   staging - Staging environment
#   prod    - Production environment
#
# Options:
#   --skip-tests     Skip pre-deployment tests
#   --force         Force deployment without confirmation
#   --rollback      Rollback to previous version
#   --dry-run       Show what would be deployed without executing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="/tmp/cortex-mcp-deploy-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/opt/cortex-backups"
CONFIG_FILE="${PROJECT_ROOT}/deploy.conf"

# Default values
ENVIRONMENT=""
SKIP_TESTS=false
FORCE_DEPLOY=false
ROLLBACK=false
DRY_RUN=false
KEEP_OLD_VERSIONS=3

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*${NC}" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*${NC}" | tee -a "$LOG_FILE"
    fi
}

# Usage information
usage() {
    cat << EOF
Cortex Memory MCP Deployment Script

Usage:
  $0 <environment> [options]

Environments:
  dev     - Development environment
  staging - Staging environment
  prod    - Production environment

Options:
  --skip-tests     Skip pre-deployment tests
  --force         Force deployment without confirmation
  --rollback      Rollback to previous version
  --dry-run       Show what would be deployed without executing
  --debug         Enable debug logging
  --help, -h      Show this help message

Examples:
  $0 staging
  $0 prod --skip-tests
  $0 prod --rollback
  $0 dev --dry-run

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --force)
                FORCE_DEPLOY=true
                shift
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --debug)
                export DEBUG=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            dev|staging|prod)
                ENVIRONMENT="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$ENVIRONMENT" ]]; then
        log_error "Environment is required"
        usage
        exit 1
    fi
}

# Validate environment and prerequisites
validate_environment() {
    log_info "Validating environment: $ENVIRONMENT"

    # Check if environment directory exists
    local env_dir="$PROJECT_ROOT/environments/$ENVIRONMENT"
    if [[ ! -d "$env_dir" ]]; then
        log_error "Environment directory not found: $env_dir"
        exit 1
    fi

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi

    # Check if we have required environment variables
    case "$ENVIRONMENT" in
        prod)
            if [[ -z "${JWT_SECRET:-}" ]]; then
                log_error "JWT_SECRET environment variable is required for production"
                exit 1
            fi
            if [[ -z "${API_KEY:-}" ]]; then
                log_error "API_KEY environment variable is required for production"
                exit 1
            fi
            ;;
        staging)
            if [[ -z "${STAGING_JWT_SECRET:-}" ]]; then
                log_warning "STAGING_JWT_SECRET not set, using default"
            fi
            ;;
    esac

    log_success "Environment validation passed"
}

# Backup current deployment
backup_deployment() {
    log_info "Creating backup of current deployment"

    local backup_name="cortex-mcp-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create backup: $backup_path"
        return 0
    fi

    mkdir -p "$backup_path"

    # Backup Docker Compose files
    if [[ -f "$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml" ]]; then
        cp "$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml" "$backup_path/"
    fi

    # Backup configuration files
    if [[ -d "$PROJECT_ROOT/environments/$ENVIRONMENT/config" ]]; then
        cp -r "$PROJECT_ROOT/environments/$ENVIRONMENT/config" "$backup_path/"
    fi

    # Backup secrets (if they exist)
    if [[ -f "$PROJECT_ROOT/environments/$ENVIRONMENT/.env" ]]; then
        cp "$PROJECT_ROOT/environments/$ENVIRONMENT/.env" "$backup_path/"
    fi

    # Export current container state
    if docker-compose -f "$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml" ps -q &> /dev/null; then
        docker-compose -f "$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml" ps > "$backup_path/containers.log"
        docker-compose -f "$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml" config > "$backup_path/compose-config.yml"
    fi

    log_success "Backup created: $backup_path"

    # Cleanup old backups
    find "$BACKUP_DIR" -name "cortex-mcp-${ENVIRONMENT}-*" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
}

# Run pre-deployment tests
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_warning "Skipping pre-deployment tests"
        return 0
    fi

    log_info "Running pre-deployment tests"

    cd "$PROJECT_ROOT"

    # Run unit tests
    log_info "Running unit tests"
    npm run test:unit || {
        log_error "Unit tests failed"
        exit 1
    }

    # Run integration tests
    log_info "Running integration tests"
    npm run test:integration || {
        log_error "Integration tests failed"
        exit 1
    }

    # Run security audit
    log_info "Running security audit"
    npm audit --audit-level=high || {
        log_warning "Security audit found issues"
        if [[ "$ENVIRONMENT" == "prod" && "$FORCE_DEPLOY" != "true" ]]; then
            log_error "Cannot deploy to production with security issues (use --force to override)"
            exit 1
        fi
    }

    # Run code quality checks
    log_info "Running code quality checks"
    npm run lint || {
        log_error "Code quality checks failed"
        exit 1
    }

    log_success "All tests passed"
}

# Build Docker images
build_images() {
    log_info "Building Docker images"

    cd "$PROJECT_ROOT"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would build Docker images"
        return 0
    fi

    # Get version from package.json
    local version=$(node -p "require('./package.json').version")
    local image_name="cortex-mcp"
    local image_tag="${image_name}:${version}-${ENVIRONMENT}"

    log_info "Building image: $image_tag"

    # Build the main application image
    docker build \
        --file docker/Dockerfile \
        --tag "$image_tag" \
        --tag "${image_name}:latest-${ENVIRONMENT}" \
        . || {
        log_error "Docker build failed"
        exit 1
    }

    # Build backup service image if needed
    if [[ -f "docker/Dockerfile.backup" ]]; then
        docker build \
            --file docker/Dockerfile.backup \
            --tag "${image_name}-backup:${version}-${ENVIRONMENT}" \
            . || {
            log_error "Backup service Docker build failed"
            exit 1
        }
    fi

    log_success "Docker images built successfully"
}

# Deploy application
deploy_application() {
    log_info "Deploying application to $ENVIRONMENT"

    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would deploy with: $compose_file"
        return 0
    fi

    cd "$PROJECT_ROOT"

    # Set environment variables
    export COMPOSE_PROJECT_NAME="cortex-mcp-${ENVIRONMENT}"
    export COMPOSE_FILE="$compose_file"

    # Pull latest images
    log_info "Pulling latest images"
    docker-compose pull

    # Stop existing services
    if docker-compose ps -q &> /dev/null; then
        log_info "Stopping existing services"
        docker-compose down
    fi

    # Start new services
    log_info "Starting new services"
    docker-compose up -d

    # Wait for services to be healthy
    log_info "Waiting for services to be healthy"
    wait_for_health

    log_success "Application deployed successfully"
}

# Wait for services to be healthy
wait_for_health() {
    local max_attempts=30
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        local unhealthy_containers=$(docker-compose ps --filter "status=running" --format "{{.Service}}" | wc -l)
        local total_containers=$(docker-compose config --services | wc -l)

        if [[ $unhealthy_containers -eq $total_containers ]]; then
            log_success "All services are healthy"
            return 0
        fi

        log_info "Waiting for services to be healthy... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    log_error "Services did not become healthy within expected time"
    docker-compose ps
    exit 1
}

# Run post-deployment verification
verify_deployment() {
    log_info "Running post-deployment verification"

    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    cd "$PROJECT_ROOT"

    # Check if all containers are running
    local running_containers=$(docker-compose -f "$compose_file" ps --filter "status=running" --format "{{.Service}}" | wc -l)
    local total_containers=$(docker-compose -f "$compose_file" config --services | wc -l)

    if [[ $running_containers -ne $total_containers ]]; then
        log_error "Not all containers are running"
        docker-compose -f "$compose_file" ps
        exit 1
    fi

    # Run smoke tests
    log_info "Running smoke tests"
    npm run test:smoke || {
        log_error "Smoke tests failed"
        exit 1
    }

    # Check health endpoints
    if [[ "$ENVIRONMENT" != "dev" ]]; then
        local health_url="http://localhost:3000/health"
        if curl -f "$health_url" &> /dev/null; then
            log_success "Health check passed"
        else
            log_error "Health check failed"
            exit 1
        fi
    fi

    log_success "Post-deployment verification passed"
}

# Rollback deployment
rollback_deployment() {
    log_info "Rolling back deployment"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would rollback deployment"
        return 0
    fi

    # Find the most recent backup
    local latest_backup=$(find "$BACKUP_DIR" -name "cortex-mcp-${ENVIRONMENT}-*" -type d | sort -r | head -n 1)

    if [[ -z "$latest_backup" ]]; then
        log_error "No backup found for rollback"
        exit 1
    fi

    log_info "Rolling back to: $latest_backup"

    # Stop current deployment
    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    if docker-compose -f "$compose_file" ps -q &> /dev/null; then
        log_info "Stopping current deployment"
        docker-compose -f "$compose_file" down
    fi

    # Restore configuration
    if [[ -f "$latest_backup/docker-compose.yml" ]]; then
        cp "$latest_backup/docker-compose.yml" "$compose_file"
    fi

    if [[ -d "$latest_backup/config" ]]; then
        cp -r "$latest_backup/config" "$PROJECT_ROOT/environments/$ENVIRONMENT/"
    fi

    # Start rollback deployment
    log_info "Starting rollback deployment"
    docker-compose -f "$compose_file" up -d

    # Wait for services
    wait_for_health

    log_success "Rollback completed successfully"
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        log_error "Deployment failed. Check logs: $LOG_FILE"
    fi
}

# Main deployment function
main() {
    log_info "Starting Cortex Memory MCP deployment"
    log_info "Environment: $ENVIRONMENT"
    log_info "Log file: $LOG_FILE"

    # Set up cleanup trap
    trap cleanup EXIT

    # Validate environment
    validate_environment

    if [[ "$ROLLBACK" == "true" ]]; then
        if [[ "$FORCE_DEPLOY" != "true" ]]; then
            read -p "Are you sure you want to rollback the $ENVIRONMENT deployment? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Rollback cancelled"
                exit 0
            fi
        fi

        backup_deployment
        rollback_deployment
        verify_deployment
        log_success "Rollback completed successfully"
        return 0
    fi

    # Regular deployment flow
    if [[ "$FORCE_DEPLOY" != "true" ]]; then
        read -p "Are you sure you want to deploy to $ENVIRONMENT? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi

    backup_deployment
    run_tests
    build_images
    deploy_application
    verify_deployment

    log_success "Deployment to $ENVIRONMENT completed successfully!"
    log_info "Logs available at: $LOG_FILE"
}

# Parse arguments and run main function
parse_args "$@"
main

exit 0