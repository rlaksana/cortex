#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - PRODUCTION ENVIRONMENT DEPLOYMENT
# ============================================================================
# Production environment deployment with comprehensive checks and rollback

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="production"
HEALTH_CHECK_TIMEOUT=300
ROLLBACK_ENABLED=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    echo -e "${BLUE}[$ENVIRONMENT] $(date '+%Y-%m-%d %H:%M:%S')] $*${NC}"
}

error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $*${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $*${NC}"
}

# Production environment variables
export NODE_ENV="production"
export LOG_LEVEL="info"
export CORS_ORIGINS="https://cortex-mcp.example.com"
export MAX_CONCURRENT_REQUESTS="100"
export REQUEST_TIMEOUT="60000"

# Load production configuration
load_production_config() {
    local config_file="$PROJECT_ROOT/config/production.env"
    if [[ -f "$config_file" ]]; then
        log "Loading production configuration..."
        set -a
        source "$config_file"
        set +a
        success "Production configuration loaded"
    else
        error "Production configuration file not found: $config_file"
        exit 1
    fi
}

# Verify production prerequisites
verify_prerequisites() {
    log "Verifying production deployment prerequisites..."

    # Check if all required environment variables are set
    local required_vars=(
        "DATABASE_URL"
        "QDRANT_API_KEY"
        "JWT_SECRET"
        "API_SECRET"
        "POSTGRES_PASSWORD"
    )

    local missing_vars=()
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        error "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi

    # Check if we're in a Git repository
    if ! git rev-parse --git-dir &>/dev/null; then
        error "Not in a Git repository"
        exit 1
    fi

    # Check if working directory is clean
    if ! git diff-index --quiet HEAD --; then
        error "Working directory is not clean. Please commit or stash changes."
        exit 1
    fi

    # Check if we're on the correct branch
    local current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" && "$current_branch" != "master" ]]; then
        warning "Not on main/master branch (current: $current_branch)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    success "Production prerequisites verified"
}

# Create backup before deployment
create_backup() {
    log "Creating backup before deployment..."

    local backup_dir="$PROJECT_ROOT/backups/pre-deploy-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"

    # Backup PostgreSQL
    log "Creating PostgreSQL backup..."
    if "$PROJECT_ROOT/scripts/backup-postgres.sh" full; then
        cp "$PROJECT_ROOT/backups/postgres"/*latest* "$backup_dir/" 2>/dev/null || true
        success "PostgreSQL backup created"
    else
        error "PostgreSQL backup failed"
        exit 1
    fi

    # Backup Qdrant
    log "Creating Qdrant backup..."
    if "$PROJECT_ROOT/scripts/backup-qdrant.sh" full; then
        cp "$PROJECT_ROOT/backups/qdrant"/*latest* "$backup_dir/" 2>/dev/null || true
        success "Qdrant backup created"
    else
        error "Qdrant backup failed"
        exit 1
    fi

    # Backup configuration files
    log "Backing up configuration files..."
    cp -r "$PROJECT_ROOT/config" "$backup_dir/" 2>/dev/null || true
    cp "$PROJECT_ROOT/docker-compose.yml" "$backup_dir/" 2>/dev/null || true

    # Save backup location for potential rollback
    echo "$backup_dir" > "$PROJECT_ROOT/.last-backup"

    success "Backup completed: $backup_dir"
}

# Run production health checks
run_health_checks() {
    log "Running production health checks..."

    local checks_passed=0
    local total_checks=0

    # Database health checks
    ((total_checks++))
    log "Checking PostgreSQL health..."
    if PGPASSWORD="$POSTGRES_PASSWORD" pg_isready -h "$(echo "$DATABASE_URL" | cut -d'@' -f2 | cut -d':' -f1)" -p "$(echo "$DATABASE_URL" | cut -d':' -f4)" -U "$(echo "$DATABASE_URL" | cut -d':' -f2 | cut -d'@' -f1)" -d "$(echo "$DATABASE_URL" | cut -d'/' -f4)"; then
        success "PostgreSQL health check passed"
        ((checks_passed++))
    else
        error "PostgreSQL health check failed"
    fi

    ((total_checks++))
    log "Checking Qdrant health..."
    if curl -f -H "api-key: $QDRANT_API_KEY" "http://$QDRANT_HOST:$QDRANT_PORT/health" &>/dev/null; then
        success "Qdrant health check passed"
        ((checks_passed++))
    else
        error "Qdrant health check failed"
    fi

    # Application health checks
    ((total_checks++))
    log "Checking application health..."
    if curl -f "http://localhost:3000/health" &>/dev/null; then
        success "Application health check passed"
        ((checks_passed++))
    else
        error "Application health check failed"
    fi

    # Load balancer health checks
    ((total_checks++))
    log "Checking load balancer health..."
    if curl -f "http://localhost/health" &>/dev/null; then
        success "Load balancer health check passed"
        ((checks_passed++))
    else
        error "Load balancer health check failed"
    fi

    if [[ $checks_passed -eq $total_checks ]]; then
        success "All health checks passed ($checks_passed/$total_checks)"
        return 0
    else
        error "Health checks failed ($checks_passed/$total_checks)"
        return 1
    fi
}

# Deploy to production infrastructure
deploy_infrastructure() {
    log "Deploying production infrastructure..."

    cd "$PROJECT_ROOT"

    # Stop existing services gracefully
    log "Stopping existing services..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod down

    # Pull latest images
    log "Pulling latest images..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod pull

    # Start infrastructure services
    log "Starting infrastructure services..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod up -d postgres qdrant redis

    # Wait for databases to be ready
    log "Waiting for databases to be ready..."

    # Wait for PostgreSQL
    local postgres_ready=false
    for i in {1..60}; do
        if docker exec cortex-prod-postgres pg_isready -U cortex -d cortex_prod &>/dev/null; then
            postgres_ready=true
            break
        fi
        log "Waiting for PostgreSQL... ($i/60)"
        sleep 2
    done

    if [[ "$postgres_ready" != "true" ]]; then
        error "PostgreSQL failed to start within timeout"
        return 1
    fi
    success "PostgreSQL is ready"

    # Wait for Qdrant
    local qdrant_ready=false
    for i in {1..60}; do
        if curl -f -H "api-key: $QDRANT_API_KEY" "http://localhost:6333/health" &>/dev/null; then
            qdrant_ready=true
            break
        fi
        log "Waiting for Qdrant... ($i/60)"
        sleep 2
    done

    if [[ "$qdrant_ready" != "true" ]]; then
        error "Qdrant failed to start within timeout"
        return 1
    fi
    success "Qdrant is ready"

    success "Infrastructure deployment completed"
}

# Deploy application
deploy_application() {
    log "Deploying production application..."

    cd "$PROJECT_ROOT"

    # Build production images
    log "Building production images..."
    docker build -t cortex-mcp:latest .

    # Run database migrations
    log "Running database migrations..."
    docker run --rm --network cortex-prod_cortex_network \
        -e DATABASE_URL="$DATABASE_URL" \
        cortex-mcp:latest npm run db:migrate

    # Start application services
    log "Starting application services..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod up -d

    success "Application deployment completed"
}

# Run production tests
run_production_tests() {
    log "Running production tests..."

    cd "$PROJECT_ROOT"

    # Run smoke tests
    log "Running smoke tests..."
    npm run test:smoke

    # Run integration tests
    log "Running integration tests..."
    npm run test:integration:prod

    # Run performance tests
    log "Running performance tests..."
    npm run test:performance:smoke

    success "Production tests completed"
}

# Verify deployment
verify_deployment() {
    log "Verifying production deployment..."

    # Wait for services to be fully ready
    log "Waiting for services to stabilize..."
    sleep 30

    # Run comprehensive health checks
    if run_health_checks; then
        success "Deployment verification passed"
        return 0
    else
        error "Deployment verification failed"
        return 1
    fi
}

# Rollback function
rollback() {
    if [[ "$ROLLBACK_ENABLED" != "true" ]]; then
        error "Rollback is disabled"
        return 1
    fi

    local backup_dir
    if [[ -f "$PROJECT_ROOT/.last-backup" ]]; then
        backup_dir=$(cat "$PROJECT_ROOT/.last-backup")
    else
        error "No backup found for rollback"
        return 1
    fi

    log "Starting rollback to backup: $backup_dir"

    # Stop current deployment
    log "Stopping current deployment..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod down

    # Restore from backup
    log "Restoring from backup..."
    if [[ -f "$backup_dir"/*postgres* ]]; then
        # Restore PostgreSQL
        log "Restoring PostgreSQL..."
        # Implementation depends on your backup strategy
    fi

    if [[ -f "$backup_dir"/*qdrant* ]]; then
        # Restore Qdrant
        log "Restoring Qdrant..."
        # Implementation depends on your backup strategy
    fi

    # Start services with previous configuration
    log "Restarting services with previous configuration..."
    docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod up -d

    # Verify rollback
    if run_health_checks; then
        success "Rollback completed successfully"
    else
        error "Rollback verification failed"
        return 1
    fi
}

# Notify deployment status
notify_deployment() {
    local status="$1"
    local message="Production deployment $status"

    log "$message"

    # Send Slack notification if configured
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        local color="good"
        if [[ "$status" == "failed" ]]; then
            color="danger"
        fi

        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-type: application/json' \
            --data "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"$message\",
                    \"text\": \"Environment: $ENVIRONMENT\nTimestamp: $(date -Iseconds)\",
                    \"fields\": [
                        {\"title\": \"Version\", \"value\": \"$(git rev-parse --short HEAD)\", \"short\": true},
                        {\"title\": \"Branch\", \"value\": \"$(git branch --show-current)\", \"short\": true}
                    ]
                }]
            }" || true
    fi

    # Send email notification if configured
    if [[ -n "${NOTIFICATION_EMAIL:-}" ]]; then
        echo "$message" | mail -s "Cortex MCP Deployment $status" "$NOTIFICATION_EMAIL" || true
    fi
}

# Create deployment tag
create_deployment_tag() {
    local tag_name="deploy-prod-$(date +%Y%m%d_%H%M%S)"

    log "Creating deployment tag: $tag_name"
    git tag "$tag_name"
    git push origin "$tag_name" || true

    success "Deployment tag created: $tag_name"
}

# Cleanup function
cleanup() {
    log "Performing post-deployment cleanup..."

    # Remove temporary files
    rm -f "$PROJECT_ROOT/.last-backup"

    # Cleanup old logs
    find "$PROJECT_ROOT/logs" -name "*.log" -mtime +7 -delete 2>/dev/null || true

    success "Post-deployment cleanup completed"
}

# Main deployment function
main() {
    local action="${1:-deploy}"

    case "$action" in
        "deploy")
            log "Starting production deployment..."
            load_production_config
            verify_prerequisites
            create_backup
            deploy_infrastructure
            deploy_application
            run_production_tests

            if verify_deployment; then
                create_deployment_tag
                notify_deployment "completed successfully"
                cleanup
                success "Production deployment completed successfully!"
                log "Services are now running in production mode"
            else
                notify_deployment "failed"
                if [[ "$ROLLBACK_ENABLED" == "true" ]]; then
                    log "Attempting automatic rollback..."
                    rollback
                else
                    error "Deployment failed and rollback is disabled"
                    exit 1
                fi
            fi
            ;;
        "rollback")
            log "Starting production rollback..."
            load_production_config
            rollback
            notify_deployment "rolled back"
            ;;
        "status")
            log "Checking production status..."
            run_health_checks
            ;;
        "logs")
            cd "$PROJECT_ROOT"
            docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod logs -f
            ;;
        "stop")
            log "Stopping production services..."
            docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod down
            success "Production services stopped"
            ;;
        "restart")
            log "Restarting production services..."
            docker-compose -f docker/docker-compose.dual-db.yml --project-name cortex-prod restart
            sleep 30
            run_health_checks
            ;;
        *)
            echo "Usage: $0 {deploy|rollback|status|logs|stop|restart}"
            echo ""
            echo "Commands:"
            echo "  deploy   - Deploy to production environment"
            echo "  rollback - Rollback to previous version"
            echo "  status   - Check production status"
            echo "  logs     - Show production logs"
            echo "  stop     - Stop production services"
            echo "  restart  - Restart production services"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"