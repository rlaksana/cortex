#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - DEVELOPMENT ENVIRONMENT DEPLOYMENT
# ============================================================================
# Development environment deployment with hot-reload and debugging support

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="development"

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

# Environment variables
export NODE_ENV="development"
export LOG_LEVEL="debug"
export CORS_ORIGINS="*"
export MAX_CONCURRENT_REQUESTS="10"
export REQUEST_TIMEOUT="30000"

# Database configuration
export DATABASE_URL="postgresql://cortex:dev_password@localhost:5432/cortex_dev"
export POSTGRES_PASSWORD="dev_password"
export POSTGRES_DB="cortex_dev"
export POSTGRES_USER="cortex"

# Qdrant configuration
export QDRANT_HOST="localhost"
export QDRANT_PORT="6333"
export QDRANT_API_KEY=""

# Redis configuration
export REDIS_URL="redis://localhost:6379"
export REDIS_TTL="300"

# Development settings
export ENABLE_VECTOR_SEARCH="true"
export ENABLE_FULLTEXT_SEARCH="true"
export ENABLE_CACHING="true"
export ENABLE_METRICS="true"
export ENABLE_TRACING="true"
export HOT_RELOAD="true"
export DEBUG_MODE="true"

# Check dependencies
check_dependencies() {
    log "Checking development dependencies..."

    local missing_deps=()
    local deps=("docker" "docker-compose" "node" "npm" "git")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        else
            log "✓ $dep is available"
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        error "Please install missing dependencies before deploying"
        exit 1
    fi

    success "All dependencies are available"
}

# Setup development environment
setup_environment() {
    log "Setting up development environment..."

    # Create necessary directories
    mkdir -p "$PROJECT_ROOT/logs"
    mkdir -p "$PROJECT_ROOT/data/postgres"
    mkdir -p "$PROJECT_ROOT/data/qdrant"
    mkdir -p "$PROJECT_ROOT/data/redis"

    # Copy environment configuration
    if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
        log "Creating .env file for development..."
        cat > "$PROJECT_ROOT/.env" << EOF
# Development Environment Configuration
NODE_ENV=development
LOG_LEVEL=debug

# Database Configuration
DATABASE_URL=postgresql://cortex:dev_password@localhost:5432/cortex_dev
POSTGRES_PASSWORD=dev_password
POSTGRES_DB=cortex_dev
POSTGRES_USER=cortex

# Qdrant Configuration
QDRANT_HOST=localhost
QDRANT_PORT=6333
QDRANT_API_KEY=

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_TTL=300

# Development Settings
ENABLE_VECTOR_SEARCH=true
ENABLE_FULLTEXT_SEARCH=true
ENABLE_CACHING=true
ENABLE_METRICS=true
ENABLE_TRACING=true
HOT_RELOAD=true
DEBUG_MODE=true
EOF
        success ".env file created"
    fi

    # Install dependencies
    log "Installing Node.js dependencies..."
    cd "$PROJECT_ROOT"
    npm install

    success "Development environment setup completed"
}

# Start development infrastructure
start_infrastructure() {
    log "Starting development infrastructure..."

    cd "$PROJECT_ROOT"

    # Start Docker Compose for development
    log "Starting Docker services (PostgreSQL, Qdrant, Redis)..."
    docker-compose -f docker/docker-compose.yml --project-name cortex-dev up -d

    # Wait for services to be ready
    log "Waiting for services to be ready..."

    # Wait for PostgreSQL
    local postgres_ready=false
    for i in {1..30}; do
        if docker exec cortex-dev-postgres pg_isready -U cortex -d cortex_dev &>/dev/null; then
            postgres_ready=true
            break
        fi
        log "Waiting for PostgreSQL... ($i/30)"
        sleep 2
    done

    if [[ "$postgres_ready" != "true" ]]; then
        error "PostgreSQL failed to start within timeout"
        exit 1
    fi
    success "PostgreSQL is ready"

    # Wait for Qdrant
    local qdrant_ready=false
    for i in {1..30}; do
        if curl -f http://localhost:6333/health &>/dev/null; then
            qdrant_ready=true
            break
        fi
        log "Waiting for Qdrant... ($i/30)"
        sleep 2
    done

    if [[ "$qdrant_ready" != "true" ]]; then
        error "Qdrant failed to start within timeout"
        exit 1
    fi
    success "Qdrant is ready"

    # Wait for Redis
    local redis_ready=false
    for i in {1..30}; do
        if docker exec cortex-dev-redis redis-cli ping &>/dev/null; then
            redis_ready=true
            break
        fi
        log "Waiting for Redis... ($i/30)"
        sleep 2
    done

    if [[ "$redis_ready" != "true" ]]; then
        error "Redis failed to start within timeout"
        exit 1
    fi
    success "Redis is ready"
}

# Setup database
setup_database() {
    log "Setting up development database..."

    cd "$PROJECT_ROOT"

    # Run database migrations
    log "Running database migrations..."
    npm run db:migrate

    # Seed development data
    log "Seeding development data..."
    if [[ -f "$PROJECT_ROOT/scripts/seed-dev.js" ]]; then
        node scripts/seed-dev.js
    fi

    success "Database setup completed"
}

# Setup Qdrant collections
setup_qdrant() {
    log "Setting up Qdrant collections..."

    # Create default collection for development
    local collection_response=$(curl -s -X PUT "http://localhost:6333/collections/dev_knowledge" \
        -H "Content-Type: application/json" \
        -d '{
            "vectors": {
                "size": 1536,
                "distance": "Cosine"
            },
            "optimizers_config": {
                "default_segment_number": 2,
                "max_segment_size_mb": 200,
                "memmap_threshold_kb": 512
            }
        }')

    if echo "$collection_response" | grep -q "ok\|result"; then
        success "Qdrant collections setup completed"
    else
        warning "Qdrant collection setup may have failed"
        log "Response: $collection_response"
    fi
}

# Build application
build_application() {
    log "Building application for development..."

    cd "$PROJECT_ROOT"

    # Build TypeScript
    npm run build

    # Build Qdrant-specific version
    npm run build:qdrant

    success "Application build completed"
}

# Start development servers
start_development_servers() {
    log "Starting development servers..."

    cd "$PROJECT_ROOT"

    # Start PostgreSQL server in background
    log "Starting PostgreSQL development server..."
    npm run start:dev &
    local postgres_pid=$!

    # Start Qdrant server in background
    log "Starting Qdrant development server..."
    npm run dev:qdrant &
    local qdrant_pid=$!

    # Save PIDs for cleanup
    echo "$postgres_pid" > "$PROJECT_ROOT/.postgres-dev.pid"
    echo "$qdrant_pid" > "$PROJECT_ROOT/.qdrant-dev.pid"

    success "Development servers started"
    log "PostgreSQL server PID: $postgres_pid"
    log "Qdrant server PID: $qdrant_pid"

    # Wait a moment for servers to start
    sleep 5

    # Health checks
    log "Performing health checks..."

    # Check PostgreSQL health
    if npm run db:health; then
        success "PostgreSQL health check passed"
    else
        warning "PostgreSQL health check failed"
    fi

    # Check Qdrant health
    if npm run db:health:qdrant; then
        success "Qdrant health check passed"
    else
        warning "Qdrant health check failed"
    fi
}

# Setup hot reload
setup_hot_reload() {
    log "Setting up hot reload configuration..."

    cd "$PROJECT_ROOT"

    # Create development nodemon configuration
    cat > "$PROJECT_ROOT/nodemon.dev.json" << EOF
{
    "watch": ["src"],
    "ext": "ts,js,json",
    "ignore": ["src/**/*.spec.ts", "src/**/*.test.ts"],
    "exec": "npm run build && npm run start:dev",
    "env": {
        "NODE_ENV": "development",
        "HOT_RELOAD": "true"
    },
    "delay": 1000
}
EOF

    success "Hot reload configuration created"
}

# Run development tests
run_tests() {
    log "Running development tests..."

    cd "$PROJECT_ROOT"

    # Run unit tests
    log "Running unit tests..."
    npm run test:unit

    # Run integration tests
    log "Running integration tests..."
    npm run test:integration

    success "Development tests completed"
}

# Display development URLs
show_urls() {
    log "Development environment is ready!"
    echo ""
    echo "🚀 Development Services:"
    echo "   • PostgreSQL: localhost:5432"
    echo "   • Qdrant:      localhost:6333"
    echo "   • Redis:       localhost:6379"
    echo "   • Nginx:       http://localhost"
    echo ""
    echo "🔧 Development Tools:"
    echo "   • Health Check: npm run db:health"
    echo "   • Qdrant Health: npm run db:health:qdrant"
    echo "   • Database Studio: npm run db:studio"
    echo "   • Logs: tail -f logs/app.log"
    echo ""
    echo "🛠 Development Commands:"
    echo "   • Restart: npm run dev"
    echo "   • Build: npm run build"
    echo "   • Test: npm test"
    echo "   • Lint: npm run lint"
    echo ""
    echo "📊 Monitoring:"
    echo "   • Prometheus: http://localhost:9090 (if enabled)"
    echo "   • Grafana:     http://localhost:3000 (if enabled)"
    echo ""
}

# Cleanup function
cleanup() {
    log "Cleaning up development environment..."

    # Stop development servers
    if [[ -f "$PROJECT_ROOT/.postgres-dev.pid" ]]; then
        local postgres_pid=$(cat "$PROJECT_ROOT/.postgres-dev.pid")
        if kill -0 "$postgres_pid" 2>/dev/null; then
            log "Stopping PostgreSQL server (PID: $postgres_pid)..."
            kill "$postgres_pid" 2>/dev/null || true
        fi
        rm "$PROJECT_ROOT/.postgres-dev.pid"
    fi

    if [[ -f "$PROJECT_ROOT/.qdrant-dev.pid" ]]; then
        local qdrant_pid=$(cat "$PROJECT_ROOT/.qdrant-dev.pid")
        if kill -0 "$qdrant_pid" 2>/dev/null; then
            log "Stopping Qdrant server (PID: $qdrant_pid)..."
            kill "$qdrant_pid" 2>/dev/null || true
        fi
        rm "$PROJECT_ROOT/.qdrant-dev.pid"
    fi

    # Stop Docker services
    log "Stopping Docker services..."
    docker-compose -f docker/docker-compose.yml --project-name cortex-dev down

    success "Development environment cleaned up"
}

# Trap signals for cleanup
trap cleanup EXIT INT TERM

# Main execution
main() {
    local action="${1:-deploy}"

    case "$action" in
        "deploy")
            log "Starting development deployment..."
            check_dependencies
            setup_environment
            start_infrastructure
            setup_database
            setup_qdrant
            build_application
            setup_hot_reload
            start_development_servers
            run_tests
            show_urls
            success "Development deployment completed!"
            ;;
        "stop")
            cleanup
            ;;
        "restart")
            cleanup
            sleep 2
            main deploy
            ;;
        "test")
            check_dependencies
            setup_environment
            run_tests
            ;;
        "logs")
            cd "$PROJECT_ROOT"
            tail -f logs/app.log 2>/dev/null || log "No log file found"
            ;;
        *)
            echo "Usage: $0 {deploy|stop|restart|test|logs}"
            echo ""
            echo "Commands:"
            echo "  deploy  - Deploy development environment"
            echo "  stop    - Stop development environment"
            echo "  restart - Restart development environment"
            echo "  test    - Run development tests"
            echo "  logs    - Show application logs"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"