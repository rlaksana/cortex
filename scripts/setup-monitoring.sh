#!/bin/bash

# Cortex MCP Monitoring Setup Script
#
# This script sets up the complete monitoring stack for Cortex Memory MCP
# including Prometheus, Grafana, Alertmanager, and dashboards.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MONITORING_PORT=${MONITORING_PORT:-9090}
GRAFANA_PORT=${GRAFANA_PORT:-3000}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9091}
ALERTMANAGER_PORT=${ALERTMANAGER_PORT:-9093}
NODE_EXPORTER_PORT=${NODE_EXPORTER_PORT:-9100}

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi

    log_success "All dependencies are installed and running."
}

check_port_conflicts() {
    log_info "Checking for port conflicts..."

    local ports=("$MONITORING_PORT" "$GRAFANA_PORT" "$PROMETHEUS_PORT" "$ALERTMANAGER_PORT" "$NODE_EXPORTER_PORT")
    local services=("Cortex MCP Monitoring" "Grafana" "Prometheus" "Alertmanager" "Node Exporter")

    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local service=${services[$i]}

        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            log_warning "Port $port is already in use. $service may conflict."
        fi
    done
}

create_directories() {
    log_info "Creating necessary directories..."

    # Create data directories
    mkdir -p prometheus/data
    mkdir -p grafana/data
    mkdir -p grafana/provisioning/datasources
    mkdir -p grafana/provisioning/dashboards
    mkdir -p alertmanager/data

    # Set proper permissions
    chmod 755 prometheus/data
    chmod 755 grafana/data
    chmod 755 alertmanager/data

    log_success "Directories created successfully."
}

generate_configs() {
    log_info "Generating configuration files..."

    # Generate Prometheus configuration if it doesn't exist
    if [ ! -f prometheus/prometheus.yml ]; then
        cat > prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'cortex-mcp'
    environment: 'production'

rule_files:
  - "alerts/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['host.docker.internal:$MONITORING_PORT']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
    honor_labels: true

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9091']
    scrape_interval: 30s

storage:
  tsdb:
    path: ./data/prometheus
    retention.time: 15d
    retention.size: 10GB
EOF
        log_success "Prometheus configuration generated."
    fi

    # Generate Grafana datasource configuration if it doesn't exist
    if [ ! -f grafana/provisioning/datasources/prometheus.yml ]; then
        cat > grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
    jsonData:
      httpMethod: POST
      manageAlerts: true
      prometheusType: Prometheus
      prometheusVersion: 2.45.0
      cacheLevel: 'High'
      disableRecordingRules: false
    secureJsonData: {}
EOF
        log_success "Grafana datasource configuration generated."
    fi

    # Generate Grafana dashboard configuration if it doesn't exist
    if [ ! -f grafana/provisioning/dashboards/dashboards.yml ]; then
        cat > grafana/provisioning/dashboards/dashboards.yml << EOF
apiVersion: 1

providers:
  - name: 'cortex-mcp-dashboards'
    orgId: 1
    folder: 'Cortex MCP'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF
        log_success "Grafana dashboard configuration generated."
    fi
}

start_monitoring_stack() {
    log_info "Starting monitoring stack..."

    # Use docker-compose if available, otherwise docker compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi

    # Start the services
    $COMPOSE_CMD -f docker/monitoring-stack.yml up -d

    log_success "Monitoring stack started successfully."
}

wait_for_services() {
    log_info "Waiting for services to be ready..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:$PROMETHEUS_PORT/-/healthy > /dev/null 2>&1; then
            log_success "Prometheus is ready."
            break
        fi

        if [ $attempt -eq $max_attempts ]; then
            log_error "Prometheus failed to start within expected time."
            return 1
        fi

        log_info "Waiting for Prometheus... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    # Wait for Grafana
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:$GRAFANA_PORT/api/health > /dev/null 2>&1; then
            log_success "Grafana is ready."
            break
        fi

        if [ $attempt -eq $max_attempts ]; then
            log_error "Grafana failed to start within expected time."
            return 1
        fi

        log_info "Waiting for Grafana... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
}

verify_setup() {
    log_info "Verifying monitoring setup..."

    # Check if Cortex MCP metrics are available
    if curl -s http://localhost:$MONITORING_PORT/metrics > /dev/null 2>&1; then
        log_success "Cortex MCP metrics endpoint is accessible."
    else
        log_warning "Cortex MCP metrics endpoint is not accessible. Make sure the Cortex MCP server is running with monitoring enabled."
    fi

    # Check Prometheus targets
    if curl -s "http://localhost:$PROMETHEUS_PORT/api/v1/targets" | grep -q "cortex-mcp"; then
        log_success "Prometheus is configured to scrape Cortex MCP metrics."
    else
        log_warning "Prometheus may not be properly configured to scrape Cortex MCP metrics."
    fi

    # Check Grafana datasource
    if curl -s "http://localhost:$GRAFANA_PORT/api/datasources" | grep -q "Prometheus"; then
        log_success "Grafana Prometheus datasource is configured."
    else
        log_warning "Grafana Prometheus datasource may not be properly configured."
    fi
}

show_access_info() {
    echo ""
    log_success "Monitoring setup complete!"
    echo ""
    echo "Access URLs:"
    echo "  • Grafana Dashboard:     http://localhost:$GRAFANA_PORT (admin/admin123)"
    echo "  • Prometheus:           http://localhost:$PROMETHEUS_PORT"
    echo "  • Alertmanager:         http://localhost:$ALERTMANAGER_PORT"
    echo "  • Cortex MCP Metrics:   http://localhost:$MONITORING_PORT/metrics"
    echo ""
    echo "Quick Commands:"
    echo "  • View logs:            docker-compose -f docker/monitoring-stack.yml logs -f"
    echo "  • Stop monitoring:      docker-compose -f docker/monitoring-stack.yml down"
    echo "  • Restart services:     docker-compose -f docker/monitoring-stack.yml restart"
    echo ""
    echo "Next Steps:"
    echo "  1. Open Grafana and explore the pre-configured dashboard"
    echo "  2. Configure alert channels in Alertmanager"
    echo "  3. Customize alert thresholds in prometheus/alerts/cortex.rules.yaml"
    echo "  4. Review the monitoring documentation: docs/MONITORING-SETUP.md"
    echo ""
}

main() {
    echo "🧠 Cortex MCP Monitoring Setup"
    echo "==============================="
    echo ""

    check_dependencies
    check_port_conflicts
    create_directories
    generate_configs
    start_monitoring_stack
    wait_for_services
    verify_setup
    show_access_info

    log_success "Cortex MCP monitoring setup completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    "stop")
        log_info "Stopping monitoring stack..."
        if command -v docker-compose &> /dev/null; then
            docker-compose -f docker/monitoring-stack.yml down
        else
            docker compose -f docker/monitoring-stack.yml down
        fi
        log_success "Monitoring stack stopped."
        ;;
    "restart")
        log_info "Restarting monitoring stack..."
        if command -v docker-compose &> /dev/null; then
            docker-compose -f docker/monitoring-stack.yml restart
        else
            docker compose -f docker/monitoring-stack.yml restart
        fi
        log_success "Monitoring stack restarted."
        ;;
    "logs")
        if command -v docker-compose &> /dev/null; then
            docker-compose -f docker/monitoring-stack.yml logs -f
        else
            docker compose -f docker/monitoring-stack.yml logs -f
        fi
        ;;
    "status")
        if command -v docker-compose &> /dev/null; then
            docker-compose -f docker/monitoring-stack.yml ps
        else
            docker compose -f docker/monitoring-stack.yml ps
        fi
        ;;
    "help"|"-h"|"--help")
        echo "Cortex MCP Monitoring Setup Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)  Set up monitoring stack"
        echo "  stop       Stop monitoring stack"
        echo "  restart    Restart monitoring stack"
        echo "  logs       Show logs from monitoring services"
        echo "  status     Show status of monitoring services"
        echo "  help       Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  MONITORING_PORT       Port for Cortex MCP monitoring (default: 9090)"
        echo "  GRAFANA_PORT          Grafana port (default: 3000)"
        echo "  PROMETHEUS_PORT       Prometheus port (default: 9091)"
        echo "  ALERTMANAGER_PORT     Alertmanager port (default: 9093)"
        echo "  NODE_EXPORTER_PORT    Node Exporter port (default: 9100)"
        echo ""
        ;;
    *)
        main
        ;;
esac