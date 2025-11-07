#!/bin/bash

# ============================================================================
# CORTEX MEMORY MCP - PRODUCTION VALIDATION SCRIPT
# ============================================================================
# Comprehensive validation script for production deployment
#
# Usage:
#   ./scripts/validate-production.sh [options]
#
# Options:
#   --skip-security   Skip security validations
#   --skip-performance Skip performance validations
#   --skip-backup     Skip backup validation
#   --environment     Specify environment (default: prod)
#   --verbose         Enable verbose output
#   --help, -h        Show help message

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
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENVIRONMENT="${ENVIRONMENT:-prod}"
SKIP_SECURITY=false
SKIP_PERFORMANCE=false
SKIP_BACKUP=false
VERBOSE=false
VALIDATION_ERRORS=0
VALIDATION_WARNINGS=0

# Results file
RESULTS_FILE="/tmp/cortex-mcp-validation-$(date +%Y%m%d-%H%M%S).json"

# Logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
}

log_success() {
    echo -e "${GREEN}✓ $*${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*" >> "$RESULTS_FILE"
}

log_warning() {
    echo -e "${YELLOW}⚠ $*${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*" >> "$RESULTS_FILE"
    ((VALIDATION_WARNINGS++))
}

log_error() {
    echo -e "${RED}✗ $*${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" >> "$RESULTS_FILE"
    ((VALIDATION_ERRORS++))
}

log_info() {
    echo -e "${BLUE}ℹ $*${NC}"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${PURPLE}🐛 $*${NC}"
    fi
}

# Usage information
usage() {
    cat << EOF
Cortex Memory MCP Production Validation Script

Usage:
  $0 [options]

Options:
  --skip-security     Skip security validations
  --skip-performance  Skip performance validations
  --skip-backup       Skip backup validation
  --environment ENV   Specify environment (default: prod)
  --verbose           Enable verbose output
  --help, -h          Show this help message

Examples:
  $0
  $0 --environment staging
  $0 --skip-security --verbose

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-security)
                SKIP_SECURITY=true
                shift
                ;;
            --skip-performance)
                SKIP_PERFORMANCE=true
                shift
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Initialize results file
init_results() {
    cat > "$RESULTS_FILE" << EOF
{
  "validation_timestamp": "$(date -Iseconds)",
  "environment": "$ENVIRONMENT",
  "results": {
EOF
}

# Finalize results file
finalize_results() {
    cat >> "$RESULTS_FILE" << EOF
  },
  "summary": {
    "errors": $VALIDATION_ERRORS,
    "warnings": $VALIDATION_WARNINGS,
    "success": $([ $VALIDATION_ERRORS -eq 0 ] && echo "true" || echo "false")
  }
}
EOF
}

# Validate environment prerequisites
validate_prerequisites() {
    log_info "Validating environment prerequisites"

    # Check if running as root (should not be)
    if [[ $EUID -eq 0 ]]; then
        log_error "Validation script should not be run as root"
    fi

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
    else
        log_success "Docker is available: $(docker --version)"
    fi

    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
    else
        log_success "Docker Compose is available"
    fi

    # Check if kubectl is available (for Kubernetes validation)
    if command -v kubectl &> /dev/null; then
        log_success "kubectl is available: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
    else
        log_warning "kubectl is not available (Kubernetes validation will be skipped)"
    fi

    # Check if helm is available (for Helm charts validation)
    if command -v helm &> /dev/null; then
        log_success "Helm is available: $(helm version --short)"
    else
        log_warning "Helm is not available (Helm chart validation will be skipped)"
    fi

    # Check environment files
    local env_file="$PROJECT_ROOT/.env.$ENVIRONMENT"
    if [[ -f "$env_file" ]]; then
        log_success "Environment file found: $env_file"
    else
        log_error "Environment file not found: $env_file"
    fi

    # Check Docker Compose file for environment
    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
        log_success "Docker Compose file found: $compose_file"
    else
        log_error "Docker Compose file not found: $compose_file"
    fi

    log_success "Prerequisites validation completed"
}

# Validate security configurations
validate_security() {
    if [[ "$SKIP_SECURITY" == "true" ]]; then
        log_warning "Skipping security validation"
        return 0
    fi

    log_info "Validating security configurations"

    # Check for hardcoded secrets
    log_debug "Checking for hardcoded secrets"
    if grep -r -i "password\|secret\|key" "$PROJECT_ROOT/environments/$ENVIRONMENT/" --include="*.yml" --include="*.yaml" --include="*.env*" | grep -v "\${" > /dev/null; then
        log_warning "Potential hardcoded secrets found in environment files"
    else
        log_success "No hardcoded secrets detected"
    fi

    # Check Dockerfile security
    log_debug "Validating Dockerfile security"
    if grep -q "FROM.*:latest" "$PROJECT_ROOT/docker/Dockerfile"; then
        log_warning "Dockerfile uses :latest tag (should use specific version for production)"
    fi

    if grep -q "USER root\|USER 0" "$PROJECT_ROOT/docker/Dockerfile"; then
        log_error "Dockerfile runs as root user"
    else
        log_success "Dockerfile uses non-root user"
    fi

    # Check for security headers in Nginx configuration
    log_debug "Validating Nginx security configuration"
    local nginx_conf="$PROJECT_ROOT/docker/nginx/nginx.conf"
    if [[ -f "$nginx_conf" ]]; then
        if grep -q "add_header.*X-Frame-Options" "$nginx_conf" && \
           grep -q "add_header.*X-Content-Type-Options" "$nginx_conf" && \
           grep -q "add_header.*X-XSS-Protection" "$nginx_conf"; then
            log_success "Security headers configured in Nginx"
        else
            log_warning "Missing security headers in Nginx configuration"
        fi
    fi

    # Check TLS configuration
    log_debug "Validating TLS configuration"
    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
        if grep -q "443:443" "$compose_file"; then
            log_success "HTTPS port (443) is exposed"
        else
            log_warning "HTTPS port not exposed"
        fi
    fi

    # Check RBAC permissions in Kubernetes manifests
    local rbac_file="$PROJECT_ROOT/k8s/monitoring.yaml"
    if [[ -f "$rbac_file" ]]; then
        if grep -q "rules.*verbs.*\*" "$rbac_file"; then
            log_warning "Wildcard permissions found in RBAC rules"
        else
            log_success "RBAC permissions are properly scoped"
        fi
    fi

    log_success "Security validation completed"
}

# Validate performance configurations
validate_performance() {
    if [[ "$SKIP_PERFORMANCE" == "true" ]]; then
        log_warning "Skipping performance validation"
        return 0
    fi

    log_info "Validating performance configurations"

    # Check resource limits in Docker Compose
    log_debug "Validating Docker Compose resource limits"
    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
        if grep -q "deploy:" "$compose_file"; then
            local services_with_limits=$(grep -A 10 "deploy:" "$compose_file" | grep -c "limits:" || true)
            if [[ $services_with_limits -gt 0 ]]; then
                log_success "Resource limits are configured for services"
            else
                log_warning "No resource limits found in Docker Compose"
            fi
        else
            log_warning "No deployment configuration found in Docker Compose"
        fi
    fi

    # Check for health checks
    log_debug "Validating health check configurations"
    if grep -q "healthcheck:" "$compose_file" 2>/dev/null; then
        local health_checks=$(grep -c "healthcheck:" "$compose_file" || true)
        log_success "Health checks configured: $health_checks services"
    else
        log_warning "No health checks found in Docker Compose"
    fi

    # Check HPA configuration in Kubernetes
    log_debug "Validating HPA configuration"
    local hpa_file="$PROJECT_ROOT/k8s/cortex-mcp-deployment.yaml"
    if [[ -f "$hpa_file" ]]; then
        if grep -q "kind: HorizontalPodAutoscaler" "$hpa_file"; then
            log_success "HPA is configured for Kubernetes deployment"
        else
            log_warning "HPA not found in Kubernetes configuration"
        fi
    fi

    # Check for caching configurations
    log_debug "Validating caching configurations"
    if grep -q "redis\|cache" "$compose_file" 2>/dev/null; then
        log_success "Caching service is configured"
    else
        log_warning "No caching service found"
    fi

    # Check monitoring and metrics
    log_debug "Validating monitoring configuration"
    if grep -q "prometheus\|metrics" "$compose_file" 2>/dev/null; then
        log_success "Monitoring and metrics are configured"
    else
        log_warning "No monitoring configuration found"
    fi

    log_success "Performance validation completed"
}

# Validate backup configurations
validate_backup() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_warning "Skipping backup validation"
        return 0
    fi

    log_info "Validating backup configurations"

    # Check backup service configuration
    log_debug "Validating backup service"
    local compose_file="$PROJECT_ROOT/environments/$ENVIRONMENT/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
        if grep -q "backup" "$compose_file"; then
            log_success "Backup service is configured"
        else
            log_warning "No backup service found in configuration"
        fi
    fi

    # Check backup schedule configuration
    log_debug "Validating backup schedule"
    if grep -q "BACKUP_SCHEDULE" "$compose_file" 2>/dev/null; then
        log_success "Backup schedule is configured"
    else
        log_warning "No backup schedule found"
    fi

    # Check backup retention configuration
    log_debug "Validating backup retention"
    if grep -q "BACKUP_RETENTION_DAYS" "$compose_file" 2>/dev/null; then
        log_success "Backup retention is configured"
    else
        log_warning "No backup retention policy found"
    fi

    # Check for cloud backup configuration
    log_debug "Validating cloud backup configuration"
    if grep -q "S3_BUCKET\|AWS_ACCESS_KEY_ID" "$compose_file" 2>/dev/null; then
        log_success "Cloud backup is configured"
    else
        log_warning "No cloud backup configuration found"
    fi

    # Validate backup directory permissions
    local backup_dir="/opt/cortex-prod/backups"
    if [[ -d "$backup_dir" ]]; then
        local backup_dir_perms=$(stat -c "%a" "$backup_dir" 2>/dev/null || echo "000")
        if [[ "$backup_dir_perms" =~ ^[4567][0-9]{2}$ ]]; then
            log_success "Backup directory has secure permissions: $backup_dir_perms"
        else
            log_warning "Backup directory permissions may be too permissive: $backup_dir_perms"
        fi
    else
        log_warning "Backup directory not found: $backup_dir"
    fi

    log_success "Backup validation completed"
}

# Validate Kubernetes configurations
validate_kubernetes() {
    log_info "Validating Kubernetes configurations"

    if ! command -v kubectl &> /dev/null; then
        log_warning "kubectl not available, skipping Kubernetes validation"
        return 0
    fi

    # Check YAML syntax for all manifests
    log_debug "Validating Kubernetes manifest syntax"
    for yaml_file in "$PROJECT_ROOT"/k8s/*.yaml; do
        if [[ -f "$yaml_file" ]]; then
            if kubectl apply --dry-run=client -f "$yaml_file" &>/dev/null; then
                log_success "Valid YAML syntax: $(basename "$yaml_file")"
            else
                log_error "Invalid YAML syntax: $(basename "$yaml_file")"
            fi
        fi
    done

    # Check for required Kubernetes resources
    log_debug "Validating required Kubernetes resources"
    local required_resources=("namespace" "configmap" "deployment" "service")

    for resource in "${required_resources[@]}"; do
        if grep -r "kind: $resource" "$PROJECT_ROOT/k8s/" &>/dev/null; then
            log_success "Found $resource definition"
        else
            log_warning "Missing $resource definition"
        fi
    done

    # Validate namespace configuration
    log_debug "Validating namespace configuration"
    local namespace_file="$PROJECT_ROOT/k8s/namespace.yaml"
    if [[ -f "$namespace_file" ]]; then
        if grep -q "name: cortex-mcp" "$namespace_file"; then
            log_success "Cortex MCP namespace configured"
        else
            log_error "Cortex MCP namespace not found"
        fi
    fi

    # Validate resource requests and limits
    log_debug "Validating resource requests and limits"
    local deployment_file="$PROJECT_ROOT/k8s/cortex-mcp-deployment.yaml"
    if [[ -f "$deployment_file" ]]; then
        if grep -q "resources:" "$deployment_file"; then
            if grep -q "requests:" "$deployment_file" && grep -q "limits:" "$deployment_file"; then
                log_success "Both resource requests and limits are configured"
            else
                log_warning "Resource requests or limits missing"
            fi
        else
            log_warning "No resources configuration found"
        fi
    fi

    # Validate ingress configuration
    log_debug "Validating ingress configuration"
    local ingress_file="$PROJECT_ROOT/k8s/ingress.yaml"
    if [[ -f "$ingress_file" ]]; then
        if grep -q "tls:" "$ingress_file"; then
            log_success "TLS is configured in ingress"
        else
            log_warning "TLS not configured in ingress"
        fi
    fi

    log_success "Kubernetes validation completed"
}

# Validate monitoring configurations
validate_monitoring() {
    log_info "Validating monitoring configurations"

    # Check Prometheus configuration
    local prometheus_file="$PROJECT_ROOT/k8s/configmap.yaml"
    if [[ -f "$prometheus_file" ]]; then
        if grep -q "prometheus.yml" "$prometheus_file"; then
            log_success "Prometheus configuration found"
        else
            log_warning "Prometheus configuration not found"
        fi
    fi

    # Check Grafana configuration
    if grep -q "grafana" "$prometheus_file" 2>/dev/null; then
        log_success "Grafana configuration found"
    else
        log_warning "Grafana configuration not found"
    fi

    # Check alerting rules
    if grep -q "alerting\|rules" "$prometheus_file" 2>/dev/null; then
        log_success "Alerting rules are configured"
    else
        log_warning "No alerting rules found"
    fi

    # Check service monitors
    local monitoring_file="$PROJECT_ROOT/k8s/monitoring.yaml"
    if [[ -f "$monitoring_file" ]]; then
        if grep -q "ServiceMonitor" "$monitoring_file"; then
            log_success "ServiceMonitor configuration found"
        else
            log_warning "ServiceMonitor configuration not found"
        fi
    fi

    log_success "Monitoring validation completed"
}

# Validate network configurations
validate_networking() {
    log_info "Validating network configurations"

    # Check network policies
    local namespace_file="$PROJECT_ROOT/k8s/namespace.yaml"
    if [[ -f "$namespace_file" ]]; then
        if grep -q "NetworkPolicy" "$namespace_file"; then
            log_success "Network policies are configured"
        else
            log_warning "No network policies found"
        fi
    fi

    # Check ingress configurations
    local ingress_file="$PROJECT_ROOT/k8s/ingress.yaml"
    if [[ -f "$ingress_file" ]]; then
        if grep -q "annotations:" "$ingress_file"; then
            log_success "Ingress annotations are configured"
        else
            log_warning "No ingress annotations found"
        fi
    fi

    # Check service configurations
    local deployment_file="$PROJECT_ROOT/k8s/cortex-mcp-deployment.yaml"
    if [[ -f "$deployment_file" ]]; then
        if grep -q "Service" "$deployment_file"; then
            log_success "Service configurations found"
        else
            log_warning "No service configurations found"
        fi
    fi

    log_success "Networking validation completed"
}

# Run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests"

    cd "$PROJECT_ROOT"

    # Check if dependencies are installed
    if [[ ! -d "node_modules" ]]; then
        log_info "Installing dependencies for smoke tests"
        npm ci --silent
    fi

    # Run smoke tests
    if npm run test:smoke &>/dev/null; then
        log_success "Smoke tests passed"
    else
        log_error "Smoke tests failed"
    fi

    # Run health check if service is running
    if curl -f http://localhost:3000/health &>/dev/null; then
        log_success "Health check endpoint responding"
    else
        log_warning "Health check endpoint not responding"
    fi
}

# Generate validation report
generate_report() {
    log_info "Generating validation report"

    local report_file="validation-report-$(date +%Y%m%d-%H%M%S).md"
    local report_path="$PROJECT_ROOT/$report_file"

    cat > "$report_path" << EOF
# Cortex Memory MCP Production Validation Report

**Environment:** $ENVIRONMENT
**Generated:** $(date)
**Status:** $([ $VALIDATION_ERRORS -eq 0 ] && echo "✅ PASSED" || echo "❌ FAILED")

## Summary

- **Errors:** $VALIDATION_ERRORS
- **Warnings:** $VALIDATION_WARNINGS
- **Overall Status:** $([ $VALIDATION_ERRORS -eq 0 ] && echo "PASSED" || echo "FAILED")

## Validation Categories

### ✅ Prerequisites
Environment dependencies and tools validation

### ✅ Security
Security configurations and best practices validation

### ✅ Performance
Performance and resource management validation

### ✅ Backup
Backup and disaster recovery validation

### ✅ Kubernetes
Kubernetes manifests and configurations validation

### ✅ Monitoring
Monitoring and alerting validation

### ✅ Networking
Network and ingress configuration validation

### ✅ Smoke Tests
Application health and functionality validation

## Recommendations

EOF

    if [[ $VALIDATION_WARNINGS -gt 0 ]]; then
        cat >> "$report_path" << EOF
### Address Warnings
- Review all warnings and address high-priority items
- Implement recommended security hardening measures
- Consider performance optimization suggestions

EOF
    fi

    if [[ $VALIDATION_ERRORS -gt 0 ]]; then
        cat >> "$report_path" << EOF
### Fix Errors
- Address all errors before production deployment
- Review failed validation steps
- Implement required fixes and re-run validation

EOF
    fi

    cat >> "$report_path" << EOF
## Next Steps

1. Review the detailed validation results
2. Address any errors or warnings
3. Re-run validation if changes were made
4. Proceed with deployment if validation passes

## Files Referenced

- Environment configuration: \`environments/$ENVIRONMENT/docker-compose.yml\`
- Kubernetes manifests: \`k8s/\`
- Security configurations: \`security/\`

**Report generated by:** Cortex MCP Production Validation Script
EOF

    log_success "Validation report generated: $report_path"
}

# Main validation function
main() {
    echo "Cortex Memory MCP Production Validation"
    echo "======================================"
    echo "Environment: $ENVIRONMENT"
    echo "Started at: $(date)"
    echo

    # Initialize results
    init_results

    # Run validations
    validate_prerequisites
    validate_security
    validate_performance
    validate_backup
    validate_kubernetes
    validate_monitoring
    validate_networking
    run_smoke_tests

    # Finalize results
    finalize_results

    # Generate report
    generate_report

    echo
    echo "Validation Summary"
    echo "=================="
    echo "Errors: $VALIDATION_ERRORS"
    echo "Warnings: $VALIDATION_WARNINGS"
    echo "Results file: $RESULTS_FILE"
    echo

    if [[ $VALIDATION_ERRORS -eq 0 ]]; then
        echo -e "${GREEN}✅ VALIDATION PASSED${NC}"
        log_success "All validations passed successfully"
        exit 0
    else
        echo -e "${RED}❌ VALIDATION FAILED${NC}"
        log_error "Validation failed with $VALIDATION_ERRORS error(s)"
        exit 1
    fi
}

# Parse arguments and run main function
parse_args "$@"
main

exit 0