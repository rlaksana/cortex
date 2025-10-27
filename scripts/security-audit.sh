#!/bin/bash
# ============================================================================
# CORTEX MEMORY MCP - SECURITY AUDIT SCRIPT
# ============================================================================
# Comprehensive security audit and vulnerability scanning for dual database setup

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../config/security/security-hardening.yaml"
REPORT_DIR="${SCRIPT_DIR}/../reports/security-audit"
TEMP_DIR="/tmp/cortex-security-audit-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}"
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

# Initialize
init() {
    log "Initializing security audit..."
    mkdir -p "$REPORT_DIR"
    mkdir -p "$TEMP_DIR"
    trap "rm -rf $TEMP_DIR" EXIT

    # Load configuration if exists
    if [[ -f "$CONFIG_FILE" ]]; then
        log "Loading security configuration..."
        # Parse YAML using basic tools (since we don't have yq)
        # This is simplified - in production, use proper YAML parser
    fi

    log "Security audit initialized"
}

# Check dependencies
check_dependencies() {
    log "Checking security audit dependencies..."

    local missing_deps=()
    local deps=("docker" "kubectl" "curl" "jq" "openssl" "nmap" "nikto" "trivy" "gitleaks")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        else
            log "✓ $dep is available"
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        error "Please install missing dependencies before running security audit"
        exit 1
    fi

    success "All dependencies are available"
}

# Container security scan
scan_containers() {
    log "Scanning container security..."

    local containers=("cortex-postgres" "cortex-qdrant" "cortex-app" "cortex-redis" "cortex-nginx")
    local report_file="$REPORT_DIR/container-security.json"

    echo "[" > "$report_file"

    local first=true
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "^${container}$"; then
            log "Scanning container: $container"

            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$report_file"
            fi

            # Run Trivy scan
            local trivy_report="$TEMP_DIR/${container}-trivy.json"
            if trivy image --format json --output "$trivy_report" "${container}:latest" 2>/dev/null; then
                log "✓ Trivy scan completed for $container"
            else
                log "⚠ Trivy scan failed for $container"
                echo '{"scan_status": "failed"}' > "$trivy_report"
            fi

            # Extract container info
            local container_info=$(docker inspect "$container" --format='{{json .}}')
            local image_id=$(echo "$container_info" | jq -r '.Image' | cut -d: -f2 | cut -c1-12)

            # Generate container security report
            cat >> "$report_file" << EOF
{
    "container": "$container",
    "image_id": "$image_id",
    "scan_timestamp": "$(date -Iseconds)",
    "trivy_scan": $(cat "$trivy_report"),
    "security_context": $(docker inspect "$container" --format='{{json .HostConfig}}' | jq '{
        user: .User,
        privileged: .Privileged,
        readonly_rootfs: .ReadonlyRootfs,
        cap_add: .CapAdd,
        cap_drop: .CapDrop,
        security_opt: .SecurityOpt
    }'),
    "mounts": $(docker inspect "$container" --format='{{json .Mounts}}')
}
EOF
        else
            log "⚠ Container $container not running"
        fi
    done

    echo "]" >> "$report_file"
    success "Container security scan completed"
}

# Kubernetes security scan
scan_kubernetes() {
    log "Scanning Kubernetes security..."

    local report_file="$REPORT_DIR/kubernetes-security.json"

    # Check if kubectl is configured
    if ! kubectl cluster-info &> /dev/null; then
        warning "kubectl not configured, skipping Kubernetes security scan"
        return 0
    fi

    echo "[" > "$report_file"

    local first=true

    # Scan RBAC
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    cat >> "$report_file" << EOF
{
    "component": "rbac",
    "scan_timestamp": "$(date -Iseconds)",
    "roles": $(kubectl get roles -A -o json | jq '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        rules: .rules
    }'),
    "cluster_roles": $(kubectl get clusterroles -o json | jq '.items[] | {
        name: .metadata.name,
        rules: .rules
    }'),
    "role_bindings": $(kubectl get rolebindings -A -o json | jq '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        roleRef: .roleRef,
        subjects: .subjects
    }')
}
EOF

    # Scan Network Policies
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    cat >> "$report_file" << EOF
{
    "component": "network_policies",
    "scan_timestamp": "$(date -Iseconds)",
    "policies": $(kubectl get networkpolicies -A -o json | jq '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        pod_selector: .spec.podSelector,
        policy_types: .spec.policyTypes,
        ingress: .spec.ingress,
        egress: .spec.egress
    }')
}
EOF

    # Scan Pod Security
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    cat >> "$report_file" << EOF
{
    "component": "pod_security",
    "scan_timestamp": "$(date -Iseconds)",
    "pods": $(kubectl get pods -A -o json | jq '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        security_context: .spec.securityContext,
        containers: [.spec.containers[] | {
            name: .name,
            security_context: .securityContext,
            image: .image
        }]
    }')
}
EOF

    # Scan Secrets
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    cat >> "$report_file" << EOF
{
    "component": "secrets",
    "scan_timestamp": "$(date -Iseconds)",
    "secrets": $(kubectl get secrets -A -o json | jq '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        type: .type,
        data_keys: (.data | keys)
    }')
}
EOF

    echo "]" >> "$report_file"
    success "Kubernetes security scan completed"
}

# Network security scan
scan_network() {
    log "Scanning network security..."

    local report_file="$REPORT_DIR/network-security.json"
    local target_host="${TARGET_HOST:-localhost}"
    local target_ports="5432 6333 6334 6379 3000 80 443"

    echo "[" > "$report_file"

    local first=true

    for port in $target_ports; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$report_file"
        fi

        # Port scan
        local port_result="closed"
        if timeout 5 bash -c "</dev/tcp/$target_host/$port" 2>/dev/null; then
            port_result="open"
        fi

        # Service detection
        local service_info="unknown"
        case "$port" in
            5432) service_info="PostgreSQL" ;;
            6333) service_info="Qdrant HTTP" ;;
            6334) service_info="Qdrant gRPC" ;;
            6379) service_info="Redis" ;;
            3000) service_info="Cortex App" ;;
            80) service_info="HTTP" ;;
            443) service_info="HTTPS" ;;
        esac

        cat >> "$report_file" << EOF
{
    "host": "$target_host",
    "port": $port,
    "status": "$port_result",
    "service": "$service_info",
    "scan_timestamp": "$(date -Iseconds)"
}
EOF
    done

    # SSL/TLS scan
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    local ssl_result="{}"
    if timeout 10 openssl s_client -connect "$target_host:443" -servername "$target_host" </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null; then
        local cert_info=$(timeout 10 openssl s_client -connect "$target_host:443" -servername "$target_host" </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
        ssl_result=$(cat << EOF
{
    "certificate_valid": true,
    "details": $(echo "$cert_info" | sed 's/^/"/;s/$/\\n"/' | tr -d '\n' | sed 's/\\n$//')
}
EOF
)
    else
        ssl_result='{"certificate_valid": false}'
    fi

    cat >> "$report_file" << EOF
{
    "host": "$target_host",
    "port": 443,
    "ssl_scan": $ssl_result,
    "scan_timestamp": "$(date -Iseconds)"
}
EOF

    echo "]" >> "$report_file"
    success "Network security scan completed"
}

# Application security scan
scan_application() {
    log "Scanning application security..."

    local report_file="$REPORT_DIR/application-security.json"
    local app_url="${APP_URL:-http://localhost:3000}"

    echo "[" > "$report_file"

    local first=true

    # HTTP headers scan
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    local headers_response=$(curl -s -I "$app_url" 2>/dev/null || echo "")
    local security_headers=$(echo "$headers_response" | grep -i -E "(x-frame-options|x-content-type-options|x-xss-protection|strict-transport-security|content-security-policy)" || echo "none")

    cat >> "$report_file" << EOF
{
    "scan_type": "security_headers",
    "url": "$app_url",
    "timestamp": "$(date -Iseconds)",
    "security_headers": "$security_headers",
    "headers_present": $(echo "$security_headers" | wc -l)
}
EOF

    # Web vulnerability scan (Nikto)
    if command -v nikto &> /dev/null; then
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$report_file"
        fi

        local nikto_output="$TEMP_DIR/nikto_output.txt"
        if nikto -h "$app_url" -output "$nikto_output" 2>/dev/null; then
            local vulnerabilities=$(grep -c "OSVDB-" "$nikto_output" 2>/dev/null || echo "0")
            cat >> "$report_file" << EOF
{
    "scan_type": "web_vulnerabilities",
    "url": "$app_url",
    "timestamp": "$(date -Iseconds)",
    "scanner": "nikto",
    "vulnerabilities_found": $vulnerabilities,
    "raw_output": $(cat "$nikto_output" | jq -Rs .)
}
EOF
        else
            cat >> "$report_file" << EOF
{
    "scan_type": "web_vulnerabilities",
    "url": "$app_url",
    "timestamp": "$(date -Iseconds)",
    "scanner": "nikto",
    "status": "failed"
}
EOF
        fi
    fi

    echo "]" >> "$report_file"
    success "Application security scan completed"
}

# Secrets scan
scan_secrets() {
    log "Scanning for leaked secrets..."

    local report_file="$REPORT_DIR/secrets-scan.json"

    # GitLeaks scan
    if command -v gitleaks &> /dev/null; then
        local gitleaks_output="$TEMP_DIR/gitleaks_output.json"
        if gitleaks detect --source "${SCRIPT_DIR}/.." --report-path "$gitleaks_output" --report-format json 2>/dev/null; then
            log "✓ GitLeaks scan completed"
        else
            log "⚠ GitLeaks scan failed or no secrets found"
            echo '{"findings": []}' > "$gitleaks_output"
        fi

        cat > "$report_file" << EOF
{
    "scan_timestamp": "$(date -Iseconds)",
    "scanner": "gitleaks",
    "findings": $(cat "$gitleaks_output" | jq '.[]? // []')
}
EOF
    else
        warning "GitLeaks not available, skipping secrets scan"
        echo '{"scan_timestamp": "'$(date -Iseconds)'", "scanner": "none", "findings": []}' > "$report_file"
    fi

    success "Secrets scan completed"
}

# Database security audit
audit_databases() {
    log "Auditing database security..."

    local report_file="$REPORT_DIR/database-security.json"

    echo "[" > "$report_file"

    local first=true

    # PostgreSQL security audit
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    local postgres_host="${POSTGRES_HOST:-localhost}"
    local postgres_user="${POSTGRES_USER:-cortex}"
    local postgres_db="${POSTGRES_DB:-cortex_prod}"

    local postgres_security="{}"
    if PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$postgres_host" -U "$postgres_user" -d "$postgres_db" -t -c "SELECT version();" &>/dev/null; then
        local pg_version=$(PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$postgres_host" -U "$postgres_user" -d "$postgres_db" -t -c "SELECT version();" 2>/dev/null | xargs)
        local user_count=$(PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$postgres_host" -U "$postgres_user" -d "$postgres_db" -t -c "SELECT count(*) FROM pg_roles;" 2>/dev/null | xargs)
        local ssl_setting=$(PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$postgres_host" -U "$postgres_user" -d "$postgres_db" -t -c "SHOW ssl;" 2>/dev/null | xargs)

        postgres_security=$(cat << EOF
{
    "accessible": true,
    "version": "$pg_version",
    "user_count": $user_count,
    "ssl_enabled": "$ssl_setting"
}
EOF
)
    else
        postgres_security='{"accessible": false}'
    fi

    cat >> "$report_file" << EOF
{
    "database": "postgresql",
    "security_audit": $postgres_security,
    "scan_timestamp": "$(date -Iseconds)"
}
EOF

    # Qdrant security audit
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo "," >> "$report_file"
    fi

    local qdrant_host="${QDRANT_HOST:-localhost}"
    local qdrant_port="${QDRANT_PORT:-6333}"

    local qdrant_security="{}"
    if curl -s "http://${qdrant_host}:${qdrant_port}/version" &>/dev/null; then
        local qdrant_version=$(curl -s "http://${qdrant_host}:${qdrant_port}/version" | jq -r '.result.version' 2>/dev/null || echo "unknown")
        local collections_count=$(curl -s "http://${qdrant_host}:${qdrant_port}/collections" | jq '.result.collections | length' 2>/dev/null || echo "0")

        qdrant_security=$(cat << EOF
{
    "accessible": true,
    "version": "$qdrant_version",
    "collections_count": $collections_count,
    "api_key_required": "${QDRANT_API_KEY:+true}"
}
EOF
)
    else
        qdrant_security='{"accessible": false}'
    fi

    cat >> "$report_file" << EOF
{
    "database": "qdrant",
    "security_audit": $qdrant_security,
    "scan_timestamp": "$(date -Iseconds)"
}
EOF

    echo "]" >> "$report_file"
    success "Database security audit completed"
}

# Generate summary report
generate_summary() {
    log "Generating security audit summary..."

    local summary_file="$REPORT_DIR/security-summary.md"
    local timestamp=$(date -Iseconds)

    cat > "$summary_file" << EOF
# Cortex Memory MCP - Security Audit Summary

**Generated:** $timestamp
**Environment:** ${ENVIRONMENT:-development}

## Executive Summary

This security audit covers the following areas:
- Container Security
- Kubernetes Security
- Network Security
- Application Security
- Secrets Management
- Database Security

## Findings Overview

### Container Security
- Total containers scanned: $(docker ps --format "table {{.Names}}" | grep -c "cortex" || echo "0")
- Vulnerabilities detected: $(jq '[.[] | select(.trivy_scan.Results? | length > 0)] | length' "$REPORT_DIR/container-security.json" 2>/dev/null || echo "0")

### Kubernetes Security
- Namespaces scanned: $(kubectl get namespaces -o name | grep -c "cortex" 2>/dev/null || echo "0")
- Network policies found: $(jq '[.[] | select(.component == "network_policies")] | .policies | length' "$REPORT_DIR/kubernetes-security.json" 2>/dev/null || echo "0")

### Network Security
- Open ports detected: $(jq '[.[] | select(.status == "open")] | length' "$REPORT_DIR/network-security.json" 2>/dev/null || echo "0")
- SSL certificates: $(jq '[.[] | select(.ssl_scan.certificate_valid == true)] | length' "$REPORT_DIR/network-security.json" 2>/dev/null || echo "0")

### Application Security
- Security headers present: $(jq '[.[] | select(.scan_type == "security_headers")] | .headers_present' "$REPORT_DIR/application-security.json" 2>/dev/null || echo "0")
- Web vulnerabilities: $(jq '[.[] | select(.scan_type == "web_vulnerabilities")] | .vulnerabilities_found' "$REPORT_DIR/application-security.json" 2>/dev/null || echo "0")

### Secrets Management
- Secrets detected: $(jq '.findings | length' "$REPORT_DIR/secrets-scan.json" 2>/dev/null || echo "0")

### Database Security
- PostgreSQL accessible: $(jq '[.[] | select(.database == "postgresql")] | .security_audit.accessible' "$REPORT_DIR/database-security.json" 2>/dev/null || echo "false")
- Qdrant accessible: $(jq '[.[] | select(.database == "qdrant")] | .security_audit.accessible' "$REPORT_DIR/database-security.json" 2>/dev/null || echo "false")

## Recommendations

### High Priority
1. Review and patch any critical vulnerabilities found in containers
2. Ensure all databases require authentication
3. Implement proper network segmentation
4. Enable SSL/TLS for all external communications

### Medium Priority
1. Regular security scans and updates
2. Implement security headers for web applications
3. Monitor for secret leaks in code repositories
4. Enable audit logging for all database operations

### Low Priority
1. Regular security training for development team
2. Document security procedures
3. Implement automated security testing in CI/CD

## Detailed Reports

- [Container Security](container-security.json)
- [Kubernetes Security](kubernetes-security.json)
- [Network Security](network-security.json)
- [Application Security](application-security.json)
- [Secrets Scan](secrets-scan.json)
- [Database Security](database-security.json)

---

*This report was generated automatically by the Cortex Memory MCP Security Audit Script*
EOF

    success "Security audit summary generated: $summary_file"
}

# Main execution
main() {
    log "Starting comprehensive security audit..."

    init
    check_dependencies

    # Run all security scans
    scan_containers
    scan_kubernetes
    scan_network
    scan_application
    scan_secrets
    audit_databases

    # Generate summary
    generate_summary

    success "Security audit completed successfully!"
    log "Detailed reports available in: $REPORT_DIR"
    log "Summary report: $REPORT_DIR/security-summary.md"

    # Exit with appropriate code based on findings
    local total_issues=0
    total_issues=$(jq '[.[] | select(.trivy_scan.Results? | length > 0)] | length' "$REPORT_DIR/container-security.json" 2>/dev/null || echo "0")
    total_issues=$((total_issues + $(jq '[.[] | select(.scan_type == "web_vulnerabilities")] | .vulnerabilities_found' "$REPORT_DIR/application-security.json" 2>/dev/null || echo "0")))
    total_issues=$((total_issues + $(jq '.findings | length' "$REPORT_DIR/secrets-scan.json" 2>/dev/null || echo "0")))

    if [[ $total_issues -gt 0 ]]; then
        warning "Security audit found $total_issues issue(s) that require attention"
        exit 1
    else
        success "No critical security issues found"
        exit 0
    fi
}

# Execute main function
main "$@"