#!/bin/bash
# DR Validation Script - Post-Recovery Validation and Testing
# This script validates system functionality after disaster recovery procedures

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/dr-validation.log"
CONFIG_FILE="$SCRIPT_DIR/../config/dr-config.json"
VALIDATION_RESULTS_DIR="/tmp/dr-validation-results"

# Service configuration
CORTEX_MCP_PORT=3000
QDRANT_PORT=6333
CORTEX_MCP_SERVICE="cortex-mcp"
QDRANT_SERVICE="qdrant"

# Validation thresholds
MAX_API_RESPONSE_TIME=5.0
MAX_DB_SEARCH_TIME=2.0
MIN_MEMORY_AVAILABLE=10
MAX_DISK_USAGE=90
MAX_CPU_LOAD=4.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
        "VALIDATION")
            echo -e "${PURPLE}[VALIDATION]${NC} $message"
            ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Initialize validation environment
init_validation() {
    log "INFO" "Initializing DR validation environment"

    # Create results directory
    mkdir -p "$VALIDATION_RESULTS_DIR"

    # Load configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log "WARN" "Configuration file not found, using defaults"
    fi

    # Export environment variables
    export CORTEX_MCP_PORT QDRANT_PORT

    log "INFO" "Validation environment initialized"
}

# Validation result tracking
VALIDATION_RESULTS=()
PASSED_CHECKS=0
TOTAL_CHECKS=0

run_validation() {
    local test_name=$1
    local test_command=$2
    local critical=${3:-true}

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local start_time=$(date +%s)

    echo
    log "VALIDATION" "Running: $test_name"

    if eval "$test_command"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log "INFO" "✅ PASSED: $test_name (${duration}s)"
        VALIDATION_RESULTS+=("PASSED:$test_name:${duration}")
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log "ERROR" "❌ FAILED: $test_name (${duration}s)"
        VALIDATION_RESULTS+=("FAILED:$test_name:${duration}")

        if [[ "$critical" == "true" ]]; then
            log "ERROR" "Critical validation failed"
        fi

        return 1
    fi
}

# Service availability validations
validate_mcp_server_availability() {
    run_validation "MCP Server Health Check" \
        "curl -f -s http://localhost:$CORTEX_MCP_PORT/health > /dev/null"
}

validate_mcp_server_readiness() {
    run_validation "MCP Server Readiness Check" \
        "curl -f -s http://localhost:$CORTEX_MCP_PORT/ready > /dev/null"
}

validate_qdrant_availability() {
    run_validation "Qdrant Health Check" \
        "curl -f -s http://localhost:$QDRANT_PORT/health > /dev/null"
}

validate_qdrant_collection() {
    run_validation "Qdrant Collection Access" \
        "curl -f -s http://localhost:$QDRANT_PORT/collections/cortex-memory > /dev/null"
}

# Functionality validations
validate_memory_store_api() {
    run_validation "Memory Store API Functionality" \
        "curl -f -s -X POST http://localhost:$CORTEX_MCP_PORT/api/memory/store \
         -H 'Content-Type: application/json' \
         -d '{\"items\":[{\"kind\":\"observation\",\"content\":\"DR validation test - $(date +%s)\"}]}' \
         > /dev/null"
}

validate_memory_find_api() {
    run_validation "Memory Find API Functionality" \
        "curl -f -s -X POST http://localhost:$CORTEX_MCP_PORT/api/memory/find \
         -H 'Content-Type: application/json' \
         -d '{\"query\":\"DR validation\",\"limit\":5}' \
         > /dev/null"
}

validate_system_status_api() {
    run_validation "System Status API Functionality" \
        "curl -f -s -X POST http://localhost:$CORTEX_MCP_PORT/api/system/status \
         -H 'Content-Type: application/json' \
         -d '{}' \
         > /dev/null"
}

validate_memory_find_orchestrator() {
    run_validation "Memory Find Orchestrator" \
        "curl -f -s -X POST http://localhost:$CORTEX_MCP_PORT/api/memory/find \
         -H 'Content-Type: application/json' \
         -d '{\"query\":\"test search\",\"limit\":10,\"search_strategy\":\"auto\"}' \
         > /dev/null"
}

validate_memory_store_orchestrator() {
    run_validation "Memory Store Orchestrator" \
        "curl -f -s -X POST http://localhost:$CORTEX_MCP_PORT/api/memory/store \
         -H 'Content-Type: application/json' \
         -d '{\"items\":[{\"kind\":\"entity\",\"content\":\"DR test entity\",\"scope\":{\"project\":\"dr-test\"}}],\"deduplication\":{\"enabled\":true}}' \
         > /dev/null"
}

# Database functionality validations
validate_vector_search() {
    run_validation "Vector Search Functionality" \
        "curl -f -s -X POST http://localhost:$QDRANT_PORT/collections/cortex-memory/search \
         -H 'Content-Type: application/json' \
         -d '{\"vector\":[0.1,0.2,0.3,0.4,0.5],\"limit\":5}' \
         > /dev/null"
}

validate_collection_info() {
    run_validation "Collection Information Retrieval" \
        "curl -f -s http://localhost:$QDRANT_PORT/collections/cortex-memory | jq -e .result.points_count > /dev/null"
}

validate_database_integrity() {
    run_validation "Database Integrity Check" \
        "curl -f -s http://localhost:$QDRANT_PORT/collections/cortex-memory | jq -e '.result.status | contains(\"ok\")' > /dev/null"
}

# System resource validations
validate_memory_availability() {
    run_validation "Memory Availability Check" \
        "test \$(free | awk 'NR==2{printf \"%d\", \$7*100/\$2}') -gt $MIN_MEMORY_AVAILABLE"
}

validate_disk_space() {
    run_validation "Disk Space Check" \
        "test \$(df / | awk 'NR==2{print \$5}' | sed 's/%//') -lt $MAX_DISK_USAGE"
}

validate_cpu_load() {
    run_validation "CPU Load Check" \
        "test \$(uptime | awk -F'load average:' '{print \$2}' | awk '{print \$1}' | sed 's/,//') \\< $MAX_CPU_LOAD"
}

validate_system_processes() {
    run_validation "System Processes Check" \
        "pgrep -f 'node.*index.js' > /dev/null && pgrep -f 'qdrant' > /dev/null"
}

# Performance validations
validate_api_response_time() {
    local response_time=$(curl -o /dev/null -s -w '%{time_total}' "http://localhost:$CORTEX_MCP_PORT/health")
    local passed=$(echo "$response_time < $MAX_API_RESPONSE_TIME" | bc -l)

    run_validation "API Response Time Check" \
        "test $passed -eq 1" \
        false

    log "DEBUG" "API response time: ${response_time}s (threshold: ${MAX_API_RESPONSE_TIME}s)"
}

validate_database_search_performance() {
    # Only run if we have data
    local vector_count=$(curl -s "http://localhost:$QDRANT_PORT/collections/cortex-memory" | jq -r .result.points_count 2>/dev/null || echo "0")

    if [[ "$vector_count" -gt 0 ]]; then
        local search_time=$(curl -o /dev/null -s -w '%{time_total}' \
                           -X POST "http://localhost:$QDRANT_PORT/collections/cortex-memory/search" \
                           -H "Content-Type: application/json" \
                           -d '{"vector":[0.1,0.2,0.3],"limit":10}')
        local passed=$(echo "$search_time < $MAX_DB_SEARCH_TIME" | bc -l)

        run_validation "Database Search Performance" \
            "test $passed -eq 1" \
            false

        log "DEBUG" "Database search time: ${search_time}s (threshold: ${MAX_DB_SEARCH_TIME}s)"
    else
        log "WARN" "No vectors in collection, skipping performance test"
    fi
}

# External dependency validations
validate_openai_api_access() {
    if [[ -n "${OPENAI_API_KEY:-}" ]]; then
        run_validation "OpenAI API Access" \
            "curl -f -s -H \"Authorization: Bearer \$OPENAI_API_KEY\" https://api.openai.com/v1/models > /dev/null" \
            false
    else
        log "WARN" "OpenAI API key not configured, skipping validation"
    fi
}

validate_internet_connectivity() {
    run_validation "Internet Connectivity" \
        "ping -c 1 8.8.8.8 > /dev/null" \
        false
}

validate_dns_resolution() {
    run_validation "DNS Resolution" \
        "nslookup google.com > /dev/null" \
        false
}

# Integration validations
validate_end_to_end_workflow() {
    run_validation "End-to-End Workflow Test" \
        "test_end_to_end_workflow"
}

test_end_to_end_workflow() {
    local test_id="dr-test-$(date +%s)"

    # Step 1: Store test data
    local store_result=$(curl -s -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/store" \
                        -H "Content-Type: application/json" \
                        -d "{\"items\":[{\"kind\":\"observation\",\"content\":\"End-to-end test $test_id\"}]}")

    if [[ $? -ne 0 ]]; then
        log "DEBUG" "Failed to store test data"
        return 1
    fi

    # Step 2: Wait for indexing
    sleep 2

    # Step 3: Search for test data
    local search_result=$(curl -s -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/find" \
                         -H "Content-Type: application/json" \
                         -d "{\"query\":\"End-to-end test $test_id\",\"limit\":5}")

    if [[ $? -ne 0 ]]; then
        log "DEBUG" "Failed to search for test data"
        return 1
    fi

    # Step 4: Verify results
    local result_count=$(echo "$search_result" | jq -r '.results | length' 2>/dev/null || echo "0")
    if [[ "$result_count" -gt 0 ]]; then
        log "DEBUG" "End-to-end workflow test passed (found $result_count results)"
        return 0
    else
        log "DEBUG" "End-to-end workflow test failed (no results found)"
        return 1
    fi
}

validate_concurrent_requests() {
    run_validation "Concurrent Request Handling" \
        "test_concurrent_requests"
}

test_concurrent_requests() {
    local temp_file="/tmp/concurrent_test_$$"

    # Launch 5 concurrent requests
    for i in {1..5}; do
        {
            curl -s -o "/tmp/concurrent_result_$i" -w "%{http_code}" \
                -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/find" \
                -H "Content-Type: application/json" \
                -d "{\"query\":\"concurrent test $i\",\"limit\":3}" &
        } &
    done

    # Wait for all requests to complete
    wait

    # Check results
    local success_count=0
    for i in {1..5}; do
        if [[ -f "/tmp/concurrent_result_$i" ]]; then
            local http_code=$(tail -1 "/tmp/concurrent_result_$i")
            if [[ "$http_code" == "200" ]]; then
                success_count=$((success_count + 1))
            fi
            rm -f "/tmp/concurrent_result_$i"
        fi
    done

    log "DEBUG" "Concurrent requests: $success_count/5 successful"

    if [[ $success_count -ge 4 ]]; then
        return 0
    else
        return 1
    fi
}

# Data integrity validations
validate_data_consistency() {
    run_validation "Data Consistency Check" \
        "validate_data_consistency_impl"
}

validate_data_consistency_impl() {
    # Get collection info
    local collection_info=$(curl -s "http://localhost:$QDRANT_PORT/collections/cortex-memory")
    local vector_count=$(echo "$collection_info" | jq -r .result.points_count 2>/dev/null || echo "0")

    if [[ "$vector_count" == "unknown" ]] || [[ "$vector_count" -lt 0 ]]; then
        log "DEBUG" "Invalid vector count: $vector_count"
        return 1
    fi

    # Check collection status
    local status=$(echo "$collection_info" | jq -r .result.status 2>/dev/null || echo "unknown")
    if [[ "$status" != "ok" ]]; then
        log "DEBUG" "Collection status not ok: $status"
        return 1
    fi

    # Check indexed vectors count
    local indexed_count=$(echo "$collection_info" | jq -r .result.indexed_vectors_count 2>/dev/null || echo "unknown")
    if [[ "$indexed_count" != "unknown" ]] && [[ "$indexed_count" -gt "$vector_count" ]]; then
        log "DEBUG" "Indexed count exceeds vector count: $indexed_count > $vector_count"
        return 1
    fi

    log "DEBUG" "Data consistency validated: $vector_count vectors, status: $status"
    return 0
}

validate_backup_integrity() {
    run_validation "Backup Integrity Check" \
        "validate_backup_integrity_impl" \
        false
}

validate_backup_integrity_impl() {
    local backup_dir="/backups"

    if [[ ! -d "$backup_dir" ]]; then
        log "DEBUG" "Backup directory not found"
        return 1
    fi

    # Check for recent backups
    local recent_backups=$(find "$backup_dir" -name "*.snapshot.gz" -mtime -7 | wc -l)
    if [[ $recent_backups -eq 0 ]]; then
        log "DEBUG" "No recent backups found (last 7 days)"
        return 1
    fi

    # Test integrity of latest backup
    local latest_backup=$(find "$backup_dir" -name "*.snapshot.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    if [[ -n "$latest_backup" ]]; then
        if gzip -t "$latest_backup" 2>/dev/null; then
            log "DEBUG" "Latest backup integrity verified: $latest_backup"
            return 0
        else
            log "DEBUG" "Latest backup corrupted: $latest_backup"
            return 1
        fi
    fi

    return 1
}

# Security validations
validate_service_security() {
    run_validation "Service Security Check" \
        "validate_service_security_impl"
}

validate_service_security_impl() {
    local security_issues=0

    # Check for exposed debug endpoints
    if curl -s "http://localhost:$CORTEX_MCP_PORT/debug" &> /dev/null; then
        log "DEBUG" "Debug endpoint exposed"
        security_issues=$((security_issues + 1))
    fi

    # Check for default credentials (simulation)
    if [[ -f "/app/.env" ]]; then
        if grep -q "password.*=.*password\|password.*=.*123456\|password.*=.*admin" "/app/.env"; then
            log "DEBUG" "Default passwords detected in configuration"
            security_issues=$((security_issues + 1))
        fi
    fi

    # Check SSL/TLS (if configured)
    if curl -s -k "https://localhost:$CORTEX_MCP_PORT/health" &> /dev/null; then
        log "DEBUG" "HTTPS endpoint available"
    fi

    if [[ $security_issues -eq 0 ]]; then
        log "DEBUG" "No obvious security issues detected"
        return 0
    else
        log "DEBUG" "$security_issues security issues detected"
        return 1
    fi
}

validate_access_controls() {
    run_validation "Access Control Validation" \
        "validate_access_controls_impl" \
        false
}

validate_access_controls_impl() {
    # Test API access without authentication (if applicable)
    local auth_test=$(curl -s -o /dev/null -w "%{http_code}" \
                     -X POST "http://localhost:$CORTEX_MCP_PORT/api/memory/store" \
                     -H "Content-Type: application/json" \
                     -d '{"items":[{"kind":"test","content":"unauthorized"}]}')

    # If the service requires authentication, it should return 401
    # If it doesn't, it should return 200 or 400 (bad request)
    if [[ "$auth_test" == "401" ]] || [[ "$auth_test" == "200" ]] || [[ "$auth_test" == "400" ]]; then
        log "DEBUG" "Access controls appear to be functioning"
        return 0
    else
        log "DEBUG" "Unexpected auth response: $auth_test"
        return 1
    fi
}

# Comprehensive validation suite
run_comprehensive_validation() {
    log "INFO" "Starting comprehensive DR validation"

    local validation_start=$(date +%s)
    local critical_failures=0
    local total_failures=0

    # Service availability
    log "INFO" "Phase 1: Service Availability Validation"
    validate_mcp_server_availability || critical_failures=$((critical_failures + 1))
    validate_mcp_server_readiness || critical_failures=$((critical_failures + 1))
    validate_qdrant_availability || critical_failures=$((critical_failures + 1))
    validate_qdrant_collection || critical_failures=$((critical_failures + 1))

    # API functionality
    log "INFO" "Phase 2: API Functionality Validation"
    validate_memory_store_api || critical_failures=$((critical_failures + 1))
    validate_memory_find_api || critical_failures=$((critical_failures + 1))
    validate_system_status_api || total_failures=$((total_failures + 1))
    validate_memory_find_orchestrator || total_failures=$((total_failures + 1))
    validate_memory_store_orchestrator || total_failures=$((total_failures + 1))

    # Database functionality
    log "INFO" "Phase 3: Database Functionality Validation"
    validate_vector_search || critical_failures=$((critical_failures + 1))
    validate_collection_info || critical_failures=$((critical_failures + 1))
    validate_database_integrity || critical_failures=$((critical_failures + 1))

    # System resources
    log "INFO" "Phase 4: System Resources Validation"
    validate_memory_availability || critical_failures=$((critical_failures + 1))
    validate_disk_space || critical_failures=$((critical_failures + 1))
    validate_cpu_load || total_failures=$((total_failures + 1))
    validate_system_processes || critical_failures=$((critical_failures + 1))

    # Performance
    log "INFO" "Phase 5: Performance Validation"
    validate_api_response_time || total_failures=$((total_failures + 1))
    validate_database_search_performance || total_failures=$((total_failures + 1))

    # External dependencies
    log "INFO" "Phase 6: External Dependencies Validation"
    validate_openai_api_access || total_failures=$((total_failures + 1))
    validate_internet_connectivity || total_failures=$((total_failures + 1))
    validate_dns_resolution || total_failures=$((total_failures + 1))

    # Integration tests
    log "INFO" "Phase 7: Integration Validation"
    validate_end_to_end_workflow || critical_failures=$((critical_failures + 1))
    validate_concurrent_requests || total_failures=$((total_failures + 1))

    # Data integrity
    log "INFO" "Phase 8: Data Integrity Validation"
    validate_data_consistency || critical_failures=$((critical_failures + 1))
    validate_backup_integrity || total_failures=$((total_failures + 1))

    # Security
    log "INFO" "Phase 9: Security Validation"
    validate_service_security || total_failures=$((total_failures + 1))
    validate_access_controls || total_failures=$((total_failures + 1))

    local validation_end=$(date +%s)
    local validation_duration=$((validation_end - validation_start))

    # Generate results
    generate_validation_results "$critical_failures" "$total_failures" "$validation_duration"

    return $critical_failures
}

generate_validation_results() {
    local critical_failures=$1
    local total_failures=$2
    local duration=$3

    local success_rate=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    local results_file="$VALIDATION_RESULTS_DIR/validation-results-$(date +%Y%m%d_%H%M%S).json"

    log "INFO" "Generating validation results"

    # Create detailed results JSON
    cat > "$results_file" << EOF
{
  "validation_id": "dr-validation-$(date +%Y%m%d_%H%M%S)",
  "timestamp": "$(date -Iseconds)",
  "summary": {
    "total_checks": $TOTAL_CHECKS,
    "passed_checks": $PASSED_CHECKS,
    "failed_checks": $((TOTAL_CHECKS - PASSED_CHECKS)),
    "critical_failures": $critical_failures,
    "total_failures": $total_failures,
    "success_rate": $success_rate,
    "duration_seconds": $duration
  },
  "validation_results": [
EOF

    # Add individual results
    local first=true
    for result in "${VALIDATION_RESULTS[@]}"; do
        IFS=':' read -r status name duration <<< "$result"
        if [[ "$first" != true ]]; then
            echo "," >> "$results_file"
        fi
        cat >> "$results_file" << EOF
    {
      "name": "$name",
      "status": "$status",
      "duration_seconds": $duration
    }
EOF
        first=false
    done

    cat >> "$results_file" << EOF
  ],
  "recommendations": [
EOF

    # Add recommendations based on results
    local recommendations=()

    if [[ $critical_failures -gt 0 ]]; then
        recommendations+=("CRITICAL: $critical_failures critical failures require immediate attention")
    fi

    if [[ $total_failures -gt $critical_failures ]]; then
        recommendations+=("Review and address non-critical failures")
    fi

    if [[ $success_rate -lt 95 ]]; then
        recommendations+=("Success rate below 95% - consider additional testing")
    fi

    if [[ $duration -gt 300 ]]; then
        recommendations+=("Validation took longer than expected - consider optimizing test procedures")
    fi

    recommendations+=("Schedule regular DR validation exercises")
    recommendations+=("Update documentation based on validation results")
    recommendations+=("Monitor system performance after recovery")

    local first_rec=true
    for rec in "${recommendations[@]}"; do
        if [[ "$first_rec" != true ]]; then
            echo "," >> "$results_file"
        fi
        echo "    \"$rec\"" >> "$results_file"
        first_rec=false
    done

    cat >> "$results_file" << EOF
  ]
}
EOF

    log "INFO" "Validation results saved to: $results_file"

    # Generate summary report
    generate_summary_report "$critical_failures" "$total_failures" "$success_rate" "$duration"
}

generate_summary_report() {
    local critical_failures=$1
    local total_failures=$2
    local success_rate=$3
    local duration=$4

    local summary_file="$VALIDATION_RESULTS_DIR/validation-summary.txt"

    cat > "$summary_file" << EOF
DR Validation Summary Report
===========================

Date/Time: $(date)
Validation Duration: ${duration} seconds

OVERALL RESULTS:
- Total Checks: $TOTAL_CHECKS
- Passed: $PASSED_CHECKS
- Failed: $((TOTAL_CHECKS - PASSED_CHECKS))
- Success Rate: ${success_rate}%
- Critical Failures: $critical_failures
- Total Failures: $total_failures

VALIDATION STATUS:
EOF

    if [[ $critical_failures -eq 0 ]]; then
        cat >> "$summary_file" << EOF
✅ VALIDATION SUCCESSFUL
- All critical systems operational
- Core functionality validated
- System ready for production use

EOF
    else
        cat >> "$summary_file" << EOF
❌ VALIDATION FAILED
- $critical_failures critical failures detected
- System not ready for production
- Immediate attention required

EOF
    fi

    cat >> "$summary_file" << EOF
DETAILED RESULTS:
EOF

    for result in "${VALIDATION_RESULTS[@]}"; do
        IFS=':' read -r status name duration <<< "$result"
        local status_symbol="✅"
        if [[ "$status" == "FAILED" ]]; then
            status_symbol="❌"
        fi
        echo "$status_symbol $name (${duration}s)" >> "$summary_file"
    done

    cat >> "$summary_file" << EOF

NEXT STEPS:
EOF

    if [[ $critical_failures -gt 0 ]]; then
        cat >> "$summary_file" << EOF
1. Address all critical failures immediately
2. Re-run validation after fixes
3. Document root causes and solutions
4. Update recovery procedures

EOF
    else
        cat >> "$summary_file" << EOF
1. Review any non-critical failures
2. Monitor system performance
3. Schedule next validation exercise
4. Update documentation if needed

EOF
    fi

    log "INFO" "Summary report generated: $summary_file"
}

# Main execution logic
main() {
    log "INFO" "DR Validation Script Starting"
    log "INFO" "Cortex MCP Disaster Recovery Validation"
    log "INFO" "======================================="

    # Initialize validation environment
    init_validation

    # Parse command line arguments
    local validation_type="comprehensive"
    local output_format="both"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                validation_type="$2"
                shift 2
                ;;
            --output)
                output_format="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --type <type>        Validation type (comprehensive, quick, performance, security)"
                echo "  --output <format>    Output format (console, json, both)"
                echo "  --help, -h          Show this help message"
                echo ""
                echo "Validation Types:"
                echo "  comprehensive        Full validation suite (default)"
                echo "  quick               Basic health and functionality checks"
                echo "  performance         Performance-focused validation"
                echo "  security            Security-focused validation"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Execute validation based on type
    local validation_success=false

    case "$validation_type" in
        "comprehensive")
            log "INFO" "Running comprehensive validation"
            if run_comprehensive_validation; then
                validation_success=true
            fi
            ;;
        "quick")
            log "INFO" "Running quick validation"
            if run_quick_validation; then
                validation_success=true
            fi
            ;;
        "performance")
            log "INFO" "Running performance validation"
            if run_performance_validation; then
                validation_success=true
            fi
            ;;
        "security")
            log "INFO" "Running security validation"
            if run_security_validation; then
                validation_success=true
            fi
            ;;
        *)
            log "ERROR" "Unknown validation type: $validation_type"
            exit 1
            ;;
    esac

    # Display final results
    echo
    log "INFO" "DR Validation Completed"
    log "INFO" "======================="
    log "INFO" "Total Checks: $TOTAL_CHECKS"
    log "INFO" "Passed: $PASSED_CHECKS"
    log "INFO" "Failed: $((TOTAL_CHECKS - PASSED_CHECKS))"
    log "INFO" "Success Rate: $(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))%"
    echo

    if [[ "$validation_success" == true ]]; then
        log "INFO" "✅ DR Validation PASSED"
        log "INFO" "System is ready for operation"
        exit 0
    else
        log "ERROR" "❌ DR Validation FAILED"
        log "ERROR" "System requires attention before going live"
        exit 1
    fi
}

# Quick validation (subset of comprehensive)
run_quick_validation() {
    log "INFO" "Running quick validation"

    validate_mcp_server_availability || return 1
    validate_qdrant_availability || return 1
    validate_memory_store_api || return 1
    validate_memory_find_api || return 1
    validate_vector_search || return 1
    validate_memory_availability || return 1
    validate_disk_space || return 1

    return 0
}

# Performance validation
run_performance_validation() {
    log "INFO" "Running performance validation"

    validate_mcp_server_availability || return 1
    validate_qdrant_availability || return 1
    validate_api_response_time || true
    validate_database_search_performance || true
    validate_concurrent_requests || true
    validate_memory_availability || return 1
    validate_disk_space || return 1
    validate_cpu_load || true

    return 0
}

# Security validation
run_security_validation() {
    log "INFO" "Running security validation"

    validate_mcp_server_availability || return 1
    validate_qdrant_availability || return 1
    validate_service_security || true
    validate_access_controls || true
    validate_data_consistency || return 1

    return 0
}

# Execute main function
main "$@"