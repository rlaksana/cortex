#!/bin/bash
# Cortex Memory MCP - Rollback Test Runner
# This script tests rollback procedures in a safe environment

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_RESULTS_DIR="$PROJECT_ROOT/test-results/rollback"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TEST_DIR="$TEST_RESULTS_DIR/rollback-test-$TIMESTAMP"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$TEST_DIR/test.log"
}

# Print colored output
print_status() {
    local status=$1
    local message=$2

    case $status in
        "OK")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "FAIL")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
    esac
}

# Initialize test environment
init_test_env() {
    print_status "INFO" "Initializing rollback test environment..."

    # Create test directory
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"

    # Clone a copy of the project for testing
    if [ ! -d "test-project" ]; then
        cp -r "$PROJECT_ROOT" test-project
        print_status "OK" "Created test project copy"
    fi

    cd test-project

    # Create test backup directory
    mkdir -p test-backups/{config,qdrant}

    log "Test environment initialized"
}

# Record test result
record_test() {
    local test_name=$1
    local result=$2
    local details=${3:-""}

    ((TESTS_TOTAL++))

    if [ "$result" = "PASS" ]; then
        ((TESTS_PASSED++))
        print_status "OK" "$test_name"
    else
        ((TESTS_FAILED++))
        print_status "FAIL" "$test_name - $details"
    fi

    echo "$test_name|$result|$details" >> test-results.csv
}

# Test configuration backup and restore
test_config_rollback() {
    print_status "INFO" "Testing configuration rollback..."

    # Create test configuration
    echo "TEST_VAR=test_value_$TIMESTAMP" >> .env
    echo '{"test": {"rollback": true, "timestamp": "'$TIMESTAMP'"}}' > src/config/test-config.json

    # Create backup
    if [ -f "scripts/backup-qdrant.sh" ]; then
        mkdir -p test-backups/config
        cp .env test-backups/config/.env.test
        cp src/config/production-config.json test-backups/config/production-config.json.test 2>/dev/null || true
        print_status "OK" "Configuration backup created"
        record_test "Configuration Backup" "PASS"
    else
        record_test "Configuration Backup" "FAIL" "Backup script not found"
        return 1
    fi

    # Modify configuration (simulate error)
    echo "BROKEN_CONFIG=true" >> .env
    echo '{"broken": true}' > src/config/production-config.json

    # Test configuration validation (should fail)
    if npm run prod:validate >/dev/null 2>&1; then
        record_test "Configuration Validation (Expected Failure)" "FAIL" "Should have failed with broken config"
    else
        record_test "Configuration Validation (Expected Failure)" "PASS"
    fi

    # Restore configuration
    cp test-backups/config/.env.test .env
    cp test-backups/config/production-config.json.test src/config/production-config.json 2>/dev/null || true

    # Test configuration validation (should pass)
    if npm run prod:validate >/dev/null 2>&1; then
        record_test "Configuration Restore" "PASS"
    else
        record_test "Configuration Restore" "FAIL" "Validation failed after restore"
    fi

    # Cleanup
    git checkout .env src/config/production-config.json 2>/dev/null || true
}

# Test application version rollback
test_app_rollback() {
    print_status "INFO" "Testing application version rollback..."

    # Get current version
    local current_commit
    current_commit=$(git rev-parse HEAD)

    # Create a test branch with changes
    git checkout -b test-rollback-branch-$TIMESTAMP 2>/dev/null || git checkout test-rollback-branch-$TIMESTAMP

    # Add test changes
    echo "// Test rollback changes - $TIMESTAMP" >> src/index.ts

    # Test build (should work)
    if npm run build >/dev/null 2>&1; then
        record_test "Application Build (Test Version)" "PASS"
    else
        record_test "Application Build (Test Version)" "FAIL" "Build failed with test changes"
        git checkout "$current_commit"
        return 1
    fi

    # Rollback to original version
    git checkout "$current_commit" --force

    # Clean build
    npm run clean:build >/dev/null 2>&1 || true

    # Test build (should still work)
    if npm run build >/dev/null 2>&1; then
        record_test "Application Rollback" "PASS"
    else
        record_test "Application Rollback" "FAIL" "Build failed after rollback"
    fi

    # Cleanup
    git branch -D test-rollback-branch-$TIMESTAMP 2>/dev/null || true
}

# Test database backup procedures
test_database_backup() {
    print_status "INFO" "Testing database backup procedures..."

    # Start Qdrant for testing
    cd docker
    if ! docker-compose ps | grep -q qdrant; then
        docker-compose up -d qdrant
        print_status "INFO" "Started Qdrant for testing"

        # Wait for Qdrant to be ready
        local max_wait=30
        local wait_time=0
        while [ $wait_time -lt $max_wait ]; do
            if curl -s http://localhost:6333/health >/dev/null 2>&1; then
                break
            fi
            sleep 1
            wait_time=$((wait_time + 1))
        done
    fi

    # Test collection creation
    if curl -s -X PUT "http://localhost:6333/collections/test-rollback" \
         -H "Content-Type: application/json" \
         -d '{"vectors": {"size": 1536, "distance": "Cosine"}}' >/dev/null 2>&1; then
        record_test "Qdrant Collection Creation" "PASS"
    else
        record_test "Qdrant Collection Creation" "FAIL" "Could not create test collection"
        return 1
    fi

    # Add test data
    local test_vector='[0.1] * 1536'
    if python3 -c "
import json
import requests
vector = [0.1] * 1536
data = {
    'points': [
        {
            'id': 1,
            'vector': vector,
            'payload': {'test': 'rollback_data_$TIMESTAMP'}
        }
    ]
}
response = requests.put('http://localhost:6333/collections/test-rollback/points', json=data)
print(response.status_code)
" | grep -q "200"; then
        record_test "Qdrant Data Insertion" "PASS"
    else
        record_test "Qdrant Data Insertion" "FAIL" "Could not insert test data"
    fi

    # Test snapshot creation
    if curl -s -X POST "http://localhost:6333/collections/test-rollback/snapshots" >/dev/null 2>&1; then
        record_test "Qdrant Snapshot Creation" "PASS"
    else
        record_test "Qdrant Snapshot Creation" "FAIL" "Could not create snapshot"
    fi

    # Test backup script if available
    if [ -f "$SCRIPT_DIR/backup-qdrant.sh" ]; then
        if "$SCRIPT_DIR/backup-qdrant.sh" >/dev/null 2>&1; then
            record_test "Qdrant Backup Script" "PASS"
        else
            record_test "Qdrant Backup Script" "FAIL" "Backup script execution failed"
        fi
    else
        record_test "Qdrant Backup Script" "FAIL" "Backup script not found"
    fi

    # Cleanup test collection
    curl -s -X DELETE "http://localhost:6333/collections/test-rollback" >/dev/null 2>&1 || true

    cd ..
}

# Test service restart procedures
test_service_restart() {
    print_status "INFO" "Testing service restart procedures..."

    # Test configuration validation
    if npm run prod:validate >/dev/null 2>&1; then
        record_test "Pre-Restart Configuration Check" "PASS"
    else
        record_test "Pre-Restart Configuration Check" "FAIL" "Configuration validation failed"
    fi

    # Test build process
    if npm run build >/dev/null 2>&1; then
        record_test "Build Process" "PASS"
    else
        record_test "Build Process" "FAIL" "Build failed"
    fi

    # Test health check endpoint (if service is running)
    if curl -s http://localhost:3000/health >/dev/null 2>&1; then
        record_test "Health Check Endpoint" "PASS"
    else
        record_test "Health Check Endpoint" "WARN" "Service not running (expected in test environment)"
    fi

    # Test smoke test script
    if [ -f "$SCRIPT_DIR/rollback-smoke-test.sh" ]; then
        if "$SCRIPT_DIR/rollback-smoke-test.sh" >/dev/null 2>&1; then
            record_test "Smoke Test Script" "PASS"
        else
            record_test "Smoke Test Script" "WARN" "Smoke test failed (service may not be running)"
        fi
    else
        record_test "Smoke Test Script" "FAIL" "Smoke test script not found"
    fi
}

# Test rollback script functionality
test_rollback_scripts() {
    print_status "INFO" "Testing rollback script functionality..."

    # Test emergency rollback script
    if [ -f "$SCRIPT_DIR/rollback-emergency.sh" ]; then
        if "$SCRIPT_DIR/rollback-emergency.sh" --help >/dev/null 2>&1; then
            record_test "Emergency Rollback Script" "PASS"
        else
            record_test "Emergency Rollback Script" "FAIL" "Script execution failed"
        fi
    else
        record_test "Emergency Rollback Script" "FAIL" "Emergency rollback script not found"
    fi

    # Test smoke test script
    if [ -f "$SCRIPT_DIR/rollback-smoke-test.sh" ]; then
        if "$SCRIPT_DIR/rollback-smoke-test.sh" --help >/dev/null 2>&1; then
            record_test "Smoke Test Script" "PASS"
        else
            record_test "Smoke Test Script" "FAIL" "Script execution failed"
        fi
    else
        record_test "Smoke Test Script" "FAIL" "Smoke test script not found"
    fi

    # Test script permissions
    if [ -x "$SCRIPT_DIR/rollback-emergency.sh" ]; then
        record_test "Script Permissions" "PASS"
    else
        record_test "Script Permissions" "FAIL" "Scripts are not executable"
    fi
}

# Test backup directory structure
test_backup_structure() {
    print_status "INFO" "Testing backup directory structure..."

    # Test main backup directory
    if [ -d "/backups" ]; then
        record_test "Main Backup Directory" "PASS"
    else
        record_test "Main Backup Directory" "WARN" "Main backup directory does not exist"
    fi

    # Test config backup directory
    if [ -d "/backups/config" ]; then
        record_test "Config Backup Directory" "PASS"
    else
        record_test "Config Backup Directory" "WARN" "Config backup directory does not exist"
    fi

    # Test qdrant backup directory
    if [ -d "/backups/qdrant" ]; then
        record_test "Qdrant Backup Directory" "PASS"
    else
        record_test "Qdrant Backup Directory" "WARN" "Qdrant backup directory does not exist"
    fi

    # Test test backup directory
    if [ -d "test-backups" ]; then
        record_test "Test Backup Directory" "PASS"
    else
        record_test "Test Backup Directory" "FAIL" "Test backup directory creation failed"
    fi
}

# Generate test report
generate_report() {
    print_status "INFO" "Generating test report..."

    local report_file="$TEST_DIR/rollback-test-report-$TIMESTAMP.md"

    cat > "$report_file" << EOF
# Rollback Test Report

**Test Date:** $(date)
**Test Directory:** $TEST_DIR
**Total Tests:** $TESTS_TOTAL
**Passed:** $TESTS_PASSED
**Failed:** $TESTS_FAILED
**Success Rate:** $(echo "scale=2; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc -l)%

## Test Results

EOF

    # Add detailed results
    while IFS='|' read -r test_name result details; do
        local status_icon="✅"
        if [ "$result" = "FAIL" ]; then
            status_icon="❌"
        elif [ "$result" = "WARN" ]; then
            status_icon="⚠️"
        fi

        echo "- $status_icon **$test_name**" >> "$report_file"
        if [ -n "$details" ]; then
            echo "  - Details: $details" >> "$report_file"
        fi
        echo "" >> "$report_file"
    done < test-results.csv

    # Add recommendations
    cat >> "$report_file" << EOF

## Recommendations

EOF

    if [ $TESTS_FAILED -eq 0 ]; then
        echo "✅ All rollback procedures are working correctly. System is ready for production." >> "$report_file"
    else
        echo "❌ Some rollback procedures failed. Please address the following issues:" >> "$report_file"
        echo "" >> "$report_file"

        while IFS='|' read -r test_name result details; do
            if [ "$result" = "FAIL" ]; then
                echo "- Fix **$test_name**: $details" >> "$report_file"
            fi
        done < test-results.csv
    fi

    # Add next steps
    cat >> "$report_file" << EOF

## Next Steps

1. Review failed tests and fix underlying issues
2. Re-run rollback tests after fixes
3. Schedule regular rollback test sessions
4. Update runbook based on test results
5. Train team on rollback procedures

## Test Environment

- **Node.js Version:** $(node --version)
- **Docker Version:** $(docker --version 2>/dev/null || echo "Not available")
- **Git Version:** $(git --version)
- **OS:** $(uname -a)

## Test Files

- **Test Log:** $TEST_DIR/test.log
- **Test Results:** $TEST_DIR/test-results.csv
- **Test Directory:** $TEST_DIR

EOF

    print_status "OK" "Test report generated: $report_file"
    echo ""
    echo "📊 Rollback Test Summary:"
    echo "   Total Tests: $TESTS_TOTAL"
    echo "   Passed: $TESTS_PASSED"
    echo "   Failed: $TESTS_FAILED"
    echo "   Success Rate: $(echo "scale=2; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc -l)%"
    echo ""
    echo "📄 Full report: $report_file"
}

# Cleanup test environment
cleanup_test_env() {
    print_status "INFO" "Cleaning up test environment..."

    # Stop test containers
    cd docker
    docker-compose down qdrant 2>/dev/null || true
    cd ..

    # Remove test project
    if [ "$1" = "--keep-test-project" ]; then
        print_status "INFO" "Keeping test project for manual inspection"
    else
        rm -rf test-project 2>/dev/null || true
    fi
}

# Show help
show_help() {
    echo "Cortex Memory MCP - Rollback Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -k, --keep-test-project Keep test project after tests"
    echo "  -o, --output DIR        Set output directory for test results"
    echo "  --test-config          Test configuration rollback only"
    echo "  --test-app             Test application rollback only"
    echo "  --test-database        Test database rollback only"
    echo "  --test-scripts         Test rollback scripts only"
    echo "  --test-structure       Test backup structure only"
    echo ""
    echo "Examples:"
    echo "  $0                      # Run all rollback tests"
    echo "  $0 --test-config        # Test configuration rollback only"
    echo "  $0 -k                   # Run tests and keep test project"
    echo "  $0 -o /tmp/rollback-tests  # Use custom output directory"
    echo ""
    echo "Exit Codes:"
    echo "  0    All tests passed"
    echo "  1    Some tests failed"
    echo "  2    Invalid arguments"
    echo "  3    Test setup failed"
}

# Main function
main() {
    local keep_test_project=false
    local test_config=true
    local test_app=true
    local test_database=true
    local test_scripts=true
    local test_structure=true

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -k|--keep-test-project)
                keep_test_project=true
                shift
                ;;
            -o|--output)
                TEST_RESULTS_DIR="$2"
                shift 2
                ;;
            --test-config)
                test_config=true
                test_app=false
                test_database=false
                test_scripts=false
                test_structure=false
                shift
                ;;
            --test-app)
                test_config=false
                test_app=true
                test_database=false
                test_scripts=false
                test_structure=false
                shift
                ;;
            --test-database)
                test_config=false
                test_app=false
                test_database=true
                test_scripts=false
                test_structure=false
                shift
                ;;
            --test-scripts)
                test_config=false
                test_app=false
                test_database=false
                test_scripts=true
                test_structure=false
                shift
                ;;
            --test-structure)
                test_config=false
                test_app=false
                test_database=false
                test_scripts=false
                test_structure=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 2
                ;;
        esac
    done

    # Update test directory with custom path if specified
    if [ "$TEST_RESULTS_DIR" != "$PROJECT_ROOT/test-results/rollback" ]; then
        TEST_DIR="$TEST_RESULTS_DIR/rollback-test-$TIMESTAMP"
    fi

    echo "🧪 Starting Cortex Memory MCP Rollback Test Suite"
    echo "=================================================="
    echo "Test Directory: $TEST_DIR"
    echo "Timestamp: $TIMESTAMP"
    echo ""

    # Initialize test environment
    init_test_env

    # Create test results file
    echo "Test Name,Result,Details" > test-results.csv

    # Run tests
    if [ "$test_structure" = true ]; then
        test_backup_structure
    fi

    if [ "$test_config" = true ]; then
        test_config_rollback
    fi

    if [ "$test_app" = true ]; then
        test_app_rollback
    fi

    if [ "$test_database" = true ]; then
        test_database_backup
    fi

    if [ "$test_scripts" = true ]; then
        test_rollback_scripts
    fi

    if [ "$test_config" = true ] || [ "$test_app" = true ]; then
        test_service_restart
    fi

    # Generate report
    generate_report

    # Cleanup
    if [ "$keep_test_project" = true ]; then
        cleanup_test_env --keep-test-project
    else
        cleanup_test_env
    fi

    # Return appropriate exit code
    if [ $TESTS_FAILED -eq 0 ]; then
        echo ""
        print_status "OK" "All rollback tests passed! System is ready for production."
        exit 0
    else
        echo ""
        print_status "FAIL" "$TESTS_FAILED out of $TESTS_TOTAL tests failed. Please review the report."
        exit 1
    fi
}

# Run main function
main "$@"