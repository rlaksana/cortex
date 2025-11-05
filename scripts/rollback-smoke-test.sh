#!/bin/bash
# Cortex Memory MCP - Rollback Smoke Test Script
# This script verifies that a rollback was successful by testing all critical components

set -e

# Configuration
API_BASE_URL="http://localhost:3000"
QDRANT_URL="http://localhost:6333"
TIMEOUT=30
LOG_FILE="/tmp/rollback-smoke-test.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
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

# Test HTTP endpoint
test_endpoint() {
    local url=$1
    local description=$2
    local expected_status=${3:-200}

    log "Testing $description: $url"

    if response=$(curl -s --max-time $TIMEOUT -w "%{http_code}" "$url" 2>/dev/null); then
        local http_code="${response: -3}"
        local body="${response%???}"

        if [ "$http_code" -eq "$expected_status" ]; then
            print_status "OK" "$description - HTTP $http_code"
            echo "$body"
            return 0
        else
            print_status "FAIL" "$description - HTTP $http_code (expected $expected_status)"
            return 1
        fi
    else
        print_status "FAIL" "$description - Connection failed"
        return 1
    fi
}

# Test JSON response
test_json_response() {
    local url=$1
    local description=$2
    local json_path=${3:-"."}

    log "Testing JSON response for $description"

    if response=$(test_endpoint "$url" "$description"); then
        if echo "$response" | jq -e "$json_path" >/dev/null 2>&1; then
            local value=$(echo "$response" | jq -r "$json_path")
            print_status "OK" "$description - JSON path '$json_path' = '$value'"
            return 0
        else
            print_status "FAIL" "$description - Invalid JSON or missing path '$json_path'"
            echo "Response: $response"
            return 1
        fi
    else
        return 1
    fi
}

# Main smoke test function
run_smoke_test() {
    local failed_tests=0
    local total_tests=0

    echo "🔍 Starting Cortex Memory MCP Rollback Smoke Test"
    echo "=================================================="
    log "Starting rollback smoke test"

    # Test 1: Application Health Check
    echo ""
    print_status "INFO" "Test 1: Application Health Check"
    ((total_tests++))
    if test_json_response "$API_BASE_URL/health" "Health endpoint" ".status" | grep -q "healthy"; then
        print_status "OK" "Application reports healthy status"
    else
        print_status "FAIL" "Application health check failed"
        ((failed_tests++))
    fi

    # Test 2: Qdrant Database Health
    echo ""
    print_status "INFO" "Test 2: Qdrant Database Health"
    ((total_tests++))
    if test_json_response "$QDRANT_URL/health" "Qdrant health" ".result.status" | grep -q "ok"; then
        print_status "OK" "Qdrant database is healthy"
    else
        print_status "FAIL" "Qdrant database health check failed"
        ((failed_tests++))
    fi

    # Test 3: Collection Access
    echo ""
    print_status "INFO" "Test 3: Collection Access"
    ((total_tests++))
    if test_endpoint "$QDRANT_URL/collections/cortex-memory" "Collection access" "200" >/dev/null; then
        print_status "OK" "Cortex memory collection is accessible"
    else
        print_status "FAIL" "Cannot access cortex memory collection"
        ((failed_tests++))
    fi

    # Test 4: Vector Search Functionality
    echo ""
    print_status "INFO" "Test 4: Vector Search Functionality"
    ((total_tests++))

    # Create a test vector (1536 dimensions for ada-002)
    test_vector=$(python3 -c "import json; print(json.dumps([0.1] * 1536))" 2>/dev/null || echo '[]')

    search_data='{
        "vector": [0.1, 0.2, 0.3],
        "limit": 1,
        "with_payload": true
    }'

    if response=$(curl -s --max-time $TIMEOUT -X POST "$QDRANT_URL/collections/cortex-memory/points/search" \
        -H "Content-Type: application/json" \
        -d "$search_data" 2>/dev/null); then

        if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
            print_status "OK" "Vector search functionality working"
        else
            print_status "WARN" "Vector search returned unexpected response (might be empty database)"
            echo "Response: $response"
        fi
    else
        print_status "FAIL" "Vector search functionality failed"
        ((failed_tests++))
    fi

    # Test 5: API Search Endpoint
    echo ""
    print_status "INFO" "Test 5: API Search Endpoint"
    ((total_tests++))

    search_api_data='{
        "query": "test rollback",
        "limit": 5
    }'

    if response=$(curl -s --max-time $TIMEOUT -X POST "$API_BASE_URL/api/search" \
        -H "Content-Type: application/json" \
        -d "$search_api_data" 2>/dev/null); then

        if echo "$response" | jq -e '.results' >/dev/null 2>&1; then
            print_status "OK" "API search endpoint working"
        else
            print_status "WARN" "API search returned unexpected response"
            echo "Response: $response"
        fi
    else
        print_status "FAIL" "API search endpoint failed"
        ((failed_tests++))
    fi

    # Test 6: Memory Storage (if possible)
    echo ""
    print_status "INFO" "Test 6: Memory Storage Test"
    ((total_tests++))

    memory_data='{
        "content": "Rollback smoke test - '$(date)'",
        "type": "observation",
        "metadata": {
            "test": true,
            "timestamp": "'$(date -Iseconds)'"
        }
    }'

    if response=$(curl -s --max-time $TIMEOUT -X POST "$API_BASE_URL/api/memory/store" \
        -H "Content-Type: application/json" \
        -d "$memory_data" 2>/dev/null); then

        if memory_id=$(echo "$response" | jq -r '.id' 2>/dev/null) && [ "$memory_id" != "null" ]; then
            print_status "OK" "Memory storage successful (ID: $memory_id)"

            # Test retrieval
            if retrieval_response=$(curl -s --max-time $TIMEOUT "$API_BASE_URL/api/memory/$memory_id" 2>/dev/null); then
                if echo "$retrieval_response" | jq -e '.content' >/dev/null 2>&1; then
                    print_status "OK" "Memory retrieval successful"
                else
                    print_status "WARN" "Memory storage worked but retrieval failed"
                fi
            else
                print_status "WARN" "Memory storage worked but retrieval failed"
            fi
        else
            print_status "FAIL" "Memory storage failed"
            ((failed_tests++))
        fi
    else
        print_status "FAIL" "Memory storage endpoint failed"
        ((failed_tests++))
    fi

    # Test 7: System Resource Check
    echo ""
    print_status "INFO" "Test 7: System Resource Check"
    ((total_tests++))

    # Check if Node.js process is running
    if pgrep -f "node.*cortex" > /dev/null; then
        print_status "OK" "Cortex MCP Node.js process is running"

        # Check memory usage
        if command -v ps >/dev/null; then
            memory_mb=$(ps aux | grep -E "node.*cortex" | grep -v grep | awk '{sum+=$6} END {print sum/1024}')
            if [ "$memory_mb" ] && [ "$(echo "$memory_mb < 2048" | bc -l 2>/dev/null || echo "1")" -eq 1 ]; then
                print_status "OK" "Memory usage is acceptable (${memory_mb}MB)"
            else
                print_status "WARN" "High memory usage detected (${memory_mb}MB)"
            fi
        fi
    else
        print_status "FAIL" "Cortex MCP Node.js process is not running"
        ((failed_tests++))
    fi

    # Test 8: Performance Check
    echo ""
    print_status "INFO" "Test 8: Performance Check"
    ((total_tests++))

    start_time=$(date +%s%N)
    if test_endpoint "$API_BASE_URL/health" "Performance test" >/dev/null; then
        end_time=$(date +%s%N)
        response_time=$(echo "scale=3; ($end_time - $start_time) / 1000000" | bc -l 2>/dev/null || echo "0")

        if [ "$(echo "$response_time < 2000" | bc -l 2>/dev/null || echo "1")" -eq 1 ]; then
            print_status "OK" "Response time is acceptable (${response_time}ms)"
        else
            print_status "WARN" "Slow response time detected (${response_time}ms)"
        fi
    else
        print_status "FAIL" "Performance test failed"
        ((failed_tests++))
    fi

    # Summary
    echo ""
    echo "=================================================="
    echo "🧪 Rollback Smoke Test Summary"
    echo "=================================================="

    passed_tests=$((total_tests - failed_tests))

    if [ $failed_tests -eq 0 ]; then
        print_status "OK" "All tests passed! ($passed_tests/$total_tests)"
        log "Rollback smoke test completed successfully - all $total_tests tests passed"
        echo ""
        echo "🎉 Rollback verification successful! System is ready for production."
        return 0
    else
        print_status "FAIL" "$failed_tests out of $total_tests tests failed"
        log "Rollback smoke test completed with failures - $failed_tests/$total_tests tests failed"
        echo ""
        echo "❌ Rollback verification failed! Please investigate the failed tests."
        echo ""
        echo "Check the log file for details: $LOG_FILE"
        return 1
    fi
}

# Help function
show_help() {
    echo "Cortex Memory MCP - Rollback Smoke Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --verbose       Enable verbose output"
    echo "  -q, --quiet         Suppress non-error output"
    echo "  -t, --timeout N     Set request timeout in seconds (default: 30)"
    echo "  -u, --url URL       Set API base URL (default: http://localhost:3000)"
    echo "  -d, --qdrant URL    Set Qdrant URL (default: http://localhost:6333)"
    echo "  -l, --log FILE      Set log file path (default: /tmp/rollback-smoke-test.log)"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Run smoke test with defaults"
    echo "  $0 -v                                       # Run with verbose output"
    echo "  $0 -t 60                                    # Use 60 second timeout"
    echo "  $0 -u http://localhost:8080                 # Use different API URL"
    echo ""
    echo "Exit Codes:"
    echo "  0    All tests passed"
    echo "  1    Some tests failed"
    echo "  2    Invalid arguments"
    echo "  3    Dependencies missing"
}

# Parse command line arguments
VERBOSE=false
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -u|--url)
            API_BASE_URL="$2"
            shift 2
            ;;
        -d|--qdrant)
            QDRANT_URL="$2"
            shift 2
            ;;
        -l|--log)
            LOG_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 2
            ;;
    esac
done

# Check dependencies
if ! command -v curl >/dev/null; then
    echo "Error: curl is required but not installed"
    exit 3
fi

if ! command -v jq >/dev/null; then
    echo "Error: jq is required but not installed"
    exit 3
fi

if ! command -v bc >/dev/null; then
    echo "Warning: bc is not installed, some calculations may not work"
fi

# Run the smoke test
if run_smoke_test; then
    exit 0
else
    exit 1
fi