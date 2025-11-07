#!/bin/bash

# TypeScript Error Tracker - Daily Monitoring Script
# Tracks TypeScript errors and generates trend analysis

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/artifacts/typescript-tracking"
CONFIG_FILE="$PROJECT_ROOT/config/typescript-error-budget.json"
TREND_FILE="$LOG_DIR/trends.json"
DAILY_REPORT="$LOG_DIR/daily-$(date +%Y-%m-%d).json"
WEEKLY_REPORT="$LOG_DIR/weekly-$(date +%Y-%W).json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Create directories
ensure_directories() {
    log "Creating directories..."
    mkdir -p "$LOG_DIR"/{daily,weekly,monthly,reports}
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "Loading configuration from $CONFIG_FILE"
        # Source configuration (in real implementation, would parse JSON)
        ERROR_BUDGET_CRITICAL=${ERROR_BUDGET_CRITICAL:-0}
        ERROR_BUDGET_HIGH=${ERROR_BUDGET_HIGH:-5}
        ERROR_BUDGET_MEDIUM=${ERROR_BUDGET_MEDIUM:-20}
    else
        warn "Configuration file not found, using defaults"
        ERROR_BUDGET_CRITICAL=0
        ERROR_BUDGET_HIGH=5
        ERROR_BUDGET_MEDIUM=20
    fi
}

# Run TypeScript compiler and capture errors
analyze_typescript_errors() {
    log "Analyzing TypeScript errors..."

    cd "$PROJECT_ROOT"

    # Create temporary file for error output
    local temp_error_file=$(mktemp)

    # Run TypeScript compiler
    if npm run type-check 2>"$temp_error_file"; then
        local compilation_success=true
    else
        local compilation_success=false
    fi

    # Parse errors
    local error_count=0
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0

    declare -A error_codes
    declare -A error_files

    while IFS= read -r line; do
        # Parse TypeScript error format: file(line,column): error TS####: message
        if [[ $line =~ ^(.+)\(([0-9]+),([0-9]+)\):\ error\ TS([0-9]+):\ (.+)$ ]]; then
            local file="${BASH_REMATCH[1]}"
            local error_code="${BASH_REMATCH[4]}"
            local message="${BASH_REMATCH[5]}"

            # Get relative path
            local rel_file="${file#$PROJECT_ROOT/}"

            # Count errors by code
            error_codes["$error_code"]=$((${error_codes["$error_code"]:-0} + 1))

            # Count errors by file
            error_files["$rel_file"]=$((${error_files["$rel_file"]:-0} + 1))

            # Categorize errors
            case "$error_code" in
                2307|2322|2339|2345|2352|2362|2365)
                    ((critical_count++))
                    ;;
                18048|7005|7006|7016|7017|7023)
                    ((high_count++))
                    ;;
                2564|2391|2367|7031|7034)
                    ((medium_count++))
                    ;;
                *)
                    ((low_count++))
                    ;;
            esac

            ((error_count++))
        fi
    done < "$temp_error_file"

    # Clean up temporary file
    rm -f "$temp_error_file"

    # Build metrics object
    local metrics=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
    "date": "$(date +%Y-%m-%d)",
    "compilationSuccess": $compilation_success,
    "totalErrors": $error_count,
    "criticalErrors": $critical_count,
    "highErrors": $high_count,
    "mediumErrors": $medium_count,
    "lowErrors": $low_count,
    "errorsByCode": {
$(for code in "${!error_codes[@]}"; do
    echo "        \"$code\": ${error_codes[$code]},"
done | sed '$ s/,$//')
    },
    "errorsByFile": {
$(for file in "${!error_files[@]}"; do
    echo "        \"$file\": ${error_files[$file]},"
done | sed '$ s/,$//')
    },
    "errorBudgetStatus": {
        "critical": {
            "current": $critical_count,
            "budget": $ERROR_BUDGET_CRITICAL,
            "withinBudget": $([ $critical_count -le $ERROR_BUDGET_CRITICAL ] && echo true || echo false)
        },
        "high": {
            "current": $high_count,
            "budget": $ERROR_BUDGET_HIGH,
            "withinBudget": $([ $high_count -le $ERROR_BUDGET_HIGH ] && echo true || echo false)
        },
        "medium": {
            "current": $medium_count,
            "budget": $ERROR_BUDGET_MEDIUM,
            "withinBudget": $([ $medium_count -le $ERROR_BUDGET_MEDIUM ] && echo true || echo false)
        }
    }
}
EOF
)

    echo "$metrics"
}

# Load historical trends
load_trends() {
    if [[ -f "$TREND_FILE" ]]; then
        log "Loading historical trends from $TREND_FILE"
        cat "$TREND_FILE"
    else
        log "No trends file found, creating new"
        echo '{"daily": [], "weekly": [], "monthly": []}'
    fi
}

# Update trends with current data
update_trends() {
    local current_metrics="$1"
    local trends_data="$2"

    log "Updating trends..."

    # Create temporary file for updated trends
    local temp_trends=$(mktemp)

    # Use jq to merge current metrics into trends (or manually parse)
    # For now, we'll append to daily array
    local updated_trends=$(echo "$trends_data" | jq --argjson daily "$current_metrics" '.daily += [$daily]')

    # Keep only last 30 days of daily data
    updated_trends=$(echo "$updated_trends" | jq '.daily |= sort_by(.date) | .daily |= .[-30:]')

    # Generate weekly summary if it's Monday (day of week = 1)
    local day_of_week=$(date +%u)
    if [[ $day_of_week -eq 1 ]]; then
        log "Generating weekly summary..."
        local weekly_summary=$(echo "$updated_trends" | jq '
            .daily[-7:] |
            group_by(.date[0:7]) |
            map({
                week: .[0].date[0:7],
                totalErrors: add | .totalErrors,
                avgErrors: (. | length | if . > 0 then (.totalErrors / .) else 0 end),
                criticalErrors: map(.criticalErrors) | add,
                dataPoints: . | length
            })
        ')

        updated_trends=$(echo "$updated_trends" | jq --argjson weekly "$weekly_summary" '.weekly += $weekly | .weekly |= .[-12:]')
    fi

    # Save updated trends
    echo "$updated_trends" > "$temp_trends"
    mv "$temp_trends" "$TREND_FILE"

    echo "$updated_trends"
}

# Generate trend analysis
generate_trend_analysis() {
    local trends_data="$1"

    log "Generating trend analysis..."

    local analysis=$(echo "$trends_data" | jq '
    {
        period: "last 30 days",
        dailyDataPoints: (.daily | length),
        weeklyDataPoints: (.weekly | length),
        trends: {
            errorTrend: (
                if .daily | length >= 2 then
                    (.daily[-1].totalErrors - .daily[0].totalErrors)
                else
                    0
                end
            ),
            criticalErrorTrend: (
                if .daily | length >= 2 then
                    (.daily[-1].criticalErrors - .daily[0].criticalErrors)
                else
                    0
                end
            ),
            avgDailyErrors: (
                if .daily | length > 0 then
                    (.daily | map(.totalErrors) | add / length)
                else
                    0
                end
            )
        },
        patterns: {
            mostCommonError: (
                .daily |
                map(.errorsByCode | to_entries | sort_by(.value) | reverse | .[0]) |
                group_by(.key) |
                map({code: .[0].key, totalFreq: map(.value) | add}) |
                sort_by(.totalFreq) | reverse | .[0]
            ),
            mostProblematicFile: (
                .daily |
                map(.errorsByFile | to_entries | sort_by(.value) | reverse | .[0]) |
                group_by(.key) |
                map({file: .[0].key, totalErrors: map(.value) | add}) |
                sort_by(.totalErrors) | reverse | .[0]
            )
        }
    }
    ')

    echo "$analysis"
}

# Generate daily report
generate_daily_report() {
    local metrics="$1"
    local trends_data="$2"
    local analysis="$3"

    log "Generating daily report..."

    local report=$(cat <<EOF
{
    "reportType": "daily",
    "date": "$(date +%Y-%m-%d)",
    "generatedAt": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
    "metrics": $metrics,
    "trendAnalysis": $analysis,
    "status": {
        "overall": $(if echo "$metrics" | jq -r '.errorBudgetStatus.critical.withinBudget and .errorBudgetStatus.high.withinBudget' | grep -q true; then echo '"healthy"'; else echo '"warning"'; fi),
        "budgetStatus": {
            "critical": $(echo "$metrics" | jq '.errorBudgetStatus.critical'),
            "high": $(echo "$metrics" | jq '.errorBudgetStatus.high'),
            "medium": $(echo "$metrics" | jq '.errorBudgetStatus.medium')
        }
    },
    "recommendations": [
$(if echo "$metrics" | jq -r '.errorBudgetStatus.critical.withinBudget' | grep -q false; then
    echo '        "Address critical errors immediately - they may impact runtime behavior",'
fi
if echo "$metrics" | jq -r '.errorBudgetStatus.high.withinBudget' | grep -q false; then
    echo '        "Review and fix high severity type errors to prevent regressions",'
fi
if echo "$analysis" | jq -r '.trends.errorTrend' | grep -v '^0$'; then
    local trend=$(echo "$analysis" | jq -r '.trends.errorTrend')
    if [[ $trend -gt 0 ]]; then
        echo '        "Error count is trending upward - investigate recent changes",'
    else
        echo '        "Error count is improving - continue current approach",'
    fi
fi
echo '        "Run automated TypeScript fix scripts to reduce error count"'
sed '$ s/,$//')
    ],
    "nextActions": [
        "Review detailed error analysis in the full report",
        "Run appropriate ts-fix scripts based on error patterns",
        "Monitor trends over the next few days",
        "Update baseline if metrics are within acceptable range"
    ]
}
EOF
)

    echo "$report" > "$DAILY_REPORT"
    echo "$report"
}

# Generate HTML report for better visualization
generate_html_report() {
    local report_data="$1"

    log "Generating HTML report..."

    local html_report_path="$LOG_DIR/reports/daily-$(date +%Y-%m-%d).html"

    # Extract data from JSON report
    local date=$(echo "$report_data" | jq -r '.date')
    local total_errors=$(echo "$report_data" | jq -r '.metrics.totalErrors')
    local critical_errors=$(echo "$report_data" | jq -r '.metrics.criticalErrors')
    local high_errors=$(echo "$report_data" | jq -r '.metrics.highErrors')
    local status=$(echo "$report_data" | jq -r '.status.overall')

    # Generate HTML
    cat > "$html_report_path" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypeScript Daily Error Report - $date</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
        .status.healthy { background: #d4edda; color: #155724; }
        .status.warning { background: #fff3cd; color: #856404; }
        .status.critical { background: #f8d7da; color: #721c24; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { padding: 20px; border: 1px solid #dee2e6; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 10px; }
        .metric-label { color: #6c757d; }
        .section { margin: 30px 0; }
        .section h2 { color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
        .recommendations { list-style: none; padding: 0; }
        .recommendations li { padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; background: #f8f9fa; }
        .error-breakdown { margin: 20px 0; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .table th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 TypeScript Daily Error Report</h1>
            <p>Date: $date</p>
            <p>Generated: $(date)</p>
            <div class="status $status">
                $status - $total_errors total errors
            </div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">$total_errors</div>
                <div class="metric-label">Total Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: $([ "$critical_errors" -gt 0 ] && echo '#dc3545' || echo '#28a745')">$critical_errors</div>
                <div class="metric-label">Critical Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: $([ "$high_errors" -gt 5 ] && echo '#ffc107' || echo '#28a745')">$high_errors</div>
                <div class="metric-label">High Severity Errors</div>
            </div>
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            <ul class="recommendations">
$(echo "$report_data" | jq -r '.recommendations[] | "<li>\(.)</li>"')
            </ul>
        </div>

        <div class="section">
            <h2>📋 Next Actions</h2>
            <ul class="recommendations">
$(echo "$report_data" | jq -r '.nextActions[] | "<li>\(.)</li>"')
            </ul>
        </div>

        <div class="footer">
            <p><em>Report generated by TypeScript Error Tracker</em></p>
            <p><em>For detailed analysis, check the JSON report in artifacts/typescript-tracking/</em></p>
        </div>
    </div>
</body>
</html>
EOF

    log "HTML report saved to $html_report_path"
}

# Check if jq is available
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed. Please install jq to continue."
        exit 1
    fi

    if ! command -v npm &> /dev/null; then
        error "npm is required but not installed. Please install npm to continue."
        exit 1
    fi
}

# Main execution
main() {
    log "Starting TypeScript Error Tracker"

    # Check dependencies
    check_dependencies

    # Setup
    ensure_directories
    load_config

    # Analyze current state
    log "Analyzing TypeScript errors..."
    local current_metrics=$(analyze_typescript_errors)

    # Load historical data
    local trends_data=$(load_trends)

    # Update trends
    local updated_trends=$(update_trends "$current_metrics" "$trends_data")

    # Generate analysis
    local analysis=$(generate_trend_analysis "$updated_trends")

    # Generate reports
    log "Generating reports..."
    local daily_report=$(generate_daily_report "$current_metrics" "$updated_trends" "$analysis")

    # Generate HTML report
    generate_html_report "$daily_report"

    # Display summary
    local total_errors=$(echo "$current_metrics" | jq -r '.totalErrors')
    local critical_errors=$(echo "$current_metrics" | jq -r '.criticalErrors')
    local status=$(echo "$daily_report" | jq -r '.status.overall')

    echo ""
    log "Daily TypeScript Error Summary:"
    log "  Total Errors: $total_errors"
    log "  Critical Errors: $critical_errors"
    log "  Status: $status"
    log "  Report: $DAILY_REPORT"

    if [[ "$status" == "warning" ]]; then
        warn "TypeScript error budget exceeded - please review recommendations"
        exit 1
    else
        success "TypeScript error budget within acceptable limits"
        exit 0
    fi
}

# Execute main function
main "$@"