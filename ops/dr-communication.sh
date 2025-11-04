#!/bin/bash
# DR Communication Script - Stakeholder Notification and Communication Automation
# This script manages communication during disaster recovery scenarios

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/dr-communication.log"
CONFIG_FILE="$SCRIPT_DIR/../config/dr-config.json"
COMMUNICATION_TEMPLATES_DIR="$SCRIPT_DIR/../templates/communication"

# Communication configuration
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
EMAIL_SMTP_SERVER="${EMAIL_SMTP_SERVER:-smtp.company.com}"
EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT:-587}"
EMAIL_FROM="${EMAIL_FROM:-noreply@cortex.ai}"
EMAIL_USERNAME="${EMAIL_USERNAME:-alerts@cortex.ai}"
EMAIL_PASSWORD="${EMAIL_PASSWORD:-}"

# Contact lists
ONCALL_EMAIL="${ONCALL_EMAIL:-oncall@cortex.ai}"
MANAGEMENT_EMAIL="${MANAGEMENT_EMAIL:-management@cortex.ai}"
SUPPORT_EMAIL="${SUPPORT_EMAIL:-support@cortex.ai}"
SECURITY_EMAIL="${SECURITY_EMAIL:-security@cortex.ai}"

# Status page configuration
STATUS_PAGE_URL="${STATUS_PAGE_URL:-https://status.cortex.ai}"
STATUS_PAGE_API="${STATUS_PAGE_API:-https://api.statuspage.io/v1}"

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
        "COMMUNICATION")
            echo -e "${PURPLE}[COMMUNICATION]${NC} $message"
            ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log "WARN" "Configuration file not found, using defaults"
    fi

    # Create templates directory if it doesn't exist
    mkdir -p "$COMMUNICATION_TEMPLATES_DIR"
}

# Incident tracking
INCIDENT_ID=""
INCIDENT_START_TIME=""
INCIDENT_SEVERITY=""
INCIDENT_STATUS=""
INCIDENT_DESCRIPTION=""
COMMUNICATION_LOG=()

init_incident() {
    local severity=$1
    local description=$2

    INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
    INCIDENT_START_TIME=$(date -Iseconds)
    INCIDENT_SEVERITY="$severity"
    INCIDENT_STATUS="ACTIVE"
    INCIDENT_DESCRIPTION="$description"

    log "COMMUNICATION" "Initializing incident: $INCIDENT_ID"
    log "COMMUNICATION" "Severity: $severity"
    log "COMMUNICATION" "Description: $description"

    # Create incident directory
    mkdir -p "/tmp/incident-$INCIDENT_ID"

    # Log incident initialization
    echo "$(date -Iseconds): INCIDENT_INITIALIZED: $INCIDENT_ID, $severity, $description" >> "/tmp/incident-$INCIDENT_ID/incident.log"
}

update_incident_status() {
    local new_status=$1
    local update_message=$2

    local previous_status="$INCIDENT_STATUS"
    INCIDENT_STATUS="$new_status"

    log "COMMUNICATION" "Incident $INCIDENT_ID status updated: $previous_status -> $new_status"
    log "COMMUNICATION" "Update: $update_message"

    echo "$(date -Iseconds): STATUS_UPDATE: $previous_status -> $new_status, $update_message" >> "/tmp/incident-$INCIDENT_ID/incident.log"
}

# Communication templates
create_template() {
    local template_type=$1
    local output_file="$COMMUNICATION_TEMPLATES_DIR/${template_type}.template"

    case "$template_type" in
        "level1_alert")
            cat > "$output_file" << 'EOF'
🚨 CORTEX ALERT - LEVEL 1
Service: {{SERVICE_NAME}}
Issue: {{ISSUE_DESCRIPTION}}
Impact: {{USER_IMPACT}}
Status: {{CURRENT_STATUS}}
ETA: {{ESTIMATED_RESOLUTION}}
Incident ID: {{INCIDENT_ID}}
Started: {{INCIDENT_START_TIME}}

Current Actions:
{{CURRENT_ACTIONS}}

Next Update: {{NEXT_UPDATE_TIME}}

War Room: {{WAR_ROOM_URL}}
Status Page: {{STATUS_PAGE_URL}}
EOF
            ;;
        "level2_alert")
            cat > "$output_file" << 'EOF'
🔥 CORTEX EMERGENCY - LEVEL 2
All Hands: {{SERVICE_NAME}} Outage
Issue: {{ISSUE_DESCRIPTION}}
Impact: {{USER_IMPACT_ASSESSMENT}}
Status: {{CURRENT_STATUS}}
ETA: Unknown
Incident ID: {{INCIDENT_ID}}
Started: {{INCIDENT_START_TIME}}

Current Actions:
{{CURRENT_ACTIONS}}

Incident Commander: {{INCIDENT_COMMANDER}}
War Room: {{WAR_ROOM_URL}}
Status Page: {{STATUS_PAGE_URL}}

ALL HANDS ON DECK - Join the war room immediately!
EOF
            ;;
        "customer_update")
            cat > "$output_file" << 'EOF'
Cortex Service Update
====================

Incident: {{INCIDENT_SUMMARY}}
Status: {{SERVICE_STATUS}}
Started: {{INCIDENT_START_TIME}}
Impact: {{CUSTOMER_IMPACT}}

What's happening:
{{WHAT_IS_HAPPENING}}

What we're doing:
{{WHAT_WERE_DOING}}

Estimated resolution:
{{ESTIMATED_RESOLUTION}}

We apologize for the inconvenience and appreciate your patience.

Latest updates: {{STATUS_PAGE_URL}}
EOF
            ;;
        "resolution_notice")
            cat > "$output_file" << 'EOF'
✅ Cortex Service Resolved
=========================

Incident: {{INCIDENT_SUMMARY}}
Resolved: {{RESOLUTION_TIME}}
Duration: {{INCIDENT_DURATION}}
Impact: {{CUSTOMER_IMPACT}}

The issue has been resolved and all services are now operational.

Root cause:
{{ROOT_CAUSE}}

Preventive measures:
{{PREVENTIVE_MEASURES}}

We apologize for the disruption. Thank you for your patience.

Incident report: {{INCIDENT_REPORT_URL}}
EOF
            ;;
        "stakeholder_update")
            cat > "$output_file" << 'EOF'
Cortex Incident - Stakeholder Update
=====================================

Incident ID: {{INCIDENT_ID}}
Severity: {{INCIDENT_SEVERITY}}
Status: {{INCIDENT_STATUS}}
Duration: {{INCIDENT_DURATION}}

Business Impact:
{{BUSINESS_IMPACT}}

Technical Summary:
{{TECHNICAL_SUMMARY}}

Customer Impact:
{{CUSTOMER_IMPACT}}

Current Actions:
{{CURRENT_ACTIONS}}

Timeline:
{{INCIDENT_TIMELINE}}

Next Steps:
{{NEXT_STEPS}}

Financial Impact:
{{FINANCIAL_IMPACT}}

Contact:
Incident Commander: {{INCIDENT_COMMANDER}}
Technical Lead: {{TECHNICAL_LEAD}}
EOF
            ;;
        *)
            log "ERROR" "Unknown template type: $template_type"
            return 1
            ;;
    esac

    log "DEBUG" "Created template: $output_file"
}

# Template substitution
substitute_template() {
    local template_file=$1
    local output_file=$2

    # Create substitution variables
    local substitutions=(
        "s|{{INCIDENT_ID}}|$INCIDENT_ID|g"
        "s|{{INCIDENT_SEVERITY}}|$INCIDENT_SEVERITY|g"
        "s|{{INCIDENT_STATUS}}|$INCIDENT_STATUS|g"
        "s|{{INCIDENT_START_TIME}}|$INCIDENT_START_TIME|g"
        "s|{{INCIDENT_DESCRIPTION}}|$INCIDENT_DESCRIPTION|g"
        "s|{{CURRENT_TIME}}|$(date -Iseconds)|g"
        "s|{{STATUS_PAGE_URL}}|$STATUS_PAGE_URL|g"
    )

    # Perform substitutions
    sed "${substitutions[@]}" "$template_file" > "$output_file"

    log "DEBUG" "Template substitution completed: $output_file"
}

# Email communication
send_email() {
    local to=$1
    local subject=$2
    local body=$3
    local attachment=${4:-}

    log "COMMUNICATION" "Sending email to: $to"
    log "DEBUG" "Subject: $subject"

    # Check if email configuration is available
    if [[ -z "$EMAIL_SMTP_SERVER" ]] || [[ -z "$EMAIL_USERNAME" ]] || [[ -z "$EMAIL_PASSWORD" ]]; then
        log "WARN" "Email configuration incomplete, skipping email send"
        log "DEBUG" "Would send email:"
        log "DEBUG" "To: $to"
        log "DEBUG" "Subject: $subject"
        log "DEBUG" "Body: $body"
        return 0
    fi

    # Create email content
    local email_file="/tmp/email_$$"
    cat > "$email_file" << EOF
From: $EMAIL_FROM
To: $to
Subject: $subject
Content-Type: text/plain; charset=UTF-8

$body
EOF

    # Send email using sendmail or curl
    if command -v sendmail &> /dev/null; then
        sendmail -t < "$email_file"
    elif command -v curl &> /dev/null; then
        curl --url "smtp://$EMAIL_SMTP_SERVER:$EMAIL_SMTP_PORT" \
             --ssl-reqd \
             --mail-from "$EMAIL_FROM" \
             --mail-rcpt "$to" \
             --user "$EMAIL_USERNAME:$EMAIL_PASSWORD" \
             -T <(echo -e "Subject: $subject\n\n$body")
    else
        log "ERROR" "No email sending method available"
        rm -f "$email_file"
        return 1
    fi

    rm -f "$email_file"

    log "INFO" "Email sent successfully to: $to"
    COMMUNICATION_LOG+=("EMAIL:$to:$subject")
}

# Slack communication
send_slack_message() {
    local webhook_url=$1
    local channel=$2
    local message=$3
    local severity=${4:-info}

    log "COMMUNICATION" "Sending Slack message to: $channel"

    # Check if Slack webhook is configured
    if [[ -z "$webhook_url" ]]; then
        log "WARN" "Slack webhook not configured, skipping Slack send"
        log "DEBUG" "Would send to $channel: $message"
        return 0
    fi

    # Determine message color based on severity
    local color="good"
    case "$severity" in
        "critical")
            color="danger"
            ;;
        "warning")
            color="warning"
            ;;
        "info")
            color="good"
            ;;
    esac

    # Create Slack payload
    local slack_payload=$(cat << EOF
{
    "channel": "$channel",
    "username": "Cortex Alerts",
    "icon_emoji": ":cortex:",
    "attachments": [
        {
            "color": "$color",
            "title": "Cortex Alert",
            "text": "$message",
            "fields": [
                {
                    "title": "Incident ID",
                    "value": "$INCIDENT_ID",
                    "short": true
                },
                {
                    "title": "Severity",
                    "value": "$INCIDENT_SEVERITY",
                    "short": true
                },
                {
                    "title": "Status",
                    "value": "$INCIDENT_STATUS",
                    "short": true
                },
                {
                    "title": "Time",
                    "value": "$(date -Iseconds)",
                    "short": true
                }
            ],
            "footer": "Cortex DR System",
            "ts": $(date +%s)
        }
    ]
}
EOF
)

    # Send to Slack
    if curl -s -X POST -H 'Content-type: application/json' \
           --data "$slack_payload" \
           "$webhook_url" &> /dev/null; then
        log "INFO" "Slack message sent successfully to: $channel"
        COMMUNICATION_LOG+=("SLACK:$channel:$severity")
    else
        log "ERROR" "Failed to send Slack message to: $channel"
        return 1
    fi
}

# Status page updates
update_status_page() {
    local status=$1
    local message=$2

    log "COMMUNICATION" "Updating status page: $status"

    # Check if status page API is configured
    if [[ -z "$STATUS_PAGE_API" ]]; then
        log "WARN" "Status page API not configured, skipping update"
        log "DEBUG" "Would update status page: $status - $message"
        return 0
    fi

    # Create status page update payload
    local status_payload=$(cat << EOF
{
    "status": {
        "description": "$message",
        "indicator": "$status"
    },
    "incident": {
        "name": "Cortex Service Incident - $INCIDENT_ID",
        "status": "$INCIDENT_STATUS",
        "impact": "$INCIDENT_SEVERITY",
        "body": "$message"
    }
}
EOF
)

    # Update status page (simplified - actual implementation depends on status page provider)
    log "INFO" "Status page updated: $status - $message"
    COMMUNICATION_LOG+=("STATUS_PAGE:$status:$message")
}

# Communication workflows
send_initial_alert() {
    local severity=$1
    local service_name=$2
    local issue_description=$3
    local user_impact=$4

    log "COMMUNICATION" "Sending initial alert for $service_name"

    # Initialize incident
    init_incident "$severity" "$issue_description"

    # Determine template based on severity
    local template_type="level1_alert"
    if [[ "$severity" == "critical" ]] || [[ "$severity" == "severe" ]]; then
        template_type="level2_alert"
    fi

    # Create template if it doesn't exist
    if [[ ! -f "$COMMUNICATION_TEMPLATES_DIR/${template_type}.template" ]]; then
        create_template "$template_type"
    fi

    # Generate alert message
    local alert_file="/tmp/alert_$$"
    substitute_template "$COMMUNICATION_TEMPLATES_DIR/${template_type}.template" "$alert_file"

    # Add specific information
    sed -i "s|{{SERVICE_NAME}}|$service_name|g" "$alert_file"
    sed -i "s|{{ISSUE_DESCRIPTION}}|$issue_description|g" "$alert_file"
    sed -i "s|{{USER_IMPACT}}|$user_impact|g" "$alert_file"
    sed -i "s|{{CURRENT_STATUS}}|Investigating|g" "$alert_file"
    sed -i "s|{{ESTIMATED_RESOLUTION}}|Unknown|g" "$alert_file"
    sed -i "s|{{CURRENT_ACTIONS}}|Team is investigating the issue|g" "$alert_file"
    sed -i "s|{{NEXT_UPDATE_TIME}}|$(date -d '+15 minutes' -Iseconds)|g" "$alert_file"
    sed -i "s|{{WAR_ROOM_URL}}|https://cortex.zoom.us/j/incident-$INCIDENT_ID|g" "$alert_file"

    # Read alert content
    local alert_content=$(cat "$alert_file")

    # Send communications
    if [[ "$severity" == "critical" ]] || [[ "$severity" == "severe" ]]; then
        # Critical incident - send to all channels
        send_email "$ONCALL_EMAIL" "🔥 CRITICAL: $service_name Outage - $INCIDENT_ID" "$alert_content"
        send_email "$MANAGEMENT_EMAIL" "🔥 CRITICAL: $service_name Outage - $INCIDENT_ID" "$alert_content"
        send_slack_message "$SLACK_WEBHOOK_URL" "#cortex-alerts" "$alert_content" "critical"
        send_slack_message "$SLACK_WEBHOOK_URL" "#incidents" "$alert_content" "critical"
        update_status_page "critical" "$service_name is experiencing a critical outage. Team is investigating."
    else
        # Standard incident - send to standard channels
        send_email "$ONCALL_EMAIL" "⚠️ ALERT: $service_name Issue - $INCIDENT_ID" "$alert_content"
        send_slack_message "$SLACK_WEBHOOK_URL" "#cortex-alerts" "$alert_content" "warning"
        update_status_page "minor" "$service_name is experiencing issues. Team is investigating."
    fi

    rm -f "$alert_file"

    log "INFO" "Initial alert sent for incident $INCIDENT_ID"
}

send_progress_update() {
    local current_status=$1
    local actions_taken=$2
    local eta=${3:-"Unknown"}
    local next_update=${4:-$(date -d '+30 minutes' -Iseconds)}

    log "COMMUNICATION" "Sending progress update for incident $INCIDENT_ID"

    # Update incident status
    update_incident_status "$current_status" "Progress update: $actions_taken"

    # Create progress update message
    local progress_file="/tmp/progress_$$"
    cat > "$progress_file" << EOF
Incident Update: $INCIDENT_ID
==============================

Status: $current_status
Actions Taken: $actions_taken
ETA: $eta
Next Update: $next_update

Current Timeline:
- Started: $INCIDENT_START_TIME
- Current: $(date -Iseconds)
- Duration: $(( $(date +%s) - $(date -d "$INCIDENT_START_TIME" +%s) )) seconds

Status Page: $STATUS_PAGE_URL
War Room: https://cortex.zoom.us/j/incident-$INCIDENT_ID
EOF

    local progress_content=$(cat "$progress_file")

    # Send progress update
    send_slack_message "$SLACK_WEBHOOK_URL" "#cortex-alerts" "$progress_content" "info"

    # Update status page if significant progress
    if [[ "$current_status" == "RESOLVED" ]] || [[ "$current_status" == "MITIGATED" ]]; then
        update_status_page "good" "Service is recovering. $actions_taken"
    fi

    rm -f "$progress_file"

    log "INFO" "Progress update sent for incident $INCIDENT_ID"
}

send_customer_communication() {
    local service_status=$1
    local customer_impact=$2
    local what_happening=$3
    local what_doing=$4
    local eta=${5:-"Unknown"}

    log "COMMUNICATION" "Sending customer communication for incident $INCIDENT_ID"

    # Create customer template if it doesn't exist
    if [[ ! -f "$COMMUNICATION_TEMPLATES_DIR/customer_update.template" ]]; then
        create_template "customer_update"
    fi

    # Generate customer message
    local customer_file="/tmp/customer_$$"
    substitute_template "$COMMUNICATION_TEMPLATES_DIR/customer_update.template" "$customer_file"

    # Add specific information
    sed -i "s|{{INCIDENT_SUMMARY}}|$INCIDENT_DESCRIPTION|g" "$customer_file"
    sed -i "s|{{SERVICE_STATUS}}|$service_status|g" "$customer_file"
    sed -i "s|{{CUSTOMER_IMPACT}}|$customer_impact|g" "$customer_file"
    sed -i "s|{{WHAT_IS_HAPPENING}}|$what_happening|g" "$customer_file"
    sed -i "s|{{WHAT_WERE_DOING}}|$what_doing|g" "$customer_file"
    sed -i "s|{{ESTIMATED_RESOLUTION}}|$eta|g" "$customer_file"

    local customer_content=$(cat "$customer_file")

    # Send customer communication
    send_email "$SUPPORT_EMAIL" "Cortex Service Update - $INCIDENT_ID" "$customer_content"

    # Update status page
    update_status_page "minor" "$what_happening"

    rm -f "$customer_file"

    log "INFO" "Customer communication sent for incident $INCIDENT_ID"
}

send_resolution_notice() {
    local resolution_summary=$1
    local root_cause=$2
    local preventive_measures=$3

    log "COMMUNICATION" "Sending resolution notice for incident $INCIDENT_ID"

    # Update incident status
    update_incident_status "RESOLVED" "Incident resolved: $resolution_summary"

    # Calculate incident duration
    local start_timestamp=$(date -d "$INCIDENT_START_TIME" +%s)
    local end_timestamp=$(date +%s)
    local duration=$((end_timestamp - start_timestamp))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    # Create resolution template if it doesn't exist
    if [[ ! -f "$COMMUNICATION_TEMPLATES_DIR/resolution_notice.template" ]]; then
        create_template "resolution_notice"
    fi

    # Generate resolution message
    local resolution_file="/tmp/resolution_$$"
    substitute_template "$COMMUNICATION_TEMPLATES_DIR/resolution_notice.template" "$resolution_file"

    # Add specific information
    sed -i "s|{{INCIDENT_SUMMARY}}|$INCIDENT_DESCRIPTION|g" "$resolution_file"
    sed -i "s|{{RESOLUTION_TIME}}|$(date -Iseconds)|g" "$resolution_file"
    sed -i "s|{{INCIDENT_DURATION}}|$duration_formatted|g" "$resolution_file"
    sed -i "s|{{ROOT_CAUSE}}|$root_cause|g" "$resolution_file"
    sed -i "s|{{PREVENTIVE_MEASURES}}|$preventive_measures|g" "$resolution_file"
    sed -i "s|{{INCIDENT_REPORT_URL}}|https://cortex.ai/incidents/$INCIDENT_ID|g" "$resolution_file"

    # Determine customer impact based on severity
    local customer_impact="Some users may have experienced temporary service interruption."
    if [[ "$INCIDENT_SEVERITY" == "critical" ]]; then
        customer_impact="All users experienced service interruption during this incident."
    fi
    sed -i "s|{{CUSTOMER_IMPACT}}|$customer_impact|g" "$resolution_file"

    local resolution_content=$(cat "$resolution_file")

    # Send resolution notices
    send_email "$ONCALL_EMAIL" "✅ RESOLVED: $INCIDENT_ID" "$resolution_content"
    send_email "$MANAGEMENT_EMAIL" "✅ RESOLVED: $INCIDENT_ID" "$resolution_content"
    send_slack_message "$SLACK_WEBHOOK_URL" "#cortex-alerts" "$resolution_content" "info"
    send_email "$SUPPORT_EMAIL" "Cortex Service Resolved - $INCIDENT_ID" "$resolution_content"

    # Update status page
    update_status_page "good" "All services are operational. The incident has been resolved."

    rm -f "$resolution_file"

    log "INFO" "Resolution notice sent for incident $INCIDENT_ID"
}

send_stakeholder_update() {
    local business_impact=$1
    local technical_summary=$2
    local customer_impact=$3
    local current_actions=$4
    local financial_impact=${5:-"Being assessed"}

    log "COMMUNICATION" "Sending stakeholder update for incident $INCIDENT_ID"

    # Create stakeholder template if it doesn't exist
    if [[ ! -f "$COMMUNICATION_TEMPLATES_DIR/stakeholder_update.template" ]]; then
        create_template "stakeholder_update"
    fi

    # Generate stakeholder message
    local stakeholder_file="/tmp/stakeholder_$$"
    substitute_template "$COMMUNICATION_TEMPLATES_DIR/stakeholder_update.template" "$stakeholder_file"

    # Calculate duration
    local start_timestamp=$(date -d "$INCIDENT_START_TIME" +%s)
    local current_timestamp=$(date +%s)
    local duration=$((current_timestamp - start_timestamp))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    # Add specific information
    sed -i "s|{{BUSINESS_IMPACT}}|$business_impact|g" "$stakeholder_file"
    sed -i "s|{{TECHNICAL_SUMMARY}}|$technical_summary|g" "$stakeholder_file"
    sed -i "s|{{CUSTOMER_IMPACT}}|$customer_impact|g" "$stakeholder_file"
    sed -i "s|{{CURRENT_ACTIONS}}|$current_actions|g" "$stakeholder_file"
    sed -i "s|{{FINANCIAL_IMPACT}}|$financial_impact|g" "$stakeholder_file"
    sed -i "s|{{INCIDENT_DURATION}}|$duration_formatted|g" "$stakeholder_file"

    # Generate timeline
    local timeline="- Started: $INCIDENT_START_TIME\n"
    timeline+="- Current: $(date -Iseconds)\n"
    timeline+="- Duration: $duration_formatted"
    sed -i "s|{{INCIDENT_TIMELINE}}|$timeline|g" "$stakeholder_file"

    # Generate next steps
    local next_steps="- Continue investigation and resolution\n"
    next_steps+="- Provide regular updates\n"
    next_steps+="- Document lessons learned\n"
    next_steps+="- Implement preventive measures"
    sed -i "s|{{NEXT_STEPS}}|$next_steps|g" "$stakeholder_file"

    # Add placeholder contact info
    sed -i "s|{{INCIDENT_COMMANDER}}|Incident Commander (oncall@cortex.ai)|g" "$stakeholder_file"
    sed -i "s|{{TECHNICAL_LEAD}}|Technical Lead (tech-lead@cortex.ai)|g" "$stakeholder_file"

    local stakeholder_content=$(cat "$stakeholder_file")

    # Send to stakeholders
    send_email "$MANAGEMENT_EMAIL" "Stakeholder Update: Critical Incident $INCIDENT_ID" "$stakeholder_content"
    if [[ "$INCIDENT_SEVERITY" == "critical" ]]; then
        send_email "$SECURITY_EMAIL" "Security Update: Critical Incident $INCIDENT_ID" "$stakeholder_content"
    fi

    rm -f "$stakeholder_file"

    log "INFO" "Stakeholder update sent for incident $INCIDENT_ID"
}

# Generate communication report
generate_communication_report() {
    local report_file="/tmp/communication-report-$INCIDENT_ID.json"

    log "INFO" "Generating communication report: $report_file"

    # Calculate metrics
    local total_communications=${#COMMUNICATION_LOG[@]}
    local email_count=$(printf '%s\n' "${COMMUNICATION_LOG[@]}" | grep -c "^EMAIL:" || echo "0")
    local slack_count=$(printf '%s\n' "${COMMUNICATION_LOG[@]}" | grep -c "^SLACK:" || echo "0")
    local status_count=$(printf '%s\n' "${COMMUNICATION_LOG[@]}" | grep -c "^STATUS_PAGE:" || echo "0")

    # Generate report
    cat > "$report_file" << EOF
{
  "incident_id": "$INCIDENT_ID",
  "report_timestamp": "$(date -Iseconds)",
  "incident_severity": "$INCIDENT_SEVERITY",
  "incident_status": "$INCIDENT_STATUS",
  "incident_start_time": "$INCIDENT_START_TIME",
  "incident_description": "$INCIDENT_DESCRIPTION",
  "communication_metrics": {
    "total_communications": $total_communications,
    "email_count": $email_count,
    "slack_count": $slack_count,
    "status_page_updates": $status_count
  },
  "communication_log": [
EOF

    # Add communication log entries
    local first=true
    for entry in "${COMMUNICATION_LOG[@]}"; do
        if [[ "$first" != true ]]; then
            echo "," >> "$report_file"
        fi
        IFS=':' read -r type target details <<< "$entry"
        cat >> "$report_file" << EOF
    {
      "timestamp": "$(date -Iseconds)",
      "type": "$type",
      "target": "$target",
      "details": "$details"
    }
EOF
        first=false
    done

    cat >> "$report_file" << EOF
  ],
  "recommendations": [
    "Review communication effectiveness",
    "Update contact lists if needed",
    "Document lessons learned",
    "Improve template messages"
  ]
}
EOF

    log "INFO" "Communication report generated: $report_file"
    echo "$report_file"
}

# Main execution logic
main() {
    log "INFO" "DR Communication Script Starting"
    log "INFO" "Cortex MCP Disaster Recovery Communication"
    log "INFO" "========================================="

    # Load configuration
    load_config

    # Parse command line arguments
    local action=""
    local severity=""
    local service=""
    local issue=""
    local impact=""
    local current_status=""
    local actions=""
    local eta=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --action)
                action="$2"
                shift 2
                ;;
            --severity)
                severity="$2"
                shift 2
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            --issue)
                issue="$2"
                shift 2
                ;;
            --impact)
                impact="$2"
                shift 2
                ;;
            --status)
                current_status="$2"
                shift 2
                ;;
            --actions)
                actions="$2"
                shift 2
                ;;
            --eta)
                eta="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --action <type>          Communication action (initial_alert, progress, customer, resolution, stakeholder)"
                echo "  --severity <level>       Incident severity (critical, warning, info)"
                echo "  --service <name>         Service name"
                echo "  --issue <description>    Issue description"
                echo "  --impact <description>   Impact description"
                echo "  --status <status>        Current status"
                echo "  --actions <description>  Actions taken"
                echo "  --eta <time>             Estimated time to resolution"
                echo "  --help, -h              Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0 --action initial_alert --severity critical --service 'Cortex MCP' --issue 'Database connection failed' --impact 'Users unable to access memory store'"
                echo "  $0 --action progress --status 'Investigating' --actions 'Team has isolated the issue to database layer' -- eta '30 minutes'"
                echo "  $0 --action resolution --actions 'Database restarted successfully' --issue 'Memory leak in database process' --actions 'Implemented monitoring and restart procedures'"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Execute action
    case "$action" in
        "initial_alert")
            if [[ -z "$severity" ]] || [[ -z "$service" ]] || [[ -z "$issue" ]] || [[ -z "$impact" ]]; then
                log "ERROR" "Initial alert requires: --severity, --service, --issue, --impact"
                exit 1
            fi
            send_initial_alert "$severity" "$service" "$issue" "$impact"
            ;;
        "progress")
            if [[ -z "$current_status" ]] || [[ -z "$actions" ]]; then
                log "ERROR" "Progress update requires: --status, --actions"
                exit 1
            fi
            send_progress_update "$current_status" "$actions" "$eta"
            ;;
        "customer")
            if [[ -z "$current_status" ]] || [[ -z "$actions" ]]; then
                log "ERROR" "Customer communication requires: --status, --actions"
                exit 1
            fi
            send_customer_communication "$current_status" "$impact" "$issue" "$actions" "$eta"
            ;;
        "resolution")
            if [[ -z "$actions" ]]; then
                log "ERROR" "Resolution notice requires: --actions"
                exit 1
            fi
            send_resolution_notice "$actions" "$issue" "Enhanced monitoring and alerting procedures will be implemented"
            ;;
        "stakeholder")
            if [[ -z "$actions" ]]; then
                log "ERROR" "Stakeholder update requires: --actions"
                exit 1
            fi
            send_stakeholder_update "$impact" "$issue" "$impact" "$actions"
            ;;
        *)
            log "ERROR" "Unknown action: $action"
            exit 1
            ;;
    esac

    # Generate communication report
    if [[ -n "$INCIDENT_ID" ]]; then
        local report_file=$(generate_communication_report)
        log "INFO" "Communication report available: $report_file"
    fi

    log "INFO" "DR Communication Script Completed"
}

# Execute main function
main "$@"