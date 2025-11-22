#!/usr/bin/env bash
#
# STIG Check: V-248520
# Severity: medium
# Rule Title: OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.
# STIG ID: OL08-00-030181
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No (systemctl status doesn't require root)
# Third-Party Tools: None (uses systemctl)
#
# Description:
#     Verifies that the auditd service is active and running.
#     The audit service must be operational to produce audit records.
#
# Execution:
#     bash V-248520.sh
#     bash V-248520.sh --config stig-config.json
#     bash V-248520.sh --config stig-config.json --output-json results.json
#
# Output Formats:
#     - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
#     - JSON: --output-json results.json
#     - Human Readable: Default to stdout

set -eo pipefail

# Global variables
VULN_ID="V-248520"
SEVERITY="medium"
STIG_ID="OL08-00-030181"
RULE_TITLE="OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events."
STIG_VERSION="Oracle Linux 8 v1r7"

REQUIRED_SERVICE="auditd"
CONFIG_FILE=""
OUTPUT_JSON=""
FORCE=false

# Results tracking
STATUS="Not Checked"
FINDING_DETAILS=()
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --config FILE         Configuration file (JSON)"
            echo "  --output-json FILE    Output results to JSON file"
            echo "  --force               Force execution (ignore elevation checks)"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 3
            ;;
    esac
done

# Load configuration file if provided
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi

    if command -v jq &> /dev/null; then
        # Verify audit_enabled setting in config
        AUDIT_ENABLED=$(jq -r '.operating_system.audit_settings.audit_enabled.value // empty' "$CONFIG_FILE" 2>/dev/null)
        if [[ -n "$AUDIT_ENABLED" ]]; then
            echo "INFO: Loaded configuration from $CONFIG_FILE"
            echo "  - Audit enabled requirement: $AUDIT_ENABLED"
        fi
    else
        echo "WARNING: jq not installed, using default values"
    fi
fi

# Function to add finding details
add_finding() {
    FINDING_DETAILS+=("$1")
}

# Function to check service status
check_service_status() {
    local service="$1"

    if ! command -v systemctl &> /dev/null; then
        echo "ERROR: systemctl not found"
        return 3
    fi

    # Get service status
    local status_output
    status_output=$(systemctl status "$service" 2>&1 || true)

    # Check if service is active
    local is_active
    is_active=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")

    # Check if service is enabled
    local is_enabled
    is_enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")

    echo "$is_active|$is_enabled|$status_output"
}

# Main check logic
run_check() {
    local service_info
    service_info=$(check_service_status "$REQUIRED_SERVICE")

    local is_active
    is_active=$(echo "$service_info" | cut -d'|' -f1)

    local is_enabled
    is_enabled=$(echo "$service_info" | cut -d'|' -f2)

    local status_output
    status_output=$(echo "$service_info" | cut -d'|' -f3-)

    # Analyze results
    if [[ "$is_active" == "active" ]]; then
        STATUS="NotAFinding"

        # Build finding details with audit evidence
        cat <<EOF | add_finding "$(cat)"
{
  "service": "$REQUIRED_SERVICE",
  "status": "PASS",
  "reason": "Audit service is active and running",
  "check_details": {
    "what_was_checked": "Audit service (auditd) operational status",
    "requirement": "The audit service must be active and running to produce audit records",
    "actual_configuration": {
      "service_name": "$REQUIRED_SERVICE",
      "active_state": "$is_active",
      "enabled_state": "$is_enabled",
      "status": "running"
    },
    "expected_configuration": {
      "service_name": "$REQUIRED_SERVICE",
      "active_state": "active",
      "enabled_state": "enabled",
      "status": "running"
    }
  },
  "evidence": {
    "service_active": "Service is in 'active' state",
    "service_enabled": "Service is '${is_enabled}' (will start at boot)",
    "verification_method": "Verified using systemctl status and is-active commands",
    "conclusion": "System meets audit service operational requirements"
  }
}
EOF

        return 0  # PASS

    else
        STATUS="Open"

        # Build finding details with compliance issues
        local compliance_issues="["

        # Add issue for service not active
        compliance_issues+='{
          "issue": "Audit service is not active",
          "evidence": "Service active state: '"$is_active"'",
          "expected": "Service active state must be: active",
          "risk": "Without an active audit service, the system cannot produce audit records for security events, making it impossible to investigate incidents or maintain compliance",
          "remediation": "Start the audit service: sudo systemctl start auditd.service"
        }'

        # Add issue if service not enabled
        if [[ "$is_enabled" != "enabled" ]]; then
            compliance_issues+=',{
              "issue": "Audit service is not enabled at boot",
              "evidence": "Service enabled state: '"$is_enabled"'",
              "expected": "Service enabled state must be: enabled",
              "risk": "Service will not start automatically after system reboot",
              "remediation": "Enable the audit service: sudo systemctl enable auditd.service"
            }'
        fi

        compliance_issues+=']'

        cat <<EOF | add_finding "$(cat)"
{
  "service": "$REQUIRED_SERVICE",
  "status": "FAIL",
  "reason": "Audit service is not active and running",
  "check_details": {
    "what_was_checked": "Audit service (auditd) operational status",
    "requirement": "The audit service must be active and running to produce audit records",
    "actual_configuration": {
      "service_name": "$REQUIRED_SERVICE",
      "active_state": "$is_active",
      "enabled_state": "$is_enabled",
      "status": "not running"
    },
    "expected_configuration": {
      "service_name": "$REQUIRED_SERVICE",
      "active_state": "active",
      "enabled_state": "enabled",
      "status": "running"
    }
  },
  "compliance_issues": $compliance_issues,
  "recommendation": "Start and enable the audit service immediately to begin producing required audit records"
}
EOF

        return 1  # FAIL
    fi
}

# Function to output results in JSON format
output_json() {
    local exit_code=$1

    cat > "$OUTPUT_JSON" <<EOF
{
  "vuln_id": "$VULN_ID",
  "severity": "$SEVERITY",
  "stig_id": "$STIG_ID",
  "stig_version": "$STIG_VERSION",
  "rule_title": "$RULE_TITLE",
  "status": "$STATUS",
  "finding_details": [
$(printf '%s\n' "${FINDING_DETAILS[@]}" | sed '$ ! s/$/,/')
  ],
  "timestamp": "$TIMESTAMP",
  "requires_elevation": false,
  "third_party_tools": "None (uses systemctl)",
  "check_method": "Bash - Native systemd service management",
  "config_file": "${CONFIG_FILE:-None (using defaults)}",
  "exit_code": $exit_code
}
EOF

    echo "Results written to: $OUTPUT_JSON"
}

# Function to print human-readable results
print_results() {
    echo ""
    echo "================================================================================"
    echo "STIG Check: $VULN_ID - $STIG_ID"
    echo "STIG Version: $STIG_VERSION"
    echo "Severity: ${SEVERITY^^}"
    echo "================================================================================"
    echo "Rule: $RULE_TITLE"
    echo "Status: $STATUS"
    echo "Timestamp: $TIMESTAMP"
    echo "Requires Elevation: No"
    echo "Third-Party Tools: None (uses systemctl)"
    echo "Check Method: Bash - Native systemd service management"
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo "Finding Details:"
    echo "--------------------------------------------------------------------------------"

    # Parse and print finding details
    for detail in "${FINDING_DETAILS[@]}"; do
        echo "$detail" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"\\nService: {data.get('service', 'N/A')}\")
    print(f\"  Status: {data.get('status', 'N/A')}\")
    print(f\"  Reason: {data.get('reason', 'N/A')}\")

    if 'check_details' in data:
        check_info = data['check_details']
        print(f\"\\n  What Was Checked:\")
        print(f\"    {check_info.get('what_was_checked', 'N/A')}\")
        print(f\"  Requirement:\")
        print(f\"    {check_info.get('requirement', 'N/A')}\")

    if data.get('status') == 'FAIL' and 'compliance_issues' in data:
        print(f\"\\n  Compliance Issues ({len(data['compliance_issues'])}):\" )
        for i, issue in enumerate(data['compliance_issues'], 1):
            print(f\"\\n    Issue #{i}: {issue.get('issue', 'N/A')}\")
            print(f\"      Evidence Found: {issue.get('evidence', 'N/A')}\")
            print(f\"      Expected: {issue.get('expected', 'N/A')}\")
            print(f\"      Risk: {issue.get('risk', 'N/A')}\")
            print(f\"      Remediation: {issue.get('remediation', 'N/A')}\")

        if 'recommendation' in data:
            print(f\"\\n  Recommendation: {data['recommendation']}\")

    elif data.get('status') == 'PASS' and 'evidence' in data:
        print(f\"\\n  Evidence Supporting PASS:\")
        evidence = data['evidence']
        for key, value in evidence.items():
            if key != 'conclusion':
                print(f\"    ✓ {value}\")
        if 'conclusion' in evidence:
            print(f\"\\n  Conclusion: {evidence['conclusion']}\")

    if 'check_details' in data:
        check_info = data['check_details']
        if 'actual_configuration' in check_info:
            print(f\"\\n  Actual Configuration:\")
            for key, value in check_info['actual_configuration'].items():
                print(f\"    - {key}: {value}\")
        if 'expected_configuration' in check_info:
            print(f\"  Expected Configuration:\")
            for key, value in check_info['expected_configuration'].items():
                print(f\"    - {key}: {value}\")
except:
    print(sys.stdin.read())
"
    done

    echo ""
    echo "================================================================================"
    echo ""
}

# Main execution
EXIT_CODE=0

# Run the check
run_check
EXIT_CODE=$?

# Output results
if [[ -n "$OUTPUT_JSON" ]]; then
    output_json $EXIT_CODE
fi

print_results

exit $EXIT_CODE
