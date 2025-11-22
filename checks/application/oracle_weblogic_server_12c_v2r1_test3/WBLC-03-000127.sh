#!/usr/bin/env bash
################################################################################
# STIG Check: Unknown
# Severity: medium
# Rule Title: Oracle WebLogic must adhere to the principles of least functionality by providing only essential capabilities.
# STIG ID: WBLC-03-000127
# Rule ID: SV-235961r628661_rule
#
# Description:
#      Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too insecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.
#
# Check Content:
#     1. Access AC
2. From '\''Domain Structure'\'', select '\''Deployments'\''
3. Select a deployment of type '\''Web Application'\'' from list of deployments
4. Select '\''Configuration'\'' tab -> '\''General'\'' tab
5. Ensure '\''JSP Page Check'\'' field value is set to '\''-1'\'', which indicates JSP reloading is disabled within this deployment. Repeat steps 3-5 for all '\''Web Application'\'' type deployments
6. For every WebLogic resource within the domain, the '\''Configuration'\'' tab and associated subtabs provide the ability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance

If the '\''JSP Page Check'\'' field is not set to '\''-1'\'' or other services or functionality deemed to be non-essential to the server mission is not set to '\''-1'\'', this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="Unknown"
STIG_ID="WBLC-03-000127"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Parse arguments
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
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 3
            ;;
    esac
done

# Load configuration if provided
if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
    # Source configuration or parse JSON as needed
    :
fi

################################################################################
# HELPER FUNCTIONS
################################################################################

# Output results in JSON format
output_json() {
    local status="$1"
    local message="$2"
    local details="$3"

    cat > "$OUTPUT_JSON" << EOF
{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "status": "$status",
  "message": "$message",
  "details": "$details",
  "timestamp": "$TIMESTAMP"
}
EOF
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {
    SVC="and"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi

}

# Run main check
main "$@"
