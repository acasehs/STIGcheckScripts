#!/usr/bin/env bash
################################################################################
# STIG Check: V-214296
# Severity: medium
# Rule Title: The Apache web server must set an inactive timeout for sessions.
# STIG ID: AS24-U2-000660
# Rule ID: SV-214296r1043182
#
# Description:
#     Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the Apache web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 
 
Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications,
#
# Check Content:
#     In a command line, run \"httpd -M | grep -i Reqtimeout_module\". 
 
If the \"Reqtimeout_module\" is not enabled, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214296"
STIG_ID="AS24-U2-000660"
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
    # Check Apache modules
    if ! command -v apachectl &>/dev/null; then
        echo "ERROR: apachectl command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not installed" ""
        exit 3
    fi

    # List loaded modules
    modules=$(apachectl -M 2>/dev/null || httpd -M 2>/dev/null)

    if [[ -z "$modules" ]]; then
        echo "ERROR: Unable to list Apache modules"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Cannot list modules" ""
        exit 3
    fi

    echo "MANUAL REVIEW REQUIRED: Verify required modules are loaded"
    echo "Loaded modules:"
    echo "$modules"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Module check requires validation" "$modules"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
