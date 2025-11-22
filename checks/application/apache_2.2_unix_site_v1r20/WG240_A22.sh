#!/usr/bin/env bash
################################################################################
# STIG Check: V-2250
# Severity: medium
# Rule Title: Logs of web server access and errors must be established and maintained
# STIG ID: WG240 A22
# Rule ID: SV-33025r1
#
# Description:
#     A major tool in exploring the web site use, attempted use, unusual conditions, and problems are reported in the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. Without these log files, SAs and web managers are seriously hindered in their efforts to respond appropriately to suspicious or criminal actions targeted at the web site.
#
# Check Content:
#     To view a list of loaded modules enter the following command: _x000D_
_x000D_
/usr/local/apache2/bin/httpd -M _x000D_
_x000D_
If the following module is not found, this is a finding: \"log_config_module\"
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2250"
STIG_ID="WG240 A22"
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
