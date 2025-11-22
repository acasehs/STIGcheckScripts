#!/usr/bin/env bash
################################################################################
# STIG Check: V-207534
# Severity: medium
# Rule Title: The platform on which the name server software is hosted must only run processes and services needed to support the BIND 9.x implementation.
# STIG ID: BIND-9X-001002
# Rule ID: SV-207534r879887
#
# Description:
#     Hosts that run the name server software should not provide any other services. Unnecessary services running on the DNS server can introduce additional attack vectors leading to the compromise of an organizationâ€™s DNS architecture.
#
# Check Content:
#     Verify that the BIND 9.x server is dedicated for DNS traffic:

With the assistance of the DNS administrator, identify all of the processes running on the BIND 9.x server:

# ps -ef | less

If any of the identified processes are not in support of normal OS functionality or in support of the BIND 9.x process, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207534"
STIG_ID="BIND-9X-001002"
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
    # Check BIND named process
    process=$(ps -ef | grep named | grep -v grep)

    if [[ -z "$process" ]]; then
        echo "ERROR: named process not running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Service not running" ""
        exit 3
    fi

    echo "INFO: named process found:"
    echo "$process"
    echo ""

    # Check for required arguments
    echo "MANUAL REVIEW REQUIRED: Verify process arguments meet STIG requirements"
    echo "Expected: required arguments"
    echo "Current: $process"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Process check requires validation" "$process"
    exit 2  # Manual review required

}

# Run main check
main "$@"
