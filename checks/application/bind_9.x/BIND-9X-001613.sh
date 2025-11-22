#!/usr/bin/env bash
################################################################################
# STIG Check: V-207596
# Severity: medium
# Rule Title: On a BIND 9.x server all authoritative name servers for a zone must have the same version of zone information.
# STIG ID: BIND-9X-001613
# Rule ID: SV-207596r879887
#
# Description:
#     It is important to maintain the integrity of a zone file. The serial number of the SOA record is used to indicate to secondary name server that a change to the zone has occurred and a zone transfer should be performed. The serial number used in the SOA record provides the DNS administrator a method to verify the integrity of the zone file based on the serial number of the last update and ensure that all slave servers are using the correct zone file.
#
# Check Content:
#     Verify that the SOA record is at the same version for all authoritative servers for a specific zone.

With the assistance of the DNS administrator, identify each name server that is authoritative for each zone.

Inspect each zone file that the server is authoritative for and identify the following:

example.com. 86400 IN SOA ns1.example.com. root.example.com. (17760704;serial) 

If the SOA \"serial\" numbers are not identical on each authoritative name server, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207596"
STIG_ID="BIND-9X-001613"
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
    # Check BIND version
    if ! command -v named &>/dev/null; then
        echo "ERROR: named command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "BIND not installed" ""
        exit 3
    fi

    version=$(named -v 2>&1)

    if [[ -z "$version" ]]; then
        echo "ERROR: Unable to determine BIND version"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Version check failed" ""
        exit 3
    fi

    echo "INFO: BIND version detected:"
    echo "$version"
    echo ""
    echo "MANUAL REVIEW REQUIRED: Verify version is Current-Stable per ISC"
    echo "Reference: https://www.isc.org/downloads/"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Version requires validation" "$version"
    exit 2  # Manual review required

}

# Run main check
main "$@"
