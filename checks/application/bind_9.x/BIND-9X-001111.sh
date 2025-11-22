#!/usr/bin/env bash
################################################################################
# STIG Check: V-207564
# Severity: medium
# Rule Title: The TSIG keys used with the BIND 9.x implementation must be group owned by a privileged account.
# STIG ID: BIND-9X-001111
# Rule ID: SV-207564r879613
#
# Description:
#     Incorrect ownership of a TSIG key file could allow an adversary to modify the file, thus defeating the security objective.
#
# Check Content:
#     With the assistance of the DNS Administrator, identify all of the TSIG keys used by the BIND 9.x implementation.

Identify the account that the \"named\" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation.

# ls â€“al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If any of the TSIG keys are not group owned by the above account, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207564"
STIG_ID="BIND-9X-001111"
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
    echo "Expected: "-t" and "-u""
    echo "Current: $process"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Process check requires validation" "$process"
    exit 2  # Manual review required

}

# Run main check
main "$@"
