#!/usr/bin/env bash
################################################################################
# STIG Check: V-207579
# Severity: medium
# Rule Title: The BIND 9.x server validity period for the RRSIGs covering the DS RR for zones delegated children must be no less than two days and no more than one week.
# STIG ID: BIND-9X-001311
# Rule ID: SV-207579r879634
#
# Description:
#     The best way for a zone administrator to minimize the impact of a key compromise is by limiting the validity period of RRSIGs in the zone and in the parent zone. This strategy limits the time during which an attacker can take advantage of a compromised key to forge responses. An attacker that has compromised a ZSK can use that key only during the KSK'\''s signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG c
#
# Check Content:
#     If the server is in a classified network, this is Not Applicable.
Note: This requirement does not validate the sig-validity-interval. This requirement ensures the signature validity period (i.e., the time from the signatureâ€™s inception until the signatureâ€™s expiration). It is recommended to ensure the Start of Authority (SOA) expire period (how long a secondary will still treat its copy of the zone data as valid if it cannot contact the primary.) is configured to ensure the SOA does not expire during the period of signature inception and signature expiration.

With the assistance of the DNS Administrator, identify the RRSIGs that cover the DS resource records for each child zone.

Each record will list an expiration and inception date, the difference of which will provide the validity period.

The dates are listed in the following format:

YYYYMMDDHHMMSS

For each RRSIG identified, verify that the validity period is no less than two days and is no longer than seven days.

If the va
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207579"
STIG_ID="BIND-9X-001311"
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
    # Generic BIND configuration check
    echo "INFO: Checking BIND installation and configuration"
    echo ""

    # Check if BIND is installed
    if command -v named &>/dev/null; then
        version=$(named -v 2>&1)
        echo "BIND version: $version"
    else
        echo "WARNING: named command not found"
    fi
    echo ""

    # Check for configuration file
    for conf in "/etc/named.conf" "/etc/bind/named.conf" "/var/named/chroot/etc/named.conf"; do
        if [[ -f "$conf" ]]; then
            echo "Configuration file: $conf"
            break
        fi
    done
    echo ""

    echo "MANUAL REVIEW REQUIRED: Review BIND configuration for STIG compliance"
    echo "This check requires manual examination of BIND settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "BIND check requires manual validation" ""
    exit 2  # Manual review required

}

# Run main check
main "$@"
