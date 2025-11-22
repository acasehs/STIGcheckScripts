#!/usr/bin/env bash
################################################################################
# STIG Check: V-207566
# Severity: medium
# Rule Title: The BIND 9.X implementation must not utilize a TSIG or DNSSEC key for more than one year.
# STIG ID: BIND-9X-001113
# Rule ID: SV-207566r879887
#
# Description:
#     Cryptographic keys are the backbone of securing DNS information over the wire, maintaining DNS data integrity, and the providing the ability to validate DNS information that is received.

When a cryptographic key is utilized by a DNS server for a long period of time, the likelihood of compromise increases. A compromised key set would allow an attacker to intercept and possibly inject comprised data into the DNS server. In this compromised state, the DNS server would be vulnerable to DoS attacks,
#
# Check Content:
#     With the assistance of the DNS Administrator, identify all of the cryptographic key files used by the BIND 9.x implementation.

With the assistance of the DNS Administrator, determine the location of the cryptographic key files used by the BIND 9.x implementation.

# ls â€“al <Crypto_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 crypto-example.key

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.

For DNSSEC Keys:
Verify that the â€œCreatedâ€ date is less than one year from the date of inspection:

Note: The date format will be displayed in YYYYMMDDHHMMSS.

# cat <DNSSEC_Key_File> | grep -i â€œcreatedâ€
Created: 20160704235959

If the â€œCreatedâ€ date is more than one year old, this is a finding.

For TSIG Keys:

Verify with the ISSO/ISSM that the TSIG keys are less than one year old.

If a TSIG key is more than one year old, this is a finding.

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207566"
STIG_ID="BIND-9X-001113"
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
