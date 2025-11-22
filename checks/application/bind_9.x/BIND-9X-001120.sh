#!/usr/bin/env bash
################################################################################
# STIG Check: V-207567
# Severity: high
# Rule Title: A BIND 9.x server must implement NIST FIPS-validated cryptography for provisioning digital signatures and generating cryptographic hashes.
# STIG ID: BIND-9X-001120
# Rule ID: SV-207567r879885
#
# Description:
#     The use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST'\''s Digital Signature Standard (DSS) [FIPS186] provides three algorithm choices:

-
#
# Check Content:
#     Verify that the DNSSEC and TSIG keys used by the BIND 9.x implementation are FIPS 180-3 compliant.

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.
DNSSEC KEYS:

Inspect the \"named.conf\" file and identify all of the DNSSEC signed zone files:

zone \"example.com\" {
file \"signed_zone_file\";
};

For each signed zone file identified, inspect the file for the \"DNSKEY\" records: 

86400 DNSKEY 257 3 8 (
<KEY HASH>
) ; KSK; 
86400 DNSKEY 256 3 8 (
<KEY HASH>
) ; ZSK; 

The fifth field in the above example identifies what algorithm was used to create the DNSKEY. 

If the fifth field the KSK DNSKEY is less than â€œ8â€ (SHA256), this is a finding.

If the algorithm used to create the ZSK is less than â€œ8â€ (SHA256), this is a finding.

TSIG KEYS: 

Inspect the \"named.conf\" file and identify all of the TSIG key statements: 

key tsig_example. {
algorithm hmac-SHA256;
include \"tsig-example.key\";
};

If each key statement does not use 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207567"
STIG_ID="BIND-9X-001120"
SEVERITY="high"
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
    # Locate BIND configuration file
    NAMED_CONF="/etc/named.conf"

    # Check common locations
    if [[ ! -f "$NAMED_CONF" ]]; then
        for conf in "/etc/bind/named.conf" "/var/named/chroot/etc/named.conf"; do
            if [[ -f "$conf" ]]; then
                NAMED_CONF="$conf"
                break
            fi
        done
    fi

    if [[ ! -f "$NAMED_CONF" ]]; then
        echo "ERROR: named.conf not found in standard locations"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file not found" ""
        exit 3
    fi

    echo "INFO: Found BIND configuration: $NAMED_CONF"
    echo ""

    # Display relevant configuration sections
    echo "Configuration preview:"
    grep -E "^[[:space:]]*(logging|options|zone|acl|view)" "$NAMED_CONF" | head -20
    echo ""

    echo "MANUAL REVIEW REQUIRED: Review BIND configuration for STIG compliance"
    echo "Configuration file: $NAMED_CONF"
    echo "Required settings: file"
    echo ""
    echo "This check requires manual examination of BIND configuration"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Configuration requires validation" "$NAMED_CONF"
    exit 2  # Manual review required

}

# Run main check
main "$@"
