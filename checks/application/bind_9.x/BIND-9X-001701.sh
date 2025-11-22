#!/usr/bin/env bash
################################################################################
# STIG Check: V-207600
# Severity: low
# Rule Title: On the BIND 9.x server CNAME records must not point to a zone with lesser security for more than six months.
# STIG ID: BIND-9X-001701
# Rule ID: SV-207600r879887
#
# Description:
#     The use of CNAME records for exercises, tests, or zone-spanning aliases should be temporary (e.g., to facilitate a migration). When a host name is an alias for a record in another zone, an adversary has two points of attack: the zone in which the alias is defined and the zone authoritative for the alias'\''s canonical name. This configuration also reduces the speed of client resolution because it requires a second lookup after obtaining the canonical name. Furthermore, in the case of an authorit
#
# Check Content:
#     Verify that the zone files used by the BIND 9.x server do not contain resource records for a domain in which the server is not authoritative.

Inspect the \"named.conf\" file for the following:

zone example.com {
file \"db.example.com.signed\";
};

Inspect each zone file for \"CNAME\" records and verify with the DNS administrator that these records are less than 6 months old.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

If there are CNAME records that point to third-party Content Delivery Networks (CDNs) or cloud computing platforms without an AO-approved and documented mission need, this is a finding.

If a CNAME record is more than six months old, excluding the above, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207600"
STIG_ID="BIND-9X-001701"
SEVERITY="low"
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
