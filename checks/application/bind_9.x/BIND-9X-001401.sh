#!/usr/bin/env bash
################################################################################
# STIG Check: V-207584
# Severity: medium
# Rule Title: On a BIND 9.x server in a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from
# STIG ID: BIND-9X-001401
# Rule ID: SV-207584r879887
#
# Description:
#     Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal n
#
# Check Content:
#     If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the external view of the BIND 9.x server is configured to only serve external hosts.

Inspect the \"named.conf\" file for the following:

view \"external\" {
match-clients { <ip_address> | <address_match_list>; };
};

If the \"match-clients\" sub statement does not limit the external view to external hosts only, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207584"
STIG_ID="BIND-9X-001401"
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
