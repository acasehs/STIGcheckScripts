#!/usr/bin/env bash
################################################################################
# STIG Check: V-207561
# Severity: high
# Rule Title: The BIND 9.x server implementation must uniquely identify and authenticate the other DNS server before responding to a server-to-server transaction, zone transfer and/or dynamic update request using c
# STIG ID: BIND-9X-001100
# Rule ID: SV-207561r879599
#
# Description:
#     Server-to-server (zone transfer) transactions are provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG), thus uniquely identifying the other server. DNS does perform server authentication when TSIG is used, but this authentication is transactional in nature (each transaction has its own authentication performed).

Enforcing mutually authenticated communication sessions during zone transfers provides the assurance that only authorized 
#
# Check Content:
#     If zone transfers are disabled with the \"allow-transfer { none; };\" directive, this is Not Applicable.
If the server is in a classified network, this is Not Applicable.

Verify that the BIND 9.x server is configured to uniquely identify a name server before responding to a zone transfer.

Inspect the \"named.conf\" file for the presence of TSIG key statements:

On the master name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include \"tsig-example.key\";
};

zone \"disa.mil\" {
type master;
file \"db.disa.mil\";
allow-transfer { key tsig_example.; };
};

On the slave name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include \"tsig-example.key\";
};

server <ip_address> {
keys { tsig_example };
};

zone \"disa.mil\" {
type slave;
masters { <ip_address>; };
file \"db.disa.mil\";
};

If a master name server does not have a key defined in the â€œallow-transferâ€ block, this is a 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207561"
STIG_ID="BIND-9X-001100"
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
    echo "Required settings: file, allow-transfer"
    echo ""
    echo "This check requires manual examination of BIND configuration"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Configuration requires validation" "$NAMED_CONF"
    exit 2  # Manual review required

}

# Run main check
main "$@"
