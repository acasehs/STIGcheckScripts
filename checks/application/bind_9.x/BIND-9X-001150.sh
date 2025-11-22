#!/usr/bin/env bash
################################################################################
# STIG Check: V-207576
# Severity: high
# Rule Title: The BIND 9.x server signature generation using the KSK must be done off-line, using the KSK-private key stored off-line.
# STIG ID: BIND-9X-001150
# Rule ID: SV-207576r879613
#
# Description:
#     The private key in the KSK key pair must be protected from unauthorized access. The private key should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

Failure to protect the private KSK may have significant effects on the overall security of the DNS infrastructure. A compromised KSK could lead to an inability to detect unauthorized DNS zone data resulting in network t
#
# Check Content:
#     If the server is in a classified network, this is Not Applicable.

Ensure that there are no private KSKs stored on the name sever. 

With the assistance of the DNS Administrator, obtain a list of all DNSSEC private keys that are stored on the name server. 

Inspect the signed zone files(s) and look for the KSK key id:

DNSKEY 257 3 8 ( <hash_algorithm) ; KSK ; alg = ECDSAP256SHA256; key id = 52807

Verify that none of the identified private keys, are KSKs.

An example private KSK would look like the following:

Kexample.com.+008+52807.private

If there are private KSKs stored on the name server, this is a finding.

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207576"
STIG_ID="BIND-9X-001150"
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
