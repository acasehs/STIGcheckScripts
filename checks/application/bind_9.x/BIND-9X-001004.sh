#!/usr/bin/env bash
################################################################################
# STIG Check: V-207536
# Severity: medium
# Rule Title: The host running a BIND 9.X implementation must implement a set of firewall rules that restrict traffic on the DNS interface.
# STIG ID: BIND-9X-001004
# Rule ID: SV-207536r879887
#
# Description:
#     Configuring hosts that run a BIND 9.X implementation to only accept DNS traffic on a DNS interface allows a system firewall to be configured to limit the allowed incoming ports/protocols to 53/tcp and 53/udp. Sending outgoing DNS messages from a random port minimizes the risk of an attacker guessing the outgoing message port and sending forged replies.

The TCP/IP stack in DNS hosts (stub resolver, caching/resolving/recursive name server, authoritative name server, etc.) could be subjected to pa
#
# Check Content:
#     With the assistance of the DNS administrator, verify that the OS firewall is configured to only allow incoming messages on ports 53/tcp and 53/udp.

Note: The following rules are for the IPTables firewall. If the system is utilizing a different firewall, the rules may be different.

Inspect the hosts firewall rules for the following rules:

-A INPUT -i [DNS Interface] -p tcp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -p udp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -j DROP

If any of the above rules do not exist, this is a finding.

If there are rules listed that allow traffic on ports other than 53/tcp and 53/udp, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207536"
STIG_ID="BIND-9X-001004"
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
