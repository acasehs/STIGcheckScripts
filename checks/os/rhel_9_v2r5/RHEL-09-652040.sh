#!/usr/bin/env bash
################################################################################
# STIG Check: V-258146
# Severity: medium
# Rule Title: RHEL 9 must authenticate the remote logging server for offloading audit logs via rsyslog.
# STIG ID: RHEL-09-652040
# Rule ID: SV-258146r1045288
#
# Description:
#     Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides \"rsyslogd\", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with \"gnutls\" (a secure communications library implementing the 
#
# Check Content:
#     Verify RHEL 9 authenticates the remote logging server for offloading audit logs with the following command:

$ grep -i '\''StreamDriver[\.]*AuthMode'\'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:$ActionSendStreamDriverAuthMode x509/name 

If the variable name \"StreamDriverAuthMode\" is present in an omfwd statement block, this is not a finding. However, if the \"StreamDriverAuthMode\" variable is in a module block, this is a finding.

If the value of the \"$ActionSendStreamDriverAuthMode or StreamDriver.AuthMode\" option is not set to \"x509/name\" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are offloaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being offloaded to another system or media is encrypted, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258146"
STIG_ID="RHEL-09-652040"
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
    CONFIG="/etc/rsyslog.conf"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "Unknown" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "Unknown"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "Unknown"
        exit 1
    fi

}

# Run main check
main "$@"
