#!/usr/bin/env bash
################################################################################
# STIG Check: V-270531
# Severity: high
# Rule Title: The Oracle Listener must be configured to require administration authentication.
# STIG ID: O19C-00-009900
# Rule ID: SV-270531r1065272
#
# Description:
#     Oracle listener authentication helps prevent unauthorized administration of the Oracle listener. Unauthorized administration of the listener could lead to denial-of-service (DoS) exploits, loss of connection audit data, unauthorized reconfiguration, or other unauthorized access. This is a Category I finding because privileged access to the listener is not restricted to authorized users. Unauthorized access can result in stopping of the listener (DoS) and overwriting of listener audit logs.
#
# Check Content:
#     If a listener is not running on the local database host server, this check is not a finding.

Note: Complete this check only once per host system and once per listener. Multiple listeners may be defined on a single host system. They must all be reviewed, but only once per database home review.

For subsequent database home reviews on the same host system, this check is not a finding.

Determine all listeners running on the host.

For Windows hosts, view all Windows services with TNSListener embedded in the service name:

- The service name format is:
Oracle[ORACLE_HOME_NAME]TNSListener

For Unix hosts, the Oracle Listener process will indicate the TNSLSNR executable.

At a command prompt, issue the command:
ps -ef | grep tnslsnr | grep -v grep

The alias for the listener follows tnslsnr in the command output.

Must be logged on the host system using the account that owns the tnslsnr executable (Unix). If the account is denied local logon, have the system administrator (SA) assist in th
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270531"
STIG_ID="O19C-00-009900"
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
    SVC="Windows"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "PASS: Service running and enabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Running" "$SVC"
        exit 0
    else
        echo "FAIL: Service not running/enabled"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not running" "$SVC"
        exit 1
    fi

}

# Run main check
main "$@"
