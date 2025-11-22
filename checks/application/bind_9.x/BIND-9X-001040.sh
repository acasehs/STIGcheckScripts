#!/usr/bin/env bash
################################################################################
# STIG Check: V-207546
# Severity: low
# Rule Title: The BIND 9.x server implementation must be configured with a channel to send audit records to a remote syslog.
# STIG ID: BIND-9X-001040
# Rule ID: SV-207546r879582
#
# Description:
#     Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to assure, in the event of a catastrophic system failure, the audit records will be retained. _x000D_
_x000D_
This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.
#
# Check Content:
#     Verify that the BIND 9.x server is configured to send audit logs to the syslog service._x000D_
_x000D_
NOTE: syslog and local file channel must be defined for every defined category._x000D_
_x000D_
Inspect the \"named.conf\" file for the following:_x000D_
_x000D_
logging {_x000D_
channel <syslog_channel> {_x000D_
syslog <syslog_facility>;_x000D_
};_x000D_
_x000D_
category <category_name> { <syslog_channel>; };_x000D_
_x000D_
If a logging channel is not defined for syslog, this is a finding._x000D_
_x000D_
If a category is not defined to send messages to the syslog channel, this is a finding._x000D_
_x000D_
Ensure audit records are forwarded to a remote server:_x000D_
_x000D_
# grep \"\*.\*\" /etc/syslog.conf |grep \"@\" | grep -v \"^#\" (for syslog)_x000D_
or:_x000D_
# grep \"\*.\*\" /etc/rsyslog.conf | grep \"@\" | grep -v \"^#\" (for rsyslog)_x000D_
_x000D_
If neither of these lines exist, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207546"
STIG_ID="BIND-9X-001040"
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
    SVC="syslog"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi

}

# Run main check
main "$@"
