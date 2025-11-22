#!/usr/bin/env bash
################################################################################
# STIG Check: V-258143
# Severity: medium
# Rule Title: RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.
# STIG ID: RHEL-09-652025
# Rule ID: SV-258143r1045283
#
# Description:
#     Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information into the system'\''s logs, or could fill the system'\''s storage leading to a denial of service.

If the system is intended to be a log aggregation server, its use must be documented with the information system security officer (ISSO).
#
# Check Content:
#     Verify that RHEL 9 is not configured to receive remote logs using rsyslog with the following commands:

$ grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*

$ModLoad imtcp
$ModLoad imrelp
$ModLoad imudp

$ grep -i '\''load=\"imtcp\"'\'' /etc/rsyslog.conf /etc/rsyslog.d/*

$ grep -i '\''load=\"imrelp\"'\'' /etc/rsyslog.conf /etc/rsyslog.d/*

$ grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*

$InputTCPServerRun 514
$InputRELPServerRun 514
$InputUDPServerRun 514

$ grep -i '\''port=\"\S*\"'\'' /etc/rsyslog.conf /etc/rsyslog.d/*

/etc/rsyslog.conf:#input(type=\"imudp\" port=\"514\")
/etc/rsyslog.conf:#input(type=\"imtcp\" port=\"514\")
/etc/rsyslog.conf:#Target=\"remote_host\" Port=\"XXX\" Protocol=\"tcp\")

If any uncommented lines are returned by the commands, rsyslog is configured to receive remote messages, and this is a finding.

Note: An error about no files or directories from the above commands may be returned. This is not a finding.

If any modules are being loaded in the \"
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258143"
STIG_ID="RHEL-09-652025"
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
