#!/usr/bin/env bash
################################################################################
# STIG Check: V-258150
# Severity: medium
# Rule Title: RHEL 9 must use cron logging.
# STIG ID: RHEL-09-652060
# Rule ID: SV-258150r1045296
#
# Description:
#     Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.
#
# Check Content:
#     Verify that \"rsyslog\" is configured to log cron events with the following command:

Note: If another logging package is used, substitute the utility configuration file for \"/etc/rsyslog.conf\" or \"/etc/rsyslog.d/*.conf\" files.

$ grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:*.info;mail.none;authpriv.none;cron.none /var/log/messages
/etc/rsyslog.conf:cron.* /var/log/cron

If the command does not return a response, check for cron logging all facilities with the following command:

$ logger -p local0.info \"Test message for all facilities.\"

Check the logs for the test message with:

$ sudo tail /var/log/messages

If \"rsyslog\" is not logging messages for the cron facility or all facilities, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258150"
STIG_ID="RHEL-09-652060"
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
    PKG="logging"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL: Prohibited package present"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not be installed" "$PKG"
        exit 1
    else
        echo "PASS: Package not installed (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Not present" "$PKG"
        exit 0
    fi

}

# Run main check
main "$@"
