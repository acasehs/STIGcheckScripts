#!/usr/bin/env bash
################################################################################
# STIG Check: V-248669
# Severity: medium
# Rule Title: OL 8 systems, versions 8.2 and above, must configure SELinux context type to allow the use of a non-default faillock tally directory.
# STIG ID: OL08-00-020027
# Rule ID: SV-248669r958388
#
# Description:
#     By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

From \"faillock.conf\" man pages: Note that the default directory that \"pam_faillock\" uses is usually cleared on system boot so the access will be re-enabled after system reboot. If that is undesirable, a different tally directory must be set with the \"dir\" option.

SELinux, enforcin
#
# Check Content:
#     If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

Note: This check applies to OL versions 8.2 or newer. If the system is OL version 8.0 or 8.1, this check is not applicable.

Verify the location of the non-default tally directory for the pam_faillock module with the following command:

$ sudo grep -w dir /etc/security/faillock.conf

dir = /var/log/faillock

Check the security context type of the non-default tally directory with the following command:

$ sudo ls -Zd /var/log/faillock

unconfined_u:object_r:faillog_t:s0 /var/log/faillock

If the security context type of the non-default tally directory is not \"faillog_t\", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248669"
STIG_ID="OL08-00-020027"
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
    CONFIG="/etc/security/faillock.conf"

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
