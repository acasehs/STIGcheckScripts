#!/usr/bin/env bash
################################################################################
# STIG Check: V-248670
# Severity: medium
# Rule Title: OL 8 systems below version 8.2 must configure SELinux context type to allow the use of a non-default faillock tally directory.
# STIG ID: OL08-00-020028
# Rule ID: SV-248670r958388
#
# Description:
#     By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

From \"Pam_Faillock\" man pages: Note that the default directory that \"pam_faillock\" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the \"dir\" option. 

SELinux, enforcing
#
# Check Content:
#     If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

Note: This check applies to OL versions 8.0 and 8.1. If the system is OL version 8.2 or newer, this check is not applicable.

Verify the location of the non-default tally directory for the pam_faillock module with the following command:

$ sudo grep -w dir /etc/pam.d/password-auth

auth   required   pam_faillock.so preauth dir=/var/log/faillock
auth   required   pam_faillock.so authfail dir=/var/log/faillock

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
VULN_ID="V-248670"
STIG_ID="OL08-00-020028"
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
    # STIG Check Implementation - Manual Review Required
    #
    # This check requires manual examination of system configuration.
    # Please review the STIG requirement in the header and verify:
    # - System configuration matches STIG requirements
    # - Security controls are properly configured
    # - Compliance status is documented

    echo "INFO: Manual review required for $STIG_ID"
    echo "Rule: Check the rule title in the header above"
    echo ""
    echo "MANUAL REVIEW REQUIRED"
    echo "This STIG check requires manual verification of system configuration."
    echo "Please consult the STIG documentation for specific compliance requirements."

    [[ -n "$OUTPUT_JSON" ]] && output_json "Not_Reviewed" "Manual review required" "Consult STIG documentation for compliance requirements"
    exit 2  # Manual review required

}

# Run main check
main "$@"
