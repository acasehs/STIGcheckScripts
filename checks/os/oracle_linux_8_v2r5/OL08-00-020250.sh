#!/usr/bin/env bash
################################################################################
# STIG Check: V-248702
# Severity: medium
# Rule Title: OL 8 must implement multifactor authentication for access to interactive accounts.
# STIG ID: OL08-00-020250
# Rule ID: SV-248702r1015060
#
# Description:
#     Using an authentication device, such as a Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device. 
 
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Pe
#
# Check Content:
#     Verify OL 8 uses multifactor authentication for local access to accounts.

Note: If the system administrator (SA) demonstrates the use of an approved alternate multifactor authentication method, this requirement is Not Applicable.

Check that the \"pam_cert_auth\" setting is set to \"true\" in the \"/etc/sssd/sssd.conf\" file.

Check that the \"try_cert_auth\" or \"require_cert_auth\" options are configured in both \"/etc/pam.d/system-auth\" and \"/etc/pam.d/smartcard-auth\" files with the following command:

     $ sudo grep -ir cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf /etc/pam.d/*

     /etc/sssd/sssd.conf:pam_cert_auth = True
     /etc/pam.d/smartcard-auth:auth sufficient pam_sss.so try_cert_auth
     /etc/pam.d/system-auth:auth [success=done authinfo_unavail=ignore ignore=ignore default=die] pam_sss.so try_cert_auth

If \"pam_cert_auth\" is not set to \"true\" in \"/etc/sssd/sssd.conf\", this is a finding.

If \"pam_sss.so\" is not set to \"try_cert_auth\" or \"require
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248702"
STIG_ID="OL08-00-020250"
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
    CONFIG="/etc/sssd/sssd.conf""

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
