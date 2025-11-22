#!/usr/bin/env bash
################################################################################
# STIG Check: V-252660
# Severity: medium
# Rule Title: OL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.
# STIG ID: OL08-00-020104
# Rule ID: SV-252660r991589
#
# Description:
#     Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \"pwquality\" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

OL 8 utilizes \"pwquality\" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/e
#
# Check Content:
#     Note: This requirement applies to OL versions 8.4 or newer. If the system is OL below version 8.4, this requirement is not applicable.

Verify the operating system is configured to limit the \"pwquality\" retry option to 3. 

Check for the use of the \"pwquality\" retry option with the following command:

$ sudo grep -r retry /etc/security/pwquality.conf*

/etc/security/pwquality.conf:retry = 3

If the value of \"retry\" is set to \"0\" or greater than \"3\", is commented out or missing, this is a finding.

If conflicting results are returned, this is a finding.

Check for the use of the \"pwquality\" retry option in the system-auth and password-auth files with the following command:

$ sudo grep pwquality /etc/pam.d/system-auth /etc/pam.d/password-auth | grep retry

If the command returns any results, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-252660"
STIG_ID="OL08-00-020104"
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
    CONFIG="/etc/security/pwquality.conf*"

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
