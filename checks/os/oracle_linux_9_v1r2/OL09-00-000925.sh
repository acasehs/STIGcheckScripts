#!/usr/bin/env bash
################################################################################
# STIG Check: V-271607
# Severity: medium
# Rule Title: OL 9 must enable certificate-based smart card authentication.
# STIG ID: OL09-00-000925
# Rule ID: SV-271607r1091533
#
# Description:
#     Without the use of multifactor authentication (MFA), the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD Common Access Card (CAC) with DOD-approved PKI is an example of multifactor authentication.

Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000105-GPOS-00052
#
# Check Content:
#     Verify that OL 9 has smart cards enabled in System Security Services Daemon (SSSD) if smart cards are used for MFA with the following command:

$ sudo grep pam_cert_auth /etc/sssd/sssd.conf
pam_cert_auth = True 

If \"pam_cert_auth\" is not set to \"True\", the line is commented out, or the line is missing, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271607"
STIG_ID="OL09-00-000925"
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
    CONFIG="/etc/sssd/sssd.conf"

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
