#!/usr/bin/env bash
################################################################################
# STIG Check: V-248710
# Severity: medium
# Rule Title: OL 8 must prohibit the use of cached authentications after one day.
# STIG ID: OL08-00-020290
# Rule ID: SV-248710r958828
#
# Description:
#     If cached authentication information is out of date, the validity of the authentication information may be questionable. 
 
OL 8 includes multiple options for configuring authentication, but this requirement will focus on the System Security Services Daemon (SSSD). By default, SSSD does not cache credentials.
#
# Check Content:
#     Verify that the SSSD prohibits the use of cached authentications after one day.
 
Note: If smart card authentication is not being used on the system, this item is not applicable.
 
Check that SSSD allows cached authentications with the following command: 
 
     $ sudo grep -ir cache_credentials /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
     cache_credentials = true 
 
If \"cache_credentials\" is set to \"false\" or is missing from the configuration file, this is not a finding and no further checks are required.
 
If \"cache_credentials\" is set to \"true\", check that SSSD prohibits the use of cached authentications after one day with the following command:
 
     $ sudo grep -ir offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
     offline_credentials_expiration = 1 
 
If \"offline_credentials_expiration\" is not set to a value of \"1\", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248710"
STIG_ID="OL08-00-020290"
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
