#!/usr/bin/env bash
################################################################################
# STIG Check: V-248685
# Severity: medium
# Rule Title: OL 8 must map the authenticated identity to the user or group account for PKI-based authentication.
# STIG ID: OL08-00-020090
# Rule ID: SV-248685r958452
#
# Description:
#     Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis. 
 
There are various methods of mapping certificates to user/group accounts for OL 8. For the purposes of this requirement, the check and fix will account for Active Directory mapping. Some of the other possible methods include joining the system to a domain and using an idM server, or a local system mapping, 
#
# Check Content:
#     Verify the certificate of the user or group is mapped to the corresponding user or group in the \"sssd.conf\" file with the following command:

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

$ sudo cat /etc/sssd/sssd.conf

[sssd]
config_file_version = 2
services = pam, sudo, ssh
domains = testing.test

[pam]
pam_cert_auth = True

[domain/testing.test]
id_provider = ldap

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the \"certmap\" section does not exist, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248685"
STIG_ID="OL08-00-020090"
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
    SVC="2"

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
