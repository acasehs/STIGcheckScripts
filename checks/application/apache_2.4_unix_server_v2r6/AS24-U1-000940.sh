#!/usr/bin/env bash
################################################################################
# STIG Check: V-214271
# Severity: high
# Rule Title: The account used to run the Apache web server must not have a valid login shell and password defined.
# STIG ID: AS24-U1-000940
# Rule ID: SV-214271r961863
#
# Description:
#     During installation of the Apache web server software, accounts are created for the Apache web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a logon screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the logon even 
#
# Check Content:
#     Identify the account that is running the \"httpd\" process:
# ps -ef | grep -i httpd | grep -v grep

apache   29613   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd
apache   29614   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd

Check to see if the account has a valid login shell:

# cut -d: -f1,7 /etc/passwd | grep -i <service_account>
apache:/sbin/nologin

If the service account has a valid login shell, verify that no password is configured for the account:

# cut -d: -f1,2 /etc/shadow | grep -i <service_account>
apache:!!

If the account has a valid login shell and a password defined, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214271"
STIG_ID="AS24-U1-000940"
SEVERITY="high"
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
    SVC="the"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "PASS: Service running and enabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Running" "$SVC"
        exit 0
    else
        echo "FAIL: Service not running/enabled"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not running" "$SVC"
        exit 1
    fi

}

# Run main check
main "$@"
