#!/usr/bin/env bash
################################################################################
# STIG Check: V-257999
# Severity: medium
# Rule Title: RHEL 9 SSH server configuration files'\'' permissions must not be modified.
# STIG ID: RHEL-09-255115
# Rule ID: SV-257999r1082182
#
# Description:
#     Service configuration files enable or disable features of their respective services, that if configured incorrectly, can lead to insecure and vulnerable configurations. Therefore, service configuration files must have correct permissions (owner, group owner, mode) to prevent unauthorized changes.
#
# Check Content:
#     Verify the permissions of the \"/etc/ssh/sshd_config\" file with the following command:

$ sudo rpm --verify openssh-server

If the command returns any output, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257999"
STIG_ID="RHEL-09-255115"
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
    TARGET="/etc/ssh/sshd_config""
    REQUIRED="600"

    if [[ ! -e "$TARGET" ]]; then
        echo "ERROR: File not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$TARGET"
        exit 3
    fi

    actual=$(stat -c "%a" "$TARGET" 2>/dev/null)
    if [[ $((8#$actual)) -le $((8#$REQUIRED)) ]]; then
        echo "PASS: Permissions $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$actual"
        exit 0
    else
        echo "FAIL: Permissions $actual (required: $REQUIRED or less)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Too permissive" "$actual"
        exit 1
    fi

}

# Run main check
main "$@"
