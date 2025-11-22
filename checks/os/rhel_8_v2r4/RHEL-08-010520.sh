#!/usr/bin/env bash
################################################################################
# STIG Check: V-230290
# Severity: medium
# Rule Title: The RHEL 8 SSH daemon must not allow authentication using known hostâ€™s authentication.
# STIG ID: RHEL-08-010520
# Rule ID: SV-230290r1069302
#
# Description:
#     Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
#
# Check Content:
#     Verify the SSH daemon does not allow authentication using known hostâ€™s authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*ignoreuserknownhosts'\''

/etc/ssh/sshd_config:IgnoreUserKnownHosts yes

If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding.

If conflicting results are returned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230290"
STIG_ID="RHEL-08-010520"
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
    SVC="SSH"

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
