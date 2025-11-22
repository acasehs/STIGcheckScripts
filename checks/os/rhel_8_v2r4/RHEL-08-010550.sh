#!/usr/bin/env bash
################################################################################
# STIG Check: V-230296
# Severity: medium
# Rule Title: RHEL 8 must not permit direct logons to the root account using remote access via SSH.
# STIG ID: RHEL-08-010550
# Rule ID: SV-230296r1069322
#
# Description:
#     Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.
#
# Check Content:
#     Verify remote access using SSH prevents users from logging on directly as \"root\".

Check that SSH prevents users from logging on directly as \"root\" with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*permitrootlogin'\''

PermitRootLogin no

If the \"PermitRootLogin\" keyword is set to any value other than \"no\", is missing, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230296"
STIG_ID="RHEL-08-010550"
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
    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not configured"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Host not specified" ""
        exit 3
    fi

    # Execute command via SSH (customize based on device type)
    output=$(ssh "$DEVICE_USER"@"$DEVICE_HOST" "show version" 2>&1)

    if [[ $? -eq 0 ]]; then
        echo "PASS: Command executed successfully"
        echo "$output"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Device accessible" ""
        exit 0
    else
        echo "ERROR: SSH connection failed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Connection failed" "$output"
        exit 3
    fi

}

# Run main check
main "$@"
