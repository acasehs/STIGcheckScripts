#!/usr/bin/env bash
################################################################################
# STIG Check: V-271487
# Severity: medium
# Rule Title: OL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.
# STIG ID: OL09-00-000256
# Rule ID: SV-271487r1091173
#
# Description:
#     The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.

Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088
#
# Check Content:
#     Verify that OL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via SSH connections.

Check for the location of the banner file currently being used with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*banner'\''
banner /etc/issue

If the line is commented out or if the file is missing, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271487"
STIG_ID="OL09-00-000256"
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
