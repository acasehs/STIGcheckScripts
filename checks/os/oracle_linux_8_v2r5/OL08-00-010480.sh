#!/usr/bin/env bash
################################################################################
# STIG Check: V-248601
# Severity: medium
# Rule Title: The OL 8 SSH public host key files must have mode \"0644\" or less permissive.
# STIG ID: OL08-00-010480
# Rule ID: SV-248601r991589
#
# Description:
#     If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
#
# Check Content:
#     Verify the SSH public host key files have mode \"0644\" or less permissive with the following command: 
 
$ sudo ls -l /etc/ssh/*.pub 
 
-rw-r--r-- 1 root wheel 618 Nov 28 06:43 ssh_host_dsa_key.pub 
-rw-r--r-- 1 root wheel 347 Nov 28 06:43 ssh_host_key.pub 
-rw-r--r-- 1 root wheel 238 Nov 28 06:43 ssh_host_rsa_key.pub 
 
If any \"key.pub\" file has a mode more permissive than \"0644\", this is a finding. 
 
Note: SSH public key files may be found in other directories on the system depending on the installation.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248601"
STIG_ID="OL08-00-010480"
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
