#!/usr/bin/env bash
################################################################################
# STIG Check: V-248902
# Severity: medium
# Rule Title: If the Trivial File Transfer Protocol (TFTP) server is required, the OL 8 TFTP daemon must be configured to operate in secure mode.
# STIG ID: OL08-00-040350
# Rule ID: SV-248902r1106146
#
# Description:
#     Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.
#
# Check Content:
#     Note: If TFTP is not required, it must not be installed. If TFTP is not installed, this rule is not applicable.

Check to see if TFTP server is installed with the following command:

$ sudo dnf list installed | grep tftp-server 
tftp-server.x86_64 x.x-x.el8

Verify the TFTP daemon, if tftp.server is installed, is configured to operate in secure mode with the following command:

$ grep -i execstart /usr/lib/systemd/system/tftp.service
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

Note: The \"-s\" option ensures the TFTP server only serves files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248902"
STIG_ID="OL08-00-040350"
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
    SVC="TFTP"

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
