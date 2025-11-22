#!/usr/bin/env bash
################################################################################
# STIG Check: V-271764
# Severity: medium
# Rule Title: OL 9 Trivial File Transfer Protocol (TFTP) daemon must be configured to operate in secure mode if the TFTP server is required. 
# STIG ID: OL09-00-002426
# Rule ID: SV-271764r1092004
#
# Description:
#     Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files. Using the \"-s\" option causes the TFTP service to only serve files from the given directory.
#
# Check Content:
#     Verify that OL 9 TFTP daemon is configured to operate in secure mode.

Check if a TFTP server is installed with the following command:

$ sudo dnf list --installed tftp-server
Installed Packages
tftp-server.x86_64                                       5.2-38.el9                                       @ol9_appstream

Note: If a TFTP server is not installed, this requirement is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

$ systemctl cat tftp | grep ExecStart
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

If the \"ExecStart\" line does not have a \"-s\" option, and a subdirectory is not assigned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271764"
STIG_ID="OL09-00-002426"
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
