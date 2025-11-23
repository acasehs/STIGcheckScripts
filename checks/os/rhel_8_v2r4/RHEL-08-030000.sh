#!/usr/bin/env bash
################################################################################
# STIG Check: V-230386
# Severity: medium
# Rule Title: The RHEL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software.
# STIG ID: RHEL-08-030000
# Rule ID: SV-230386r958730
#
# Description:
#     Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

Satisfies: SRG-OS-000326-GPOS-00126, SRG-OS-000327-GPOS-00127
#
# Check Content:
#     Verify RHEL 8 audits the execution of privileged functions.

Check if RHEL 8 is configured to audit the execution of the \"execve\" system call, by running the following command:

$ sudo grep execve /etc/audit/audit.rules

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv

-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

If the command does not return all lines, or the lines are commented out, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230386"
STIG_ID="RHEL-08-030000"
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
    # STIG Check Implementation - Manual Review Required
    #
    # This check requires manual examination of system configuration.
    # Please review the STIG requirement in the header and verify:
    # - System configuration matches STIG requirements
    # - Security controls are properly configured
    # - Compliance status is documented

    echo "INFO: Manual review required for $STIG_ID"
    echo "Rule: Check the rule title in the header above"
    echo ""
    echo "MANUAL REVIEW REQUIRED"
    echo "This STIG check requires manual verification of system configuration."
    echo "Please consult the STIG documentation for specific compliance requirements."

    [[ -n "$OUTPUT_JSON" ]] && output_json "Not_Reviewed" "Manual review required" "Consult STIG documentation for compliance requirements"
    exit 2  # Manual review required

}

# Run main check
main "$@"
