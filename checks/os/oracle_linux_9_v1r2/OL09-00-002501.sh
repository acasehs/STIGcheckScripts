#!/usr/bin/env bash
################################################################################
# STIG Check: V-271770
# Severity: medium
# Rule Title: OL 9 must not have unauthorized accounts.
# STIG ID: OL09-00-002501
# Rule ID: SV-271770r1092022
#
# Description:
#     Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.
#
# Check Content:
#     Verify that OL 9 prohibits unauthorized interactive user accounts with the following command:

$ less /etc/passwd  
root:x:0:0:root:/root:/bin/bash
...
games:x:12:100:games:/usr/games:/sbin/nologin
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Interactive user account, generally will have a user identifier (UID) of 1000 or greater, a home directory in a specific partition, and an interactive shell.

Obtain the list of interactive user accounts authorized to be on the system from the system administrator or information system security officer (ISSO) and compare it to the list of local interactive user accounts on the system.

If there are unauthorized local user accounts on the system, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271770"
STIG_ID="OL09-00-002501"
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
