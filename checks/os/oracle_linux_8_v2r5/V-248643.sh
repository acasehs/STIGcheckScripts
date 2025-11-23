#!/usr/bin/env bash
################################################################################
# STIG Check: V-248643
# Severity: medium
# Rule Title: All OL 8 local interactive user home directories defined in the "/etc/passwd" file must exist.
# STIG ID: OL08-00-010750
# Rule ID: SV-248643r991589
#
# Description:
#     If a local interactive user has a home directory defined that does not exist, the user may be given access to the "/" directory as the current working directory upon logon. This could create a denial of service because the user would not be able to access their logon configuration files, and it may ...
#
# Check Content:
#     Verify that the assigned home directory of all local interactive users on OL 8 exists with the following command:    $ sudo ls -ld $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd)    drwxr-xr-x 2 smithj admin 4096 Jun 5 12:41 smithj    Note: This may miss interactive users that have bee...
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248643"
STIG_ID="OL08-00-010750"
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

Example:
  $0
  $0 --config stig-config.json
  $0 --output-json results.json
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
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi
    # TODO: Load configuration values using jq if available
fi

################################################################################
# CHECK IMPLEMENTATION
################################################################################

# STIG Check Implementation - Manual Review Required
#
# This check requires manual examination of system configuration.
# Please review the STIG requirement in the header and verify:
# - System configuration matches STIG requirements
# - Security controls are properly configured
# - Compliance status is documented

echo "INFO: Manual review required for $VULN_ID"
echo "STIG ID: $STIG_ID"
echo ""
echo "MANUAL REVIEW REQUIRED"
echo "This STIG check requires manual verification of system configuration."
echo "Please consult the STIG documentation for specific compliance requirements."

# Manual review status
STATUS="Not_Reviewed"
EXIT_CODE=2
FINDING_DETAILS="Manual review required - consult STIG documentation for compliance verification"


################################################################################
# OUTPUT RESULTS
################################################################################

# JSON output if requested
if [[ -n "$OUTPUT_JSON" ]]; then
    cat > "$OUTPUT_JSON" << EOF_JSON
{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "rule_title": "All OL 8 local interactive user home directories defined in the "/etc/passwd" file must exist.",
  "status": "$STATUS",
  "finding_details": "$FINDING_DETAILS",
  "timestamp": "$TIMESTAMP",
  "exit_code": $EXIT_CODE
}
EOF_JSON
fi

# Human-readable output
cat << EOF

================================================================================
STIG Check: $VULN_ID - $STIG_ID
Severity: ${SEVERITY^^}
================================================================================
Rule: All OL 8 local interactive user home directories defined in the "/etc/passwd" file must exist.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
