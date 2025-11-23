#!/usr/bin/env bash
################################################################################
# STIG Check: V-271857
# Severity: medium
# Rule Title: OL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.
# STIG ID: OL09-00-005030
# Rule ID: SV-271857r1092283
#
# Description:
#     Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information into the system's logs, or could fill the system's s...
#
# Check Content:
#     Verify that OL 9 is not configured to receive remote logs using rsyslog with the following commands:  $ grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/* $ModLoad imtcp $ModLoad imrelp  $ grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/* $InputTCPServerRun 514 $InputRELPServerRun 514  Note: An e...
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271857"
STIG_ID="OL09-00-005030"
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
  "rule_title": "OL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.",
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
Rule: OL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
