#!/usr/bin/env bash
################################################################################
# STIG Check: V-270504
# Severity: medium
# Rule Title: Oracle Database must generate audit records for the DOD-selected list of auditable events, when successfully accessed, added, modified, or deleted, to the extent such information is available.
# STIG ID: O19C-00-002000
# Rule ID: SV-270504r1068292
#
# Description:
#     Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited, as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source 
#
# Check Content:
#     Check Oracle Database settings to determine if auditing is being performed on the DOD-required list of auditable events supplied in the discussion.

If Standard Auditing is used:
To verify Oracle is configured to capture audit data, enter the following SQL*Plus command:

SHOW PARAMETER AUDIT_TRAIL
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = '\''audit_trail'\'';
If Oracle returns the value \"NONE\", this is a finding.

To confirm that Oracle audit is capturing information on the required events, review the contents of the SYS.AUD$ table or the audit file, whichever is in use. If auditable events are not listed, this is a finding.

If Unified Auditing is used:
To verify Oracle is configured to capture audit data, enter the following SQL*Plus command:

SELECT * FROM V$OPTION WHERE PARAMETER = '\''Unified Auditing'\'';

If Oracle returns a value something other than \"TRUE\", this is a finding.

Unified Audit supports named audit policies, which are defined using
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270504"
STIG_ID="O19C-00-002000"
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
    if ! command -v sqlplus &>/dev/null; then
        echo "ERROR: Oracle client not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "sqlplus not installed" ""
        exit 3
    fi

    if [[ -z "$ORACLE_USER" ]] || [[ -z "$ORACLE_SID" ]]; then
        echo "ERROR: Oracle credentials not configured"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Credentials missing" ""
        exit 3
    fi

    # Execute SQL query (customize based on specific check)
    output=$(sqlplus -S "$ORACLE_USER"@"$ORACLE_SID" <<EOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF
-- Add specific query here
EXIT;
EOF
)

    if [[ -n "$output" ]]; then
        echo "PASS: Query executed successfully"
        echo "$output"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Query passed" "$output"
        exit 0
    else
        echo "FAIL: No results or query failed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Query failed" ""
        exit 1
    fi

}

# Run main check
main "$@"
