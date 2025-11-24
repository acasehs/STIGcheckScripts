#!/usr/bin/env bash
################################################################################
# STIG Check: V-270549
# STIG ID: O19C-00-012300
# Severity: medium
# Rule Title: Oracle Database must verify account lockouts persist until reset by an...
#
# Automated Check: SQL Query Validation
################################################################################

set -euo pipefail

VULN_ID="V-270549"
STIG_ID="O19C-00-012300"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

while [[ $# -gt 0 ]]; do
    case $1 in --output-json) OUTPUT_JSON="$2"; shift 2;; *) shift;; esac
done

output_json() {
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$1","finding_details":"$2","timestamp":"$TIMESTAMP"}
EOF
}

# Check Oracle environment
if [[ -z "$ORACLE_HOME" || -z "$ORACLE_SID" ]]; then
    output_json "Not_Applicable" "Oracle Database not configured (ORACLE_HOME or ORACLE_SID not set)"
    echo "[$VULN_ID] N/A - Oracle not configured"
    exit 2
fi

# Check for sqlplus
if ! command -v sqlplus &>/dev/null; then
    output_json "Not_Applicable" "SQL*Plus not available"
    echo "[$VULN_ID] N/A - SQL*Plus not found"
    exit 2
fi

# SQL Query to execute
QUERY="SELECT profile FROM dba_users WHERE username = '<username>' This will return the profile name assigned to that user. The user profile, ORA_STIG_PROFILE, has been provided to satisfy the STIG requirements pertaining to the profile parameters. Oracle recommends that this profile be customized with any site-specific requirements and assigned to all users where applicable. Note: It remains necessary to create a customized replacement for the password validation function, ORA12C_STIG_VERIFY_FUNCTION,"

# Note: This requires proper Oracle credentials
# Execute query and check results
# This is a template - adjust validation logic based on specific check requirements

output_json "Not_Reviewed" "Database check requires DBA credentials. Query: $QUERY"
echo "[$VULN_ID] MANUAL - Requires SQL execution with proper credentials"
echo "Query: $QUERY"
exit 2
