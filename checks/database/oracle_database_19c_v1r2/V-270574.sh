#!/usr/bin/env bash
################################################################################
# STIG Check: V-270574
# STIG ID: O19C-00-016800
# Severity: high
# Rule Title: Oracle Database must take needed steps to protect data at rest and ens...
#
# Automated Check: SQL Query Validation
################################################################################

set -euo pipefail

VULN_ID="V-270574"
STIG_ID="O19C-00-016800"
SEVERITY="high"
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
QUERY="SELECT t.name 'TSName', e.encryptionalg 'Algorithm', d.file_name 'File Name' FROM v$tablespace t, v$encrypted_tablespaces e, dba_data_files d WHERE t.ts# = e.ts# and t.name = d.tablespace_name"

# Note: This requires proper Oracle credentials
# Execute query and check results
# This is a template - adjust validation logic based on specific check requirements

output_json "Not_Reviewed" "Database check requires DBA credentials. Query: $QUERY"
echo "[$VULN_ID] MANUAL - Requires SQL execution with proper credentials"
echo "Query: $QUERY"
exit 2
