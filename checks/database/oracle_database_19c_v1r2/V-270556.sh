#!/usr/bin/env bash
################################################################################
# STIG Check: V-270556
# STIG ID: O19C-00-013300
# Severity: medium
# Rule Title: Use of external executables must be authorized....
#
# Automated Check: SQL Query Validation
################################################################################

set -euo pipefail

VULN_ID="V-270556"
STIG_ID="O19C-00-013300"
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
QUERY="select library_name,owner, '' grantee, '' privilege from dba_libraries where file_spec is not null and owner not in ('SYS', 'ORDSYS') minus ( select library_name,o.name owner, '' grantee, '' privilege from dba_libraries l, sys.user$ o, sys.user$ ge, sys.obj$ obj, sys.objauth$ oa where l.owner=o.name and obj.owner#=o.user# and obj.name=l.library_name and oa.obj#=obj.obj# and ge.user#=oa.grantee# and l.file_spec is not null ) union all select library_name,o.name owner, --obj.obj#,oa.privilege#, ge"

# Note: This requires proper Oracle credentials
# Execute query and check results
# This is a template - adjust validation logic based on specific check requirements

output_json "Not_Reviewed" "Database check requires DBA credentials. Query: $QUERY"
echo "[$VULN_ID] MANUAL - Requires SQL execution with proper credentials"
echo "Query: $QUERY"
exit 2
