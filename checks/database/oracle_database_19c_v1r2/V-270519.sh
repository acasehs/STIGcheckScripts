#!/usr/bin/env bash
################################################################################
# STIG Check: V-270519
# STIG ID: O19C-00-008300
# Severity: medium
# Rule Title: The role(s)/group(s) used to modify database structure (including but ...
#
# Automated Check: SQL Query Validation
################################################################################

set -euo pipefail

VULN_ID="V-270519"
STIG_ID="O19C-00-008300"
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
QUERY="SELECT grantee, privilege FROM dba_sys_privs WHERE grantee IN ( SELECT username FROM dba_users WHERE username NOT IN ( 'XDB', 'SYSTEM', 'SYS', 'LBACSYS', 'DVSYS', 'DVF', 'SYSMAN_RO', 'SYSMAN_BIPLATFORM', 'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP', 'SYSMAN', 'APEX_040200', 'WMSYS', 'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR', 'SPATIAL_CSW_ADMIN_US', 'GSMCATUSER', 'OLAPSYS', 'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS', 'ORDDATA', 'OJVMSYS', 'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS', 'GSMADMIN_INT"

# Note: This requires proper Oracle credentials
# Execute query and check results
# This is a template - adjust validation logic based on specific check requirements

output_json "Not_Reviewed" "Database check requires DBA credentials. Query: $QUERY"
echo "[$VULN_ID] MANUAL - Requires SQL execution with proper credentials"
echo "Query: $QUERY"
exit 2
