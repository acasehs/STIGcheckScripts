#!/usr/bin/env bash
################################################################################
# STIG Check: V-270556
# Severity: medium
# Rule Title: Use of external executables must be authorized.
# STIG ID: O19C-00-013300
# Rule ID: SV-270556r1064946
#
# Description:
#     Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to
#
# Check Content:
#     Review the database for definitions of application executable objects stored external to the database.

Determine if there are methods to disable use or access, or to remove definitions for external executable objects.

Verify any application executable objects listed are authorized by the information system security officer (ISSO).

To check for external procedures, execute the following query, which will provide the libraries containing external procedures, the owners of those libraries, users that have been granted access to those libraries, and the privileges they have been granted. If there are owners other than the owners Oracle provides, then there might be executable objects stored either in the database or external to the database that are called by objects in the database. 

(connect as sysdba)
set linesize 130
column library_name format a25
column name format a15
column owner format a15
column grantee format a15
column privilege format a15
select library_name,owner, '\'''\''
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270556"
STIG_ID="O19C-00-013300"
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
    # Oracle Database SQL Check

    # Check for Oracle client
    if ! command -v sqlplus &>/dev/null; then
        echo "ERROR: Oracle client (sqlplus) not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "sqlplus not installed" ""
        exit 3
    fi

    # Check for required environment variables
    if [[ -z "$ORACLE_USER" ]]; then
        echo "ERROR: ORACLE_USER environment variable not set"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "ORACLE_USER not configured" ""
        exit 3
    fi

    if [[ -z "$ORACLE_SID" ]] && [[ -z "$ORACLE_CONNECT" ]]; then
        echo "ERROR: ORACLE_SID or ORACLE_CONNECT must be set"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Oracle connection not configured" ""
        exit 3
    fi

    # Build connection string
    if [[ -n "$ORACLE_CONNECT" ]]; then
        CONNECT_STRING="$ORACLE_USER@$ORACLE_CONNECT"
    else
        CONNECT_STRING="$ORACLE_USER@$ORACLE_SID"
    fi

    echo "INFO: Executing Oracle Database check"
    echo "Connection: $CONNECT_STRING"
    echo ""

    # Execute SQL query
    query_result=$(sqlplus -S "$CONNECT_STRING" <<'EOSQL'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING ON ECHO OFF
SET LINESIZE 200
WHENEVER SQLERROR EXIT SQL.SQLCODE
select library_name,owner, \\'\\' grantee, \\'\\' privilege from dba_libraries where file_spec is not null and owner not in (\\'SYS\\', \\'ORDSYS\\') minus ( select library_name,o.name owner, \\'\\' grantee, \\'\\' privilege from dba_libraries l, sys.user\$ o, sys.user\$ ge, sys.obj\$ obj, sys.objauth\$ oa where l.owner=o.name and obj.owner#=o.user# and obj.name=l.library_name and oa.obj#=obj.obj# and ge.user#=oa.grantee# and l.file_spec is not null ) union all select library_name,o.name owner, --obj.obj#,oa.privilege#, ge.name grantee, tpm.name privilege from dba_libraries l, sys.user\$ o, sys.user\$ ge, sys.obj\$ obj, sys.objauth\$ oa, sys.table_privilege_map tpm where l.owner=o.name and obj.owner#=o.user# and obj.name=l.library_name and oa.obj#=obj.obj# and ge.user#=oa.grantee# and tpm.privilege=oa.privilege# and l.file_spec is not null /
EXIT;
EOSQL
)

    query_exit=$?

    if [[ $query_exit -ne 0 ]]; then
        echo "ERROR: SQL query failed with exit code $query_exit"
        echo "$query_result"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Query execution failed" "$query_result"
        exit 3
    fi

    echo "Query Results:"
    echo "$query_result"
    echo ""

    # Manual review required to determine compliance
    echo "MANUAL REVIEW REQUIRED: Analyze query results for STIG compliance"
    echo "Finding Condition: If any owners are returned other than those Oracle provides, ensure those owners are authorized to access those libraries. If there are users that have been granted access to libraries that are not authorized, this is a finding."
    echo ""
    echo "Review the query results above and verify compliance with STIG requirements"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Manual review required" "$query_result"
    exit 2  # Manual review required

}

# Run main check
main "$@"
