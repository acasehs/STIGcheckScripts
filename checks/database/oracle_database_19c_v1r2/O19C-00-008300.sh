#!/usr/bin/env bash
################################################################################
# STIG Check: V-270519
# Severity: medium
# Rule Title: The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to sof
# STIG ID: O19C-00-008300
# Rule ID: SV-270519r1112463
#
# Description:
#     If the database management system (DBMS) were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the datab
#
# Check Content:
#     Review accounts for direct assignment of administrative privileges. Connected as SYSDBA, run the query:

SELECT grantee, privilege
FROM dba_sys_privs
WHERE grantee IN 
(
SELECT username
FROM dba_users
WHERE username NOT IN 
(
'\''XDB'\'', '\''SYSTEM'\'', '\''SYS'\'', '\''LBACSYS'\'',
'\''DVSYS'\'', '\''DVF'\'', '\''SYSMAN_RO'\'',
'\''SYSMAN_BIPLATFORM'\'', '\''SYSMAN_MDS'\'',
'\''SYSMAN_OPSS'\'', '\''SYSMAN_STB'\'', '\''DBSNMP'\'',
'\''SYSMAN'\'', '\''APEX_040200'\'', '\''WMSYS'\'',
'\''SYSDG'\'', '\''SYSBACKUP'\'', '\''SPATIAL_WFS_ADMIN_USR'\'',
'\''SPATIAL_CSW_ADMIN_US'\'', '\''GSMCATUSER'\'',
'\''OLAPSYS'\'', '\''SI_INFORMTN_SCHEMA'\'',
'\''OUTLN'\'', '\''ORDSYS'\'', '\''ORDDATA'\'', '\''OJVMSYS'\'',
'\''ORACLE_OCM'\'', '\''MDSYS'\'', '\''ORDPLUGINS'\'',
'\''GSMADMIN_INTERNAL'\'', '\''MDDATA'\'', '\''FLOWS_FILES'\'',
'\''DIP'\'', '\''CTXSYS'\'', '\''AUDSYS'\'',
'\''APPQOSSYS'\'', '\''APEX_PUBLIC_USER'\'', '\''ANONYMOUS'\'',
'\''SPATIAL_CSW_ADMIN_USR'\'', '\''SYSKM'\'',
'\''SYSMAN_TY
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270519"
STIG_ID="O19C-00-008300"
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
