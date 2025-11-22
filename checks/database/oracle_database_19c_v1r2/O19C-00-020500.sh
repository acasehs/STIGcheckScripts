#!/usr/bin/env bash
################################################################################
# STIG Check: V-275999
# Severity: medium
# Rule Title: A minimum of three Oracle Control Files must be created and each stored on a separate physical and logical device.
# STIG ID: O19C-00-020500
# Rule ID: SV-275999r1115962
#
# Description:
#     Oracle control files store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files and verify the validity of system data and log files at system startup. Loss of access to the control files can affect database availability, integrity, and recovery.

Oracle Pluggable Databases (PDBs) do not contain their own control files; instead, all PDBs within a Container Database (CDB) share control files managed by the CDB.
#
# Check Content:
#     Use the SQL statement below to obtain information on each currently existing Control File:

SELECT name
FROM sys.v$controlfile
ORDER BY 1;

Oracle Best Practice:
Oracle recommends a minimum of three Oracle Control Files and each stored on a separate physical and logical device (RAID 1 + 0).  

DOD guidance recommends:
Each control file must be located on a separate physical and logical (virtual) storage device.

Consult with the storage administrator, system administrator, or database administrator to determine whether the mount points or partitions referenced in the file paths indicate separate physical disks or directories on RAID devices.

Note: Distinct does not equal dedicated. May share directory space with other Oracle database instances if present.

If the minimum of three control files is not met, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-275999"
STIG_ID="O19C-00-020500"
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
SELECT name FROM sys.v\$controlfile ORDER BY 1;
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
    echo "Finding Condition: If the minimum of three control files is not met, this is a finding."
    echo ""
    echo "Review the query results above and verify compliance with STIG requirements"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Manual review required" "$query_result"
    exit 2  # Manual review required

}

# Run main check
main "$@"
