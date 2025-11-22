#!/usr/bin/env bash
################################################################################
# STIG Check: V-276000
# Severity: medium
# Rule Title: A minimum of three Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device. In addition, each Oracle redo
# STIG ID: O19C-00-020600
# Rule ID: SV-276000r1112495
#
# Description:
#     The Oracle Database Redo Log files store detailed transactional information on changes made to the database using SQL Data Manipulation Language (DML), Data Definition Language (DDL), and Data Control Language (DCL), which is required for undo, backup, restoration, and recovery. 

A minimum of three Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID (mirrored) device. In addition, each Oracle redo log gr
#
# Check Content:
#     From SQL*Plus:

-- Check to see how many Oracle redo log groups there are:
select group#, bytes, members, status, archived from v$log;

-- Check to see how many Oracle redo log members there are:
select * from v$logfile;

This is a finding if there are less than three Oracle redo log groups a RAID storage device, or equivalent storage system, is not being used.

If one or more groups (group#) has only a single member this is a finding.

If one or more groups (group#) have more than a single member but one or more of those members are located on the same physical or logical device this is a finding.

select count(*) from V$LOG;

If the value of the count returned is less than 3, this is a finding.

From SQL*Plus:

select count(*) from V$LOG where members > 1;

If the value of the count returned is less than 3 and a RAID storage device is not being used, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-276000"
STIG_ID="O19C-00-020600"
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
select group#, bytes, members, status, archived from v\$log;
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
    echo "Finding Condition: This is a finding if there are less than three Oracle redo log groups a RAID storage device, or equivalent storage system, is not being used."
    echo ""
    echo "Review the query results above and verify compliance with STIG requirements"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Manual review required" "$query_result"
    exit 2  # Manual review required

}

# Run main check
main "$@"
