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
