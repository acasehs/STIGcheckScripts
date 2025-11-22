#!/usr/bin/env bash
################################################################################
# STIG Check: V-270534
# Severity: medium
# Rule Title: The directories assigned to the LOG_ARCHIVE_DEST* parameters must be protected from unauthorized access.
# STIG ID: O19C-00-010400
# Rule ID: SV-270534r1065274
#
# Description:
#     The LOG_ARCHIVE_DEST parameter is used to specify the directory to which Oracle archive logs are written. Where the database management system (DBMS) availability and recovery to a specific point in time is critical, the protection of archive log files is critical. Archive log files may also contain unencrypted sensitive data. If written to an inadequately protected or invalidated directory, the archive log files may be accessed by unauthorized persons or processes.
#
# Check Content:
#     From SQL*Plus:

select log_mode from v$database;
select value from v$parameter where name = '\''log_archive_dest'\'';
select value from v$parameter where name = '\''log_archive_duplex_dest'\'';
select name, value from v$parameter where name LIKE '\''log_archive_dest_%'\'';
select value from v$parameter where name = '\''db_recovery_file_dest'\'';

If the value returned for LOG_MODE is NOARCHIVELOG, this check is not a finding.

If a value is not returned for LOG_ARCHIVE_DEST and no values are returned for any of the LOG_ARCHIVE_DEST_[1-10] parameters, and no value is returned for DB_RECOVERY_FILE_DEST, this is a finding.

Note: LOG_ARCHIVE_DEST and LOG_ARCHIVE_DUPLEX_DEST are incompatible with the LOG_ARCHIVE_DEST_n parameters, and must be defined as the null string ('\'' '\'') when any LOG_ARCHIVE_DEST_n parameter has a value other than a null string.

On Unix Systems:

ls -ld [pathname]

Substitute [pathname] with the directory paths listed from the above SQL statements for log_archiv
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270534"
STIG_ID="O19C-00-010400"
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
