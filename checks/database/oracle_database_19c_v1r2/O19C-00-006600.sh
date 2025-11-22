#!/usr/bin/env bash
################################################################################
# STIG Check: V-270510
# Severity: medium
# Rule Title: The audit information produced by the Oracle Database must be protected from unauthorized access, modification, or deletion.
# STIG ID: O19C-00-006600
# Rule ID: SV-270510r1068294
#
# Description:
#     If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, et
#
# Check Content:
#     Review locations of audit logs, both internal to the database and database audit logs located at the operating system level. Verify there are appropriate controls and permissions to protect the audit information from unauthorized access.

If appropriate controls and permissions do not exist, this is a finding.

- - - - -
From SQL*Plus or SQL Developer:

select value from v$parameter where name = '\''audit_trail'\'';
select value from v$parameter where name = '\''audit_file_dest'\'';

If audit_trail is set to OS, XML or XML EXTENDED, this means logs are stored at the operating system level.

If audit_trail is set to OS, but the audit records are routed directly to a separate log server without writing to the local file system, this is not a finding.

If audit_trail is set to DB or \"DB, EXTENDED\" this means logs are stored in the database.

If any logs are written to the database, DBA_TAB_PRIVS describes all object grants in the database. 

If standard auditing is in use, follow the be
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270510"
STIG_ID="O19C-00-006600"
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
select value from v\$parameter where name = \\'audit_trail\\'; select value from v\$parameter where name = \\'audit_file_dest\\';
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
    echo "Finding Condition: If appropriate controls and permissions do not exist, this is a finding."
    echo ""
    echo "Review the query results above and verify compliance with STIG requirements"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Manual review required" "$query_result"
    exit 2  # Manual review required

}

# Run main check
main "$@"
