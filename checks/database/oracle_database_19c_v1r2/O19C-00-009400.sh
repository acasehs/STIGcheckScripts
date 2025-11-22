#!/usr/bin/env bash
################################################################################
# STIG Check: V-270526
# Severity: medium
# Rule Title: The Oracle password file ownership and permissions should be limited and the REMOTE_LOGIN_PASSWORDFILE parameter must be set to EXCLUSIVE or NONE.
# STIG ID: O19C-00-009400
# Rule ID: SV-270526r1115966
#
# Description:
#     It is critically important to the security of the system to protect the password file and the environment variables that identify the location of the password file. Any user with access to these could potentially compromise the security of the connection. 

The REMOTE_LOGIN_PASSWORDFILE setting of \"NONE\" disallows remote administration of the database. The REMOTE_LOGIN_PASSWORDFILE setting of \"EXCLUSIVE\" allows for auditing of individual database administrator (DBA) logons to the SYS account
#
# Check Content:
#     To verify the current status of the REMOTE_LOGIN_PASSWORDFILE parameter: 

If using a non-CDB database:

From SQL*Plus:

select value from v$parameter where upper(name) = '\''REMOTE_LOGIN_PASSWORDFILE'\'';

If the value returned does not equal '\''EXCLUSIVE'\'' or '\''NONE'\'', this is a finding.

If using a CDB database:

From SQL*Plus:

To verify the current status of the remote_login_passwordfile parameter use the SQL statement:

column name format a25
column parameter_value format a25

SELECT name, inst_id, con_id, value AS PARAMETER_VALUE 
FROM sys.gv_$parameter 
WHERE name = '\''REMOTE_LOGIN_PASSWORDFILE'\'' 
ORDER BY 1;

In any instance or container, if the PARAMETER_VALUE is set to SHARED, or to a value other than EXCLUSIVE or NONE, that is a finding.

Check the security permissions on password file within the OS.

On Unix Systems:

ls -ld $ORACLE_HOME/dbs/orapw${ORACLE_SID}

Substitute ${ORACLE_SID} with the name of the ORACLE_SID for the database.

If permissions are granted 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270526"
STIG_ID="O19C-00-009400"
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
