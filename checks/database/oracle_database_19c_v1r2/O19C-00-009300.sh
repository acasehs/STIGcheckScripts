#!/usr/bin/env bash
################################################################################
# STIG Check: V-270525
# Severity: medium
# Rule Title: The Oracle SQL92_SECURITY parameter must be set to TRUE.
# STIG ID: O19C-00-009300
# Rule ID: SV-270525r1112473
#
# Description:
#     The configuration option SQL92_SECURITY specifies whether table-level SELECT privileges are required to execute an update or delete those references table column values. If this option is disabled (set to FALSE), the UPDATE privilege can be used to determine values that should require SELECT privileges.

The SQL92_SECURITY setting of TRUE prevents the exploitation of user credentials with only DELETE or UPDATE privileges on a table from being able to derive column values in that table by perform
#
# Check Content:
#     To verify the current status of the SQL92_SECURITY parameter use the SQL statement: 

If using a non-CDB database: 
From SQL*Plus:

select value from v$parameter where name = '\''sql92_security'\'';

If using a CDB database:
From SQL*Plus:

column name format a20
column parameter_value format a20

SELECT name, inst_id, con_id, value AS PARAMETER_VALUE 
FROM sys.gv_$parameter 
WHERE name = '\''sql92_security'\'' 
ORDER BY 1;

Check Result:

The CDB database and all PDBs must be checked.

If the value returned is set to FALSE, this is a finding.

If the parameter is set to TRUE or does not exist, this is not a finding.

In any instance or container, if the PARAMETER_VALUE is not TRUE, that is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270525"
STIG_ID="O19C-00-009300"
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
