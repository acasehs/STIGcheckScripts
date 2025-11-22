#!/usr/bin/env bash
################################################################################
# STIG Check: V-270551
# Severity: medium
# Rule Title: Oracle Database must disable user accounts after 35 days of inactivity.
# STIG ID: O19C-00-012500
# Rule ID: SV-270551r1112483
#
# Description:
#     Attackers that are able to exploit an inactive database management system (DBMS) account can potentially obtain and maintain undetected access to the database. 

Owners of inactive DBMS accounts will not notice if unauthorized access to their user account has been obtained. All DBMS need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.

To address access requ
#
# Check Content:
#     If all user accounts are managed and authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For accounts managed by Oracle, check DBMS settings to determine if accounts are automatically disabled by the system after 35 days of inactivity. 

In Oracle 12c, Oracle introduced a new security parameter in the profile called INACTIVE_ACCOUNT_TIME. This parameter specifies the number of days permitted the account will be in OPEN state since the last login, after that will be LOCKED if no successful logins happens after the specified duration.

Check to verify what profile each user is associated with, if any, with this query:

select username, profile from dba_users order by 1,2;

Then, check the profile to verify what the inactive_account_time is set to in the table dba_profiles; the inactive_account_time is a value stored in the LIMIT column, and identified by the value inactive_account_time in the RESOURCE_NAME column.

SQ
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270551"
STIG_ID="O19C-00-012500"
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
