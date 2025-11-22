#!/usr/bin/env bash
################################################################################
# STIG Check: V-270563
# Severity: medium
# Rule Title: Oracle Database must enforce password maximum lifetime restrictions.
# STIG ID: O19C-00-014700
# Rule ID: SV-270563r1064967
#
# Description:
#     Password maximum lifetime is the maximum period of time, (typically in days) a user'\''s password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, ther
#
# Check Content:
#     If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Review database management system (DBMS) settings to determine if passwords must be changed periodically. Run the following script:

SELECT p1.profile,
CASE DECODE(p1.limit, '\''DEFAULT'\'', p3.limit, p1.limit) WHEN '\''UNLIMITED'\'' THEN '\''UNLIMITED'\'' ELSE
CASE DECODE(p2.limit, '\''DEFAULT'\'', p4.limit, p2.limit) WHEN '\''UNLIMITED'\'' THEN '\''UNLIMITED'\'' ELSE
TO_CHAR(DECODE(p1.limit, '\''DEFAULT'\'', p3.limit, p1.limit) + DECODE(p2.limit, '\''DEFAULT'\'', p4.limit, p2.limit))
END
END effective_life_time
FROM dba_profiles p1, dba_profiles p2, dba_profiles p3, dba_profiles p4
WHERE p1.profile=p2.profile
AND p3.profile='\''DEFAULT'\''
AND p4.profile='\''DEFAULT'\''
AND p1.resource_name='\''PASSWORD_LIFE_TIME'\''
AND p2.resource_name='\''PASSWORD_GRACE_TIME'\''
AND p3.resource_name='\''PASSWORD_LIFE_TIME'\'' -- from DEFAULT profile
AN
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270563"
STIG_ID="O19C-00-014700"
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
SELECT p1.profile, CASE DECODE(p1.limit, \\'DEFAULT\\', p3.limit, p1.limit) WHEN \\'UNLIMITED\\' THEN \\'UNLIMITED\\' ELSE CASE DECODE(p2.limit, \\'DEFAULT\\', p4.limit, p2.limit) WHEN \\'UNLIMITED\\' THEN \\'UNLIMITED\\' ELSE TO_CHAR(DECODE(p1.limit, \\'DEFAULT\\', p3.limit, p1.limit) + DECODE(p2.limit, \\'DEFAULT\\', p4.limit, p2.limit)) END END effective_life_time FROM dba_profiles p1, dba_profiles p2, dba_profiles p3, dba_profiles p4 WHERE p1.profile=p2.profile AND p3.profile=\\'DEFAULT\\' AND p4.profile=\\'DEFAULT\\' AND p1.resource_name=\\'PASSWORD_LIFE_TIME\\' AND p2.resource_name=\\'PASSWORD_GRACE_TIME\\' AND p3.resource_name=\\'PASSWORD_LIFE_TIME\\' -- from DEFAULT profile AND p4.resource_name=\\'PASSWORD_GRACE_TIME\\' -- from DEFAULT profile order by 1;
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
    echo "Finding Condition: If the EFFECTIVE_LIFE_TIME is greater than 60 for any profile applied to user accounts, and the need for this has not been documented and approved, this is a finding."
    echo ""
    echo "Review the query results above and verify compliance with STIG requirements"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Manual review required" "$query_result"
    exit 2  # Manual review required

}

# Run main check
main "$@"
