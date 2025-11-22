#!/usr/bin/env bash
################################################################################
# STIG Check: V-270546
# Severity: medium
# Rule Title: Oracle Database must provide a mechanism to automatically identify accounts designated as temporary or emergency accounts.
# STIG ID: O19C-00-012000
# Rule ID: SV-270546r1112478
#
# Description:
#     Temporary application accounts could be used in the event of a vendor support visit where a support representative requires a temporary unique account to perform diagnostic testing or conduct some other support-related activity. When these types of accounts are created, there is a risk that the temporary account may remain in place and active after the support representative has left.

To address this in the event temporary application accounts are required, the application must automatically te
#
# Check Content:
#     If the organization has a policy, consistently enforced, forbidding the creation of emergency or temporary accounts, this is not a finding.

If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

If using the database to identify temporary accounts, and temporary accounts exist, there should be a temporary profile. If a profile for temporary accounts cannot be identified, this is a finding.

To check for a temporary profile, run the scripts below:

To obtain a list of profiles:

SELECT PROFILE#, NAME FROM SYS.PROFNAME$;

To obtain a list of users assigned a given profile (TEMPORARY_USERS, in this example):

SELECT USERNAME, PROFILE FROM SYS.DBA_USERS
WHERE PROFILE = '\''TEMPORARY_USERS'\''
ORDER BY USERNAME;
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270546"
STIG_ID="O19C-00-012000"
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
