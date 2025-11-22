#!/usr/bin/env bash
################################################################################
# STIG Check: V-270561
# Severity: medium
# Rule Title: Oracle Database must enforce the DOD standards for password complexity.
# STIG ID: O19C-00-013900
# Rule ID: SV-270561r1112485
#
# Description:
#     OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native database management system (DBMS) authentication may be used only when circumstances make it unavoidable; and must be documented and authorizing official (AO)-approved.

The DOD standard for authentication is DOD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, the DOD 
#
# Check Content:
#     If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle'\''s control, determine the password verification function that is in use:

SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME = '\''PASSWORD_VERIFY_FUNCTION'\''
ORDER BY PROFILE;

Note: Profiles can inherit settings from another profile so some password functions could be set to DEFAULT. If so, review the DEFAULT profile function name. 

If the function name is null for any profile, this is a finding.

Review the password verification functions specified for the PASSWORD_VERIFY_FUNCTION settings for each profile. Determine whether the following rules are enforced by the code in those functions. 
a. Minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numeric
- Special characters (e.g., ~ ! @ #
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270561"
STIG_ID="O19C-00-013900"
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
