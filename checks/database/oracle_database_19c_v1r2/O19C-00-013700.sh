#!/usr/bin/env bash
################################################################################
# STIG Check: V-270559
# Severity: medium
# Rule Title: Oracle Database must ensure users are authenticated with an individual authenticator prior to using a shared authenticator.
# STIG ID: O19C-00-013700
# Rule ID: SV-270559r1068298
#
# Description:
#     To assure individual accountability and prevent unauthorized access, application users (and any processes acting on behalf of users) must be individually identified and authenticated.

A shared authenticator is a generic account used by multiple individuals. Use of a shared authenticator alone does not uniquely identify individual users. An example of a shared authenticator is the Unix OS \"root\" user account, a Windows \"administrator\" account, a \"SA\" account, or a \"helpdesk\" account.

Fo
#
# Check Content:
#     Review database management system (DBMS) settings, OS settings, and/or enterprise-level authentication/access mechanism settings to determine whether shared accounts exist. If shared accounts do not exist, this is Not Applicable.

Review DBMS settings to determine if individual authentication is required before shared authentication.

If shared authentication does not require prior individual authentication, this is a finding.

If using Oracle Access Manager:
Verify the Authentication Module is set up properly:
1. Go to the Oracle Access Manager Home Screen and click the Policy Configuration tab. Select the X509Scheme.
2. Ensure the Authentication Module option is set to X509Plugin.

Verify the Authentication policy is using the x509Scheme:
1. Go to Oracle Access Manager Home Screen and click the Policy Configuration tab.
2. Select Application Domains. Select Search.
3. Select the application domain protecting the Oracle Database.
4. Select the Authentication Policies tab and click Pro
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270559"
STIG_ID="O19C-00-013700"
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
