#!/usr/bin/env bash
################################################################################
# STIG Check: Unknown
# Severity: medium
# Rule Title: Oracle WebLogic must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.
# STIG ID: WBLC-05-000177
# Rule ID: SV-235976r628706_rule
#
# Description:
#     Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules, and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified hardware-based encryption modules. 

Application servers must provide FIPS-compliant encryption modules when authe
#
# Check Content:
#     1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select '\''WebLogic Domain'\'' -> '\''Logs'\'' -> '\''View Log Messages'\''
3. Within the '\''Search'\'' panel, expand '\''Selected Targets'\''
4. Click '\''Target Log Files'\'' icon for '\''AdminServer'\'' target
5. From the list of log files, select '\''AdminServer.log'\'' and click '\''View Log File'\'' button
6. Within the search criteria, enter the value '\''FIPS'\'' for the '\''Message contains'\'' field, and select the appropriate '\''Start Date'\'' and '\''End Date'\'' range. Click '\''Search'\''
7. Check for the following log entry: \"Changing the default Random Number Generator in RSA CryptoJ ... to FIPS186PRNG\" or \"Changing the default Random Number Generator in RSA CryptoJ from ECDRBG128 to HMACDRBG.\"

If either of these log entries are found, this is not a finding.

If a log entry cannot be found, navigate to the DOMAIN_HOME directory: 
8. View the contents of the appropriate WebLogic s
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="Unknown"
STIG_ID="WBLC-05-000177"
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
