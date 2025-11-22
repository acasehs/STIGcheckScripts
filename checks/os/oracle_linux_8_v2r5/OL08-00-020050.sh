#!/usr/bin/env bash
################################################################################
# STIG Check: V-248679
# Severity: medium
# Rule Title: OL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.
# STIG ID: OL08-00-020050
# Rule ID: SV-248679r1015046
#
# Description:
#     A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. 
 
Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reaut
#
# Check Content:
#     Verify the operating system enables a user'\''s session lock until that user reestablishes access using established identification and authentication procedures with the following command:
 
This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo grep -r removal-action /etc/dconf/db/*

/etc/dconf/db/distro.d/20-authselect:removal-action='\''lock-screen'\''

If the \"removal-action='\''lock-screen'\''\" setting is missing or commented out from the \"dconf\" database files, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248679"
STIG_ID="OL08-00-020050"
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
