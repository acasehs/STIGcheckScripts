#!/usr/bin/env bash
################################################################################
# STIG Check: V-270557
# Severity: medium
# Rule Title: Access to external executables must be disabled or restricted.
# STIG ID: O19C-00-013400
# Rule ID: SV-270557r1065281
#
# Description:
#     The Oracle external procedure capability provides use of the Oracle process account outside the operation of the database management system (DBMS) process. It can be used to submit and execute applications stored externally from the database under operating system controls. The external procedure process is the subject of frequent and successful attacks as it allows unauthenticated use of the Oracle process account on the operating system. As of Oracle version 11.1, the external procedure agent 
#
# Check Content:
#     Review the system documentation to determine if the use of the external procedure agent is authorized.

Review the ORACLE_HOME/bin directory or search the ORACLE_BASE path for the executable extproc (Unix) or extproc.exe (Windows).

If external procedure agent is not authorized for use in the system documentation and the executable file does not exist or is restricted, this is not a finding.

If external procedure agent is not authorized for use in the system documentation and the executable file exists and is not restricted, this is a finding.

If use of the external procedure agent is authorized, ensure extproc is restricted to execution of authorized applications.

External jobs are run using the account \"nobody\" by default.

Review the contents of the file ORACLE_HOME/rdbms/admin/externaljob.ora for the lines run_user= and run_group=.

If the user assigned to these parameters is not \"nobody\", this is a finding.

The external procedure agent (extproc executable) is available dir
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270557"
STIG_ID="O19C-00-013400"
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
    TARGET="/usr/fso:/usr/local/packages")"
    REQUIRED="127"

    if [[ ! -e "$TARGET" ]]; then
        echo "ERROR: File not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$TARGET"
        exit 3
    fi

    actual=$(stat -c "%a" "$TARGET" 2>/dev/null)
    if [[ $((8#$actual)) -le $((8#$REQUIRED)) ]]; then
        echo "PASS: Permissions $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$actual"
        exit 0
    else
        echo "FAIL: Permissions $actual (required: $REQUIRED or less)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Too permissive" "$actual"
        exit 1
    fi

}

# Run main check
main "$@"
