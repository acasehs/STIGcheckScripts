#!/usr/bin/env bash
################################################################################
# STIG Check: V-13689
# Severity: medium
# Rule Title: Access to the web server log files must be restricted to administrators, web administrators, and auditors.
# STIG ID: WG255 A22
# Rule ID: SV-36643r1
#
# Description:
#     A major tool in exploring the web site use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and the web administrator with valuable information. Because of the information that is captured in the logs, it is critical that only authorized individuals have access to the logs.
#
# Check Content:
#     Look for the presence of log files at:_x000D_
_x000D_
/usr/local/apache/logs/access_log _x000D_
_x000D_
To ensure the correct location of the log files, examine the \"ServerRoot\" directive in the htttpd.conf file and then navigate to that directory where you will find a subdirectory for the logs. _x000D_
_x000D_
Determine permissions for log files, from the command line: cd to the directory where the log files are located and enter the command: _x000D_
_x000D_
ls â€“al *log and note the owner and group permissions on these files. Only the Auditors, Web Managers, Administrators, and the account that runs the web server should have permissions to the files._x000D_
_x000D_
If any users other than those authorized have read access to the log files, this is a finding._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-13689"
STIG_ID="WG255 A22"
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
    TARGET="/usr/local/apache/logs/access_log"
    REQUIRED="000"

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
