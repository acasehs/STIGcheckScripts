#!/usr/bin/env bash
################################################################################
# STIG Check: V-2252
# Severity: medium
# Rule Title: Log file access must be restricted to System Administrators, Web Administrators or Auditors.
# STIG ID: WG250 A22
# Rule ID: SV-33033r1
#
# Description:
#     A major tool in exploring the web site use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. To ensure the integrity of the log files and protect the SA and the web manager from a conflict of interest related to the maintenance of these files, only the members of the Auditors group will be granted permissions to move, copy, and delete these files in the 
#
# Check Content:
#     Enter the following command to determine the directory the log files are located in:_x000D_
_x000D_
grep \"ErrorLog\" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
grep \"CustomLog\" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
Verify the permission of the ErrorLog & CustomLog files by entering the following command:_x000D_
_x000D_
ls -al /usr/local/apache2/logs/*.log _x000D_
_x000D_
Unix file permissions should be 640 or less for all web log files if not, this is a finding.  _x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2252"
STIG_ID="WG250 A22"
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
    TARGET="/usr/local/apache2/conf/httpd.conf_x000D_"
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
