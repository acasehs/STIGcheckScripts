#!/usr/bin/env bash
################################################################################
# STIG Check: V-248896
# Severity: low
# Rule Title: The OL 8 file integrity tool must be configured to verify extended attributes.
# STIG ID: OL08-00-040300
# Rule ID: SV-248896r991589
#
# Description:
#     Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications. 
 
OL 8 installation media come with a file integrity tool, Advanced Intrusion Detection Environment (AIDE).
#
# Check Content:
#     Verify the file integrity tool is configured to verify extended attributes. 
 
If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 
 
Note: AIDE is highly configurable at install time. This requirement assumes the \"aide.conf\" file is under the \"/etc\" directory. 
 
Use the following command to determine if the file is in another location: 
 
$ sudo find / -name aide.conf 
 
Check the \"aide.conf\" file to determine if the \"xattrs\" rule has been added to the rule list being applied to the files and directories selection lists. 
 
An example rule that includes the \"xattrs\" rule follows: 
 
All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux 
/bin All # apply the custom rule to the files in bin 
/sbin All # apply the same custom rule to the files in sbin 
 
If the \"xattrs\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or extended attributes are not being checked by another file integr
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248896"
STIG_ID="OL08-00-040300"
SEVERITY="low"
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
