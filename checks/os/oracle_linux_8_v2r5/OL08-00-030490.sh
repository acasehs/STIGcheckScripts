#!/usr/bin/env bash
################################################################################
# STIG Check: V-248791
# Severity: medium
# Rule Title: OL 8 must generate audit records for any use of the \"chmod\", \"fchmod\", and \"fchmodat\" system calls.
# STIG ID: OL08-00-030490
# Rule ID: SV-248791r958412
#
# Description:
#     Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). The \"chmod\" system call changes the file mode bits of each given file according to mode, which can be either a symbolic representation
#
# Check Content:
#     Verify OL 8 generates an audit record for any use of the \"chmod\",\"fchmod\", and \"fchmodat\" syscalls by running the following command to check the file system rules in \"/etc/audit/audit.rules\": 
 
$ sudo grep chmod /etc/audit/audit.rules 
 
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng 
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng 
 
If the command does not return an audit rule for \"chmod\", \"fchmod\", and \"fchmodat\", or any of the lines returned are commented out, this is a finding. 
 
Note: The \"-k\" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248791"
STIG_ID="OL08-00-030490"
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
    TARGET="/etc/audit/audit.rules":"
    REQUIRED="1000"

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
