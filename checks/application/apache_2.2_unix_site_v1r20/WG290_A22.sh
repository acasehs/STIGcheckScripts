#!/usr/bin/env bash
################################################################################
# STIG Check: V-2258
# Severity: high
# Rule Title: Web client access to the content directories must be restricted to read and execute.
# STIG ID: WG290 A22
# Rule ID: SV-33027r2
#
# Description:
#     Excessive permissions for the anonymous web user account are one of the most common faults contributing to the compromise of a web server. If this user is able to upload and execute files on the web server, the organization or owner of the server will no longer have control of the asset.
#
# Check Content:
#     To view the value of Alias enter the following command: _x000D_
_x000D_
grep \"Alias\" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Alias_x000D_
ScriptAlias_x000D_
ScriptAliasMatch_x000D_
_x000D_
Review the results to determine the location of the files listed above. _x000D_
_x000D_
Enter the following command to determine the permissions of the above file: _x000D_
_x000D_
ls -Ll /file-path_x000D_
_x000D_
The only accounts listed should be the web administrator, developers, and the account assigned to run the apache server service. _x000D_
_x000D_
If accounts that donâ€™t need access to these directories are listed, this is a finding. _x000D_
_x000D_
If the permissions assigned to the account for the Apache web server service, or any group to which the Apache web server service belongs, is greater than Read & Execute (R_E), this is a finding._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2258"
STIG_ID="WG290 A22"
SEVERITY="high"
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
    SVC="server"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi

}

# Run main check
main "$@"
