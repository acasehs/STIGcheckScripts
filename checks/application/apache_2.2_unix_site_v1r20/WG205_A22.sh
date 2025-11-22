#!/usr/bin/env bash
################################################################################
# STIG Check: V-3333
# Severity: medium
# Rule Title: The web document (home) directory must be in a separate partition from the web serverâ€™s system files.
# STIG ID: WG205 A22
# Rule ID: SV-33021r1
#
# Description:
#     Application partitioning enables an additional security measure by securing user traffic under one security context, while managing system and application files under another.  Web content is can be to an anonymous web user. For such an account to have access to system files of any type is a major security risk that is avoidable and desirable. Failure to partition the system files from the web site documents increases risk of attack via directory traversal, or impede web site availability due to
#
# Check Content:
#     grep \"DocumentRoot\" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Note each location following the DocumentRoot string, this is the configured path to the document root directory(s). _x000D_
_x000D_
Use the command df -k to view each document root'\''s partition setup. _x000D_
_x000D_
Compare that against the results for the Operating System file systems, and against the partition for the web server system files, which is the result of the command: _x000D_
_x000D_
df -k /usr/local/apache2/bin_x000D_
_x000D_
If the document root path is on the same partition as the web server system files or the OS file systems, this is a finding._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-3333"
STIG_ID="WG205 A22"
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
    CONFIG="/usr/local/apache2/conf/httpd.conf"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "Unknown" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "Unknown"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "Unknown"
        exit 1
    fi

}

# Run main check
main "$@"
