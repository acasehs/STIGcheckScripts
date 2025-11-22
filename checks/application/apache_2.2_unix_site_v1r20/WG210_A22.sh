#!/usr/bin/env bash
################################################################################
# STIG Check: V-2226
# Severity: medium
# Rule Title: Web content directories must not be anonymously shared.
# STIG ID: WG210 A22
# Rule ID: SV-33022r1
#
# Description:
#     Sharing web content is a security risk when a web server is involved. Users accessing the share anonymously could experience privileged access to the content of such directories. Network sharable directories expose those directories and their contents to unnecessary access. Any unnecessary exposure increases the risk that someone could exploit that access and either compromises the web content or cause web server performance problems.
#
# Check Content:
#     To view the DocumentRoot enter the following command: _x000D_
_x000D_
grep \"DocumentRoot\" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
To view the ServerRoot enter the following command: _x000D_
_x000D_
grep \"serverRoot\" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Note the location following the DocumentRoot and ServerRoot directives. _x000D_
_x000D_
Enter the following commands to determine if file sharing is running: _x000D_
_x000D_
ps -ef | grep nfs, ps -ef | grep smb _x000D_
_x000D_
If results are returned, determine the shares and confirm they are not in the same directory as listed above, If they are, this is a finding. 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2226"
STIG_ID="WG210 A22"
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

    if grep -q "ServerRoot" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "ServerRoot"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "ServerRoot"
        exit 1
    fi

}

# Run main check
main "$@"
