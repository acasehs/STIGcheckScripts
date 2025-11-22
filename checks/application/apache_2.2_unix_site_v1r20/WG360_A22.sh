#!/usr/bin/env bash
################################################################################
# STIG Check: V-2227
# Severity: high
# Rule Title: Symbolic links must not be used in the web content directory tree.
# STIG ID: WG360 A22
# Rule ID: SV-30576r1
#
# Description:
#     A symbolic link allows a file or a directory to be referenced using a symbolic name raising a potential hazard if symbolic linkage is made to a sensitive area._x000D_
_x000D_
When web scripts are executed and symbolic links are allowed, the web user could be allowed to access locations on the web server that are outside the scope of the web document root or home directory._x000D_

#
# Check Content:
#     Locate the directories containing the web content, (i.e., /usr/local/apache/htdocs). _x000D_
_x000D_
Use ls â€“al. _x000D_
_x000D_
An entry, such as the following, would indicate the presence and use of symbolic links:_x000D_
_x000D_
lr-xrâ€”r--  4000 wwwusr  wwwgrp	2345	Apr 15	  data  -> /usr/local/apache/htdocs_x000D_
_x000D_
Such a result found in a web document directory is a finding. Additional Apache configuration check in the httpd.conf file:_x000D_
_x000D_
<Directory /[website root dir]>_x000D_
    Options FollowSymLinks_x000D_
    AllowOverride None_x000D_
</Directory>_x000D_
_x000D_
The above configuration is incorrect and is a finding. The correct configuration is:_x000D_
_x000D_
<Directory /[website root dir]>_x000D_
    Options SymLinksIfOwnerMatch_x000D_
    AllowOverride None_x000D_
</Directory>_x000D_
_x000D_
Finally, the target file or directory must be owned by the same owner as the link, which should be a privileged account with access to the web content._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2227"
STIG_ID="WG360 A22"
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
    CONFIG="/usr/local/apache/htdocs)."

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
