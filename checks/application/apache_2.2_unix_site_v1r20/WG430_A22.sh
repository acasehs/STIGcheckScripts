#!/usr/bin/env bash
################################################################################
# STIG Check: V-2270
# Severity: medium
# Rule Title: Anonymous FTP user access to interactive scripts is prohibited.
# STIG ID: WG430 A22
# Rule ID: SV-36641r1
#
# Description:
#     The directories containing the CGI scripts, such as PERL, must not be accessible to anonymous users via FTP. This applies to all directories that contain scripts that can dynamically produce web pages in an interactive manner (i.e., scripts based upon user-provided input). Such scripts contain information that could be used to compromise a web service, access system resources, or deface a web site.
#
# Check Content:
#     Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). _x000D_
_x000D_
Using ls â€“al, examine the file permissions on the CGI, the cgi-bin, and the cgi-shl directories._x000D_
_x000D_
Anonymous FTP users must not have access to these directories._x000D_
_x000D_
If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any group that does not require access, this is a finding._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2270"
STIG_ID="WG430 A22"
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
    # Locate Apache configuration directory
    HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i 'HTTPD_ROOT' | cut -d'"' -f2)

    if [[ -z "$HTTPD_ROOT" ]]; then
        echo "ERROR: Unable to locate Apache root directory"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not configured" ""
        exit 3
    fi

    if [[ ! -d "$HTTPD_ROOT" ]]; then
        echo "ERROR: Apache root directory not found: $HTTPD_ROOT"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Directory missing" "$HTTPD_ROOT"
        exit 3
    fi

    # Check permissions
    perms=$(ls -ld "$HTTPD_ROOT" 2>/dev/null)

    echo "INFO: Directory permissions:"
    echo "$perms"

    echo "MANUAL REVIEW REQUIRED: Verify permissions meet STIG requirements"
    echo "Location: $HTTPD_ROOT"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Permission check requires validation" "$perms"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
