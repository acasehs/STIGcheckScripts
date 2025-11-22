#!/usr/bin/env bash
################################################################################
# STIG Check: V-214292
# Severity: medium
# Rule Title: The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.
# STIG ID: AS24-U2-000620
# Rule ID: SV-214292r961167
#
# Description:
#     The goal is to completely control the web user'\''s experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. 
 
Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the Apache web server'\''s directory structure by locating directories without default pages. In the scenario, the Apache web
#
# Check Content:
#     View the \"DocumentRoot\" value by entering the following command: 
 
awk '\''{print $1,$2,$3}'\'' <'\''INSTALL PATH'\''>/conf/httpd.conf|grep -i DocumentRoot|grep -v '\''^#'\'' 
 
Note each location following the \"DocumentRoot\" string. This is the configured path(s) to the document root directory(s). 
 
To view a list of the directories and subdirectories and the file \"index.html\", from each stated \"DocumentRoot\" location enter the following commands: 
 
find . -type d 
find . -type f -name index.html 
 
Review the results for each document root directory and its subdirectories. 
 
If a directory does not contain an \"index.html\" or equivalent default document, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214292"
STIG_ID="AS24-U2-000620"
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
    # Locate Apache configuration
    HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i 'HTTPD_ROOT' | cut -d'"' -f2)
    CONFIG_FILE=$(apachectl -V 2>/dev/null | grep -i 'SERVER_CONFIG_FILE' | cut -d'"' -f2)

    if [[ -z "$HTTPD_ROOT" ]] || [[ -z "$CONFIG_FILE" ]]; then
        echo "ERROR: Unable to locate Apache configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not found or not configured" ""
        exit 3
    fi

    FULL_CONFIG="$HTTPD_ROOT/$CONFIG_FILE"

    if [[ ! -f "$FULL_CONFIG" ]]; then
        echo "ERROR: Configuration file not found: $FULL_CONFIG"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file missing" "$FULL_CONFIG"
        exit 3
    fi

    echo "INFO: Apache configuration file: $FULL_CONFIG"
    echo ""
    echo "MANUAL REVIEW REQUIRED: Review Apache configuration for STIG compliance"
    echo "Configuration file location: $FULL_CONFIG"
    echo ""
    echo "This check requires manual examination of Apache settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Configuration review requires manual validation" "$FULL_CONFIG"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
