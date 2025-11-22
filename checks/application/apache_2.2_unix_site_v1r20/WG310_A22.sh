#!/usr/bin/env bash
################################################################################
# STIG Check: V-2260
# Severity: medium
# Rule Title: A web site must not contain a robots.txt file.
# STIG ID: WG310 A22
# Rule ID: SV-33028r2
#
# Description:
#     Search engines are constantly at work on the Internet.  Search engines are augmented by agents, often referred to as spiders or bots, which endeavor to capture and catalog web-site content.  In turn, these search engines make the content they obtain and catalog available to any public web user. _x000D_
_x000D_
To request that a well behaved search engine not crawl and catalog a site, the web site may contain a file called robots.txt.  This file contains directories and files that the web server 
#
# Check Content:
#     Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor and search for the following uncommented directives: DocumentRoot & Alias_x000D_
_x000D_
Navigate to the location(s) specified in the Include statement(s), and review each file for the following uncommented directives: DocumentRoot & Alias_x000D_
_x000D_
At the top level of the directories identified after the enabled DocumentRoot & Alias directives, verify that a â€œrobots.txtâ€ file does not exist.  If the file does exist, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2260"
STIG_ID="WG310 A22"
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
