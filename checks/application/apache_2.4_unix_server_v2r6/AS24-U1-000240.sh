#!/usr/bin/env bash
################################################################################
# STIG Check: V-214239
# Severity: medium
# Rule Title: The Apache web server must not perform user management for hosted applications.
# STIG ID: AS24-U1-000240
# Rule ID: SV-214239r960963
#
# Description:
#     User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts. All of this must be done enterprise-wide.

The web server contains a minimal user management function, but the web server user management function does not off
#
# Check Content:
#     Review the web server documentation and configuration to determine if the web server is being used as a user management application.
 
Search for \"AuthUserFile\" in the configuration files in the installed Apache Path.
 
Example:

grep -rin AuthUserFile *
 
If there are uncommented lines pointing to files on disk using the above configuration option, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214239"
STIG_ID="AS24-U1-000240"
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
