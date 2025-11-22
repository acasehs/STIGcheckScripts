#!/usr/bin/env bash
################################################################################
# STIG Check: V-214232
# Severity: medium
# Rule Title: The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.
# STIG ID: AS24-U1-000070
# Rule ID: SV-214232r960879
#
# Description:
#     Log records can be generated from various components within the Apache web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific Apache web server functionalities may be logged as well. The Apache web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the Apache web server must be able to facilitate these changes.

The minimum list of logged events
#
# Check Content:
#     Verify the Log Configuration Module is loaded:
# httpd -M | grep -i log_config_module
Output:  log_config_module (shared)

If the \"log_config_module\" is not enabled, this is a finding.

Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:

# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, \"apache2ctl -V\" or  \"httpd -V\" can also be used.  

Search for the directive \"LogFormat\" in the \"httpd.conf\" file:

# cat /<path_to_file>/httpd.conf | grep -i \"LogFormat\"

If the \"LogFormat\" directive is missing, this is a finding:

An example is:
LogFormat \"%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\" \" common
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214232"
STIG_ID="AS24-U1-000070"
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
    CONFIG="/etc/httpd""

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "the" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "the"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "the"
        exit 1
    fi

}

# Run main check
main "$@"
