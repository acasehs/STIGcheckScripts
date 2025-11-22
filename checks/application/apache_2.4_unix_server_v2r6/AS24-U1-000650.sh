#!/usr/bin/env bash
################################################################################
# STIG Check: V-214258
# Severity: medium
# Rule Title: The Apache web server must set an inactive timeout for sessions.
# STIG ID: AS24-U1-000650
# Rule ID: SV-214258r1043182
#
# Description:
#     Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the Apache web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. mod_reqtimeout is an Apache module designed to shut down connections from clients taking too long to send
#
# Check Content:
#     Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:

# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, \"apache2ctl -V\" or  \"httpd -V\" can also be used. 

Verify the \"reqtimeout_module\" is loaded:

Change to the root directory of Apache and run the following command to verify the \"reqtimeout_module\" is loaded:

# httpd -M | grep reqtimeout_module
Outout: reqtimeout_module (shared)

If the \"reqtimeout_module\" is not loaded, this is a finding.

Verify the \"RequestReadTimeout\" directive is configured. 
Example: RequestReadTimeout handshake=5 header=10 body=30
Allows for 5 seconds to complete the TLS handshake, 10 seconds to receive the request headers, and 30 seconds for receiving the request body.
The values will depend upon the website. 
The 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214258"
STIG_ID="AS24-U1-000650"
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
