#!/usr/bin/env bash
################################################################################
# STIG Check: V-214288
# Severity: medium
# Rule Title: Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted applic
# STIG ID: AS24-U2-000470
# Rule ID: SV-214288r1043180
#
# Description:
#     Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol. 
 
When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web s
#
# Check Content:
#     Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file: 
 
# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions \"apache2ctl -V\" or  \"httpd -V\" can also be used. 

Search for the \"Header\" directive:

# cat /<path_to_file>/httpd.conf | grep -i \"Header\"
 
If \"HttpOnly\" \"secure\" is not configured, this is a finding. 
 
\"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure\" 
 
Review the code. If, when creating cookies, the following is not occurring, this is a finding: 
 
function setCookie() { document.cookie = \"ALEPH_SESSION_ID = $SESS; path = /; secure\"; }
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214288"
STIG_ID="AS24-U2-000470"
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
