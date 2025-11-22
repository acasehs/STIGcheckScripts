#!/usr/bin/env bash
################################################################################
# STIG Check: V-214268
# Severity: medium
# Rule Title: Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.
# STIG ID: AS24-U1-000870
# Rule ID: SV-214268r961632
#
# Description:
#     A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e., HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.

Satisfies: SRG-APP-000439-WSR-000154, SRG-APP-000439-WSR-000155
#
# Check Content:
#     Verify the session cookie module is loaded

# httpd -M | grep -i session_cookie_module
Output should look similar to: session_cookie_module (shared)

Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:

# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, \"apache2ctl -V\" or  \"httpd -V\" can also be used. 

Search for the directive \"Session\" in the \"httpd.conf\" file:

# cat httpd.conf  | grep -i \"Session\"
Output should be similar to: 
Session on
SessionCookieName httpOnly Secure
SessionCryptoCipher aes256
SessionMaxAge 600

Note: SSL directives can also be located in /etc/httpd/conf.d/ssl.conf.

If the \"Session\" and \"SessionCookieName\" directives are not present, this is a finding.

If \"Session\" is not set to \"on\" and \"SessionCookieName\"
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214268"
STIG_ID="AS24-U1-000870"
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
