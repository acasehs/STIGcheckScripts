#!/usr/bin/env bash
################################################################################
# STIG Check: V-13694
# Severity: medium
# Rule Title: Public web servers must use TLS if authentication is required.
# STIG ID: WG342 A22
# Rule ID: SV-33030r2
#
# Description:
#     Transport Layer Security (TLS) is optional for a public web server.  However, if authentication is being performed, then the use of the TLS protocol is required._x000D_
_x000D_
Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure.  Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network.  To further protect the authentication
#
# Check Content:
#     Enter the following command: _x000D_
_x000D_
/usr/local/apache2/bin/httpd â€“M _x000D_
_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, this is a finding. _x000D_
_x000D_
After determining that the ssl module is active, enter the following command: _x000D_
_x000D_
grep \"SSL\" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Review the SSL sections of the httpd.conf file, all enabled SSLProtocol directives for Apache 2.2.22 and older must be set to â€œTLSv1â€.  Releases newer than Apache 2.2.22 must be set to \"ALL -SSLv2 -SSLv3\". If SSLProtocol is not set to the proper value, this is a finding. _x000D_
_x000D_
All enabled SSLEngine directives must be set to â€œonâ€, If they are not, this a finding. _x000D_
_x000D_
NOTE: In some cases web servers are configured in an environment to support load balancing. This configuration most likely utilizes a content switch to control traffic to the various web
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-13694"
STIG_ID="WG342 A22"
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
    CONFIG="/usr/local/apache2/bin/httpd"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "SSLProtocol" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "SSLProtocol"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "SSLProtocol"
        exit 1
    fi

}

# Run main check
main "$@"
