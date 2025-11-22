#!/usr/bin/env bash
################################################################################
# STIG Check: V-2262
# Severity: medium
# Rule Title: A private web server must utilize an approved TLS version.
# STIG ID: WG340 A22
# Rule ID: SV-33029r2
#
# Description:
#     Transport Layer Security (TLS) encryption is a required security setting for a private web server.  Encryption of private information is essential to ensuring data confidentiality.  If private information is not encrypted, it can be intercepted and easily read by an unauthorized party.  A private web server must use a FIPS 140-2 approved TLS version, and all non-FIPS-approved SSL versions must be disabled._x000D_
_x000D_
FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP 800-
#
# Check Content:
#     Enter the following command:_x000D_
_x000D_
/usr/local/apache2/bin/httpd â€“M |grep -i ssl_x000D_
_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, determine if it is loaded as a dynamic module. Enter the following command:_x000D_
_x000D_
grep ^LoadModule /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
If the SSL module is not enabled this is a finding. _x000D_
_x000D_
After determining that the ssl module is active, enter the following command to review the SSL directives._x000D_
_x000D_
grep -i ssl /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
Review the SSL section(s) of the httpd.conf file, all enabled SSLProtocol directives must be set to â€œALL -SSLv2 -SSLv3â€ or this is a finding. _x000D_
_x000D_
NOTE: For Apache 2.2.22 and older, all enabled SSLProtocol directives must be set to \"TLSv1\" or this is a finding._x000D_
_x000D_
All enabled SSLEngine directive must be set to â€œonâ€, if not t
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2262"
STIG_ID="WG340 A22"
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

    if grep -q "SSL" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "SSL"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "SSL"
        exit 1
    fi

}

# Run main check
main "$@"
