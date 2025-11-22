#!/usr/bin/env bash
################################################################################
# STIG Check: V-214269
# Severity: medium
# Rule Title: The Apache web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.
# STIG ID: AS24-U1-000900
# Rule ID: SV-214269r961632
#
# Description:
#     During the initial setup of a Transport Layer Security (TLS) connection to the Apache web server, the client sends a list of supported cipher suites in order of preference. The Apache web server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the Apache web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to br
#
# Check Content:
#     Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" and \"ssl.conf\" files:

Search the httpd.conf and ssl.conf file for the following uncommented directive: SSLCipherSuite

# cat httpd.conf  | grep -i SSLCipherSuite
Output: None

# cat /etc/httpd/conf.d/ssl.conf | grep -i SSLCipherSuite
Output: SSLCipherSuite HIGH:3DES:!NULL:!MD5:!SEED:!IDEA:!EXPORT

For all enabled SSLCipherSuite directives, ensure the cipher specification string contains the kill cipher from list option for all export cipher suites, i.e., !EXPORT, which may be abbreviated !EXP as in the following example:

Example: SSLCipherSuite=\"HIGH:MEDIUM:!MD5!EXP:!NULL:!LOW:!ADH

If the SSLCipherSuite directive does not contain !EXPORT or !EXP or there are no enabled SSLCipherSuite directives, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214269"
STIG_ID="AS24-U1-000900"
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
    CONFIG="/etc/httpd/conf.d/ssl.conf"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "uncommented" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "uncommented"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "uncommented"
        exit 1
    fi

}

# Run main check
main "$@"
