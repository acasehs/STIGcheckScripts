#!/usr/bin/env bash
################################################################################
# STIG Check: V-214300
# Severity: medium
# Rule Title: The Apache web server must only accept client certificates issued by DOD PKI or DoD-approved PKI Certification Authorities (CAs).
# STIG ID: AS24-U2-000810
# Rule ID: SV-214300r1051295
#
# Description:
#     Non-DOD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DOD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.
#
# Check Content:
#     Verify the â€œssl moduleâ€ module is loaded:
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the \"ssl_module\" is not found, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the following:
# cat /etc/httpd/conf.d/ssl.conf | grep -i \"SSLCACertificateFile\"
Output should be similar to: SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt

Review the path of the \"SSLCACertificateFile\" directive.

Review the contents of <'\''path of SSLCACertificateFile'\''>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DOD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DOD CA, this is a finding.

NOTE: There are non-DOD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DOD-approved certificate can in
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214300"
STIG_ID="AS24-U2-000810"
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
