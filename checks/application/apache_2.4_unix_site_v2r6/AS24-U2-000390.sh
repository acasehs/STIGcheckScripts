#!/usr/bin/env bash
################################################################################
# STIG Check: V-214287
# Severity: medium
# Rule Title: Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.
# STIG ID: AS24-U2-000390
# Rule ID: SV-214287r961041
#
# Description:
#     The web server'\''s private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. 
 
By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
#
# Check Content:
#     Verify the \"ssl module\" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the \"ssl_module\" is not enabled, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLCertificateKeyFile location.
# cat <path to file>/ssl.conf | grep -i SSLCertificateKeyFile
Output: SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

Identify the correct permission set and owner/group of the certificate key file.
# ls -laH /etc/pki/tls/private/localhost.key
Output: -rw-------. 1 root root 1675 Sep 10  2020 /etc/pki/tls/private/localhost.key

The permission set must be 600 or more restrictive and the owner/group of the key file must be accessible to only authenticated system administrator and the designated PKI Sponsor.

If the correct permissions are not set or if the private key is accessible by unauthenticated or unauthorized users, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214287"
STIG_ID="AS24-U2-000390"
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
    TARGET="/etc/httpd/conf.d/ssl.conf"
    REQUIRED="1675"

    if [[ ! -e "$TARGET" ]]; then
        echo "ERROR: File not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$TARGET"
        exit 3
    fi

    actual=$(stat -c "%a" "$TARGET" 2>/dev/null)
    if [[ $((8#$actual)) -le $((8#$REQUIRED)) ]]; then
        echo "PASS: Permissions $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$actual"
        exit 0
    else
        echo "FAIL: Permissions $actual (required: $REQUIRED or less)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Too permissive" "$actual"
        exit 1
    fi

}

# Run main check
main "$@"
