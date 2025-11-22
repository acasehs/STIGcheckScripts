#!/usr/bin/env bash
################################################################################
# STIG Check: V-214278
# Severity: medium
# Rule Title: The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.
# STIG ID: AS24-U2-000030
# Rule ID: SV-214278r960759
#
# Description:
#     The Apache web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, and communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented. 
 
Methods of communication are \"http\" for publicly displayed information, \"https\" to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.

Satisfies: SRG-APP-000014-
#
# Check Content:
#     Verify the \"ssl module\" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared)
 
If the \"ssl_module\" is not enabled, this is a finding. 
 
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLProtocol
# cat /<path_to_file>/ssl.conf | grep -i \"SSLProtocol\" 
Output: SSLProtocol -ALL +TLSv1.2
 
If the \"SSLProtocol\" directive is missing or does not look like the following, this is a finding: 
 
SSLProtocol -ALL +TLSv1.2 
 
If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52 Rev 2, or if non-FIPS-approved algorithms are enabled, this is a finding. 
 
Note: In some cases, web servers are configured in an environment to support load balancing. This configuration most likely uses a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the websites may be installed on the content switch versus the individua
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214278"
STIG_ID="AS24-U2-000030"
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
