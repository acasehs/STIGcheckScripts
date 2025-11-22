#!/usr/bin/env bash
################################################################################
# STIG Check: V-2263
# Severity: medium
# Rule Title: A private web server will have a valid DoD server certificate.
# STIG ID: WG350 A22
# Rule ID: SV-33031r1
#
# Description:
#     This check verifies that DoD is a hosted web site'\''s CA. The certificate is actually a DoD-issued server certificate used by the organization being reviewed. This is used to verify the authenticity of the web site to the user. If the certificate is not for the server (Certificate belongs to), if the certificate is not issued by DoD (Certificate was issued by), or if the current date is not included in the valid date (Certificate is valid from), then there is no assurance that the use of the ce
#
# Check Content:
#     Open browser window and browse to the appropriate site. Before entry to the site, you should be presented with the server'\''s DoD PKI credentials. Review these credentials for authenticity._x000D_
_x000D_
Find an entry which cites:_x000D_
_x000D_
Issuer:_x000D_
CN = DOD CLASS 3 CA-3_x000D_
OU = PKI_x000D_
OU = DoD_x000D_
O = U.S. Government_x000D_
C = US_x000D_
_x000D_
If the server is running as a public web server, this finding should be Not Applicable._x000D_
_x000D_
NOTE: In some cases, the web servers are configured in an environment to support load balancing. This configuration most likely utilizes a content switch to control traffic to the various web servers. In this situation, the SSL certificate for the web sites may be installed on the content switch vs. the individual web sites. This solution is acceptable as long as the web servers are isolated from the general population LAN. Users should not have the ability to bypass the content switch to access the web sites._x000D_

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2263"
STIG_ID="WG350 A22"
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
    # Locate Apache configuration
    HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i 'HTTPD_ROOT' | cut -d'"' -f2)
    CONFIG_FILE=$(apachectl -V 2>/dev/null | grep -i 'SERVER_CONFIG_FILE' | cut -d'"' -f2)

    if [[ -z "$HTTPD_ROOT" ]] || [[ -z "$CONFIG_FILE" ]]; then
        echo "ERROR: Unable to locate Apache configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not found or not configured" ""
        exit 3
    fi

    FULL_CONFIG="$HTTPD_ROOT/$CONFIG_FILE"

    if [[ ! -f "$FULL_CONFIG" ]]; then
        echo "ERROR: Configuration file not found: $FULL_CONFIG"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file missing" "$FULL_CONFIG"
        exit 3
    fi

    echo "INFO: Apache configuration file: $FULL_CONFIG"
    echo ""
    echo "MANUAL REVIEW REQUIRED: Review Apache configuration for STIG compliance"
    echo "Configuration file location: $FULL_CONFIG"
    echo ""
    echo "This check requires manual examination of Apache settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Configuration review requires manual validation" "$FULL_CONFIG"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
