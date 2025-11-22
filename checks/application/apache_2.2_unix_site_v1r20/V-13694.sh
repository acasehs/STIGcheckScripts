#!/usr/bin/env bash
################################################################################
# STIG Check: V-13694
# Severity: medium
# Rule Title: Public web servers must use TLS if authentication is required.
# STIG ID: WG342 A22
# Rule ID: SV-33030r2
#
# Description:
#     Transport Layer Security (TLS) is optional for a public web server.  However, if authentication is being performed, then the use of the TLS protocol is required._x000D_ _x000D_ Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure....
#
# Check Content:
#     Enter the following command: _x000D_ _x000D_ /usr/local/apache2/bin/httpd â€“M _x000D_ _x000D_ This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, this is a finding. _x000D_ _x000D_ After determining that the ssl module is active, enter the following command: _x000D_ _x000D_ grep \"SSL\" /usr/local/apache2/conf/httpd.conf _x000...
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

Example:
  $0
  $0 --config apache-config.json
  $0 --output-json results.json
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
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi
    # TODO: Load configuration values using jq if available
fi

################################################################################
# APACHE HTTPD HELPER FUNCTIONS
################################################################################

# Get Apache configuration root and main config file
get_apache_config() {
    # Try apachectl first
    if command -v apachectl &> /dev/null; then
        HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i "HTTPD_ROOT" | cut -d'"' -f2)
        SERVER_CONFIG=$(apachectl -V 2>/dev/null | grep -i "SERVER_CONFIG_FILE" | cut -d'"' -f2)
    # Try apache2ctl
    elif command -v apache2ctl &> /dev/null; then
        HTTPD_ROOT=$(apache2ctl -V 2>/dev/null | grep -i "HTTPD_ROOT" | cut -d'"' -f2)
        SERVER_CONFIG=$(apache2ctl -V 2>/dev/null | grep -i "SERVER_CONFIG_FILE" | cut -d'"' -f2)
    # Try httpd directly
    elif command -v httpd &> /dev/null; then
        HTTPD_ROOT=$(httpd -V 2>/dev/null | grep -i "HTTPD_ROOT" | cut -d'"' -f2)
        SERVER_CONFIG=$(httpd -V 2>/dev/null | grep -i "SERVER_CONFIG_FILE" | cut -d'"' -f2)
    else
        echo "ERROR: Apache not found (apachectl, apache2ctl, or httpd)"
        return 1
    fi

    # Construct full config path
    if [[ "$SERVER_CONFIG" == /* ]]; then
        HTTPD_CONF="$SERVER_CONFIG"
    else
        HTTPD_CONF="$HTTPD_ROOT/$SERVER_CONFIG"
    fi

    if [[ ! -f "$HTTPD_CONF" ]]; then
        echo "ERROR: Apache config file not found: $HTTPD_CONF"
        return 1
    fi

    return 0
}

################################################################################
# CHECK IMPLEMENTATION
################################################################################

# TODO: Implement the actual check logic
#
# STIG Check Method from the official STIG:
# Enter the following command: _x000D_ _x000D_ /usr/local/apache2/bin/httpd â€“M _x000D_ _x000D_ This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, this is a finding. _x000D_ _x000D_ After determining that the ssl module is active, enter the following command: _x000D_ _x000D_ grep \"SSL\" /usr/local/apache2/conf/httpd.conf _x000D_ _x000D_ Review the SSL sections of the httpd.conf file, all enabled SSLProtocol directives for Ap...
#
# Fix Text from the official STIG:
# Edit the httpd.conf file and set the SSLProtocol to \"TLSv1\" for Apache 2.2.22 and older or to \"ALL -SSLv2 -SSLv3\" for Apache versions newer than 2.2.22.  The SSLEngine parameter must also be set to On.

echo "TODO: Implement Apache check for V-13694"
echo "This is a placeholder that requires implementation."

# Placeholder status
STATUS="Not Implemented"
EXIT_CODE=2
FINDING_DETAILS="Check logic not yet implemented - requires Apache domain expertise"

################################################################################
# OUTPUT RESULTS
################################################################################

# JSON output if requested
if [[ -n "$OUTPUT_JSON" ]]; then
    cat > "$OUTPUT_JSON" << EOF_JSON
{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "rule_title": "Public web servers must use TLS if authentication is required.",
  "status": "$STATUS",
  "finding_details": "$FINDING_DETAILS",
  "timestamp": "$TIMESTAMP",
  "exit_code": $EXIT_CODE
}
EOF_JSON
fi

# Human-readable output
cat << EOF

================================================================================
STIG Check: $VULN_ID - $STIG_ID
Severity: ${SEVERITY^^}
================================================================================
Rule: Public web servers must use TLS if authentication is required.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
