#!/usr/bin/env bash
################################################################################
# STIG Check: V-214281
# Severity: medium
# Rule Title: The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.
# STIG ID: AS24-U2-000300
# Rule ID: SV-214281r960963
#
# Description:
#     Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not ...
#
# Check Content:
#     In a command line, run \"httpd -M | grep -i ssl_module\".    If the \"ssl_module\" is not enabled, this is a finding.    Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:    # apachectl -V | egrep -i 'httpd_root|server_config_file' -D HTTPD_ROOT=\"/etc/httpd\" -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"  Note: The apachectl front end is the preferred method for locating the Apa...
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214281"
STIG_ID="AS24-U2-000300"
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
# In a command line, run \"httpd -M | grep -i ssl_module\".    If the \"ssl_module\" is not enabled, this is a finding.    Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:    # apachectl -V | egrep -i 'httpd_root|server_config_file' -D HTTPD_ROOT=\"/etc/httpd\" -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"  Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions \"apache2ctl -V\" or  \"httpd -V\" can also be used.    If ...
#
# Fix Text from the official STIG:
# Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:    # apachectl -V | egrep -i 'httpd_root|server_config_file'  -D HTTPD_ROOT=\"/etc/httpd\"  -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"    Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.    If \"Action\" or \"AddHandler\" exist and they configure any of the following (.exe, .dll, .com, .bat, or .csh), remove those references.    Restart Apache: apachectl restart    Ensure this process is documented and approv...

echo "TODO: Implement Apache check for V-214281"
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
  "rule_title": "The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.",
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
Rule: The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
