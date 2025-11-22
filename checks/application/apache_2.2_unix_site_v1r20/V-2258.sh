#!/usr/bin/env bash
################################################################################
# STIG Check: V-2258
# Severity: high
# Rule Title: Web client access to the content directories must be restricted to read and execute.
# STIG ID: WG290 A22
# Rule ID: SV-33027r2
#
# Description:
#     Excessive permissions for the anonymous web user account are one of the most common faults contributing to the compromise of a web server. If this user is able to upload and execute files on the web server, the organization or owner of the server will no longer have control of the asset.
#
# Check Content:
#     To view the value of Alias enter the following command: _x000D_ _x000D_ grep \"Alias\" /usr/local/apache2/conf/httpd.conf _x000D_ _x000D_ Alias_x000D_ ScriptAlias_x000D_ ScriptAliasMatch_x000D_ _x000D_ Review the results to determine the location of the files listed above. _x000D_ _x000D_ Enter the following command to determine the permissions of the above file: _x000D_ _x000D_ ls -Ll /file-path_x0...
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2258"
STIG_ID="WG290 A22"
SEVERITY="high"
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
# To view the value of Alias enter the following command: _x000D_ _x000D_ grep \"Alias\" /usr/local/apache2/conf/httpd.conf _x000D_ _x000D_ Alias_x000D_ ScriptAlias_x000D_ ScriptAliasMatch_x000D_ _x000D_ Review the results to determine the location of the files listed above. _x000D_ _x000D_ Enter the following command to determine the permissions of the above file: _x000D_ _x000D_ ls -Ll /file-path_x000D_ _x000D_ The only accounts listed should be the web administrator, developers, and the account a...
#
# Fix Text from the official STIG:
# Assign the appropriate permissions to the applicable directories and files using the chmod command.

echo "TODO: Implement Apache check for V-2258"
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
  "rule_title": "Web client access to the content directories must be restricted to read and execute.",
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
Rule: Web client access to the content directories must be restricted to read and execute.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
