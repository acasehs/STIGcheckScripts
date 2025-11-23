#!/usr/bin/env bash
################################################################################
# STIG Check: V-2265
# Severity: low
# Rule Title: Java software on production web servers must be limited to class files and the JAVA virtual machine.
# STIG ID: WG490 A22
# Rule ID: SV-33032r1
#
# Description:
#     From the source code in a .java or a .jpp file, the Java compiler produces a binary file with an extension of .class. The .java or .jpp file would, therefore, reveal sensitive information regarding an applicationâ€™s logic and permissions to resources on the server. By contrast, the .class file, bec...
#
# Check Content:
#     Enter the commands: _x000D_ _x000D_ find / -name *.java _x000D_ _x000D_ find / -name *.jpp _x000D_ _x000D_ If either file type is found, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2265"
STIG_ID="WG490 A22"
SEVERITY="low"
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

# STIG Check Implementation - Manual Review Required
#
# This check requires manual verification of Apache 2.2 Unix Site configuration.
#
# Please consult the STIG documentation for specific compliance requirements.

echo "================================================================================"
echo "STIG Check: $VULN_ID"
echo "STIG ID: $STIG_ID"
echo "Severity: $SEVERITY"
echo "Timestamp: $TIMESTAMP"
echo "================================================================================"
echo ""
echo "MANUAL REVIEW REQUIRED"
echo "This STIG check requires manual verification of Apache/HTTP Server configuration."
echo ""
echo "Apache checks typically require:"
echo "  - Access to Apache configuration files (httpd.conf, ssl.conf, etc.)"
echo "  - Review of server directives and module configuration"
echo "  - Inspection of virtual host settings"
echo "  - Log file analysis"
echo ""
echo "Please consult the STIG documentation for specific compliance requirements."
echo ""

# Manual review status
STATUS="Not_Reviewed"
EXIT_CODE=2
FINDING_DETAILS="Manual review required - consult STIG documentation for Apache 2.2 Unix Site compliance verification"


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
  "rule_title": "Java software on production web servers must be limited to class files and the JAVA virtual machine.",
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
Rule: Java software on production web servers must be limited to class files and the JAVA virtual machine.
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
