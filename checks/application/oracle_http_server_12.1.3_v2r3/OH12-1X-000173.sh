#!/usr/bin/env bash
################################################################################
# STIG Check: V-221415
# Severity: medium
# Rule Title: OHS must be configured to use a specified IP address, port, and protocol.
# STIG ID: OH12-1X-000173
# Rule ID: SV-221415r1043177
#
# Description:
#     The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.  

Accessing the hosted application through an IP address normally used for non-application functions opens the pos
#
# Check Content:
#     1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a \"Listen\" directive at the OHS server configuration scope.

3. If the directive is set without an IP address, port, and protocol specified, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221415"
STIG_ID="OH12-1X-000173"
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
    # Oracle HTTP Server - Configuration File Check

    # Note: DOMAIN_HOME must be set or provided via config
    if [[ -z "$DOMAIN_HOME" ]]; then
        if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
            DOMAIN_HOME=$(grep -i "domain_home" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d ' "')
        fi
    fi

    if [[ -z "$DOMAIN_HOME" ]]; then
        echo "ERROR: DOMAIN_HOME not set"
        echo "Please set DOMAIN_HOME environment variable or provide via --config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "DOMAIN_HOME not set" ""
        exit 3
    fi

    # Search for configuration files
    CONF_FILE=""
    for file in "$DOMAIN_HOME"/config/fmwconfig/components/OHS/*/httpd.conf \
                "$DOMAIN_HOME"/config/fmwconfig/components/OHS/*/ssl.conf \
                "$DOMAIN_HOME"/config/fmwconfig/components/OHS/*/*.conf; do
        if [[ -f "$file" ]]; then
            CONF_FILE="$file"
            break
        fi
    done

    if [[ -z "$CONF_FILE" ]]; then
        echo "ERROR: Configuration file not found"
        echo "Expected location: $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file not found" ""
        exit 3
    fi

    echo "INFO: Found configuration file: $CONF_FILE"
    echo ""

    # Display relevant directives
    echo "Checking for directive: Listen"
    grep -i "Listen" "$CONF_FILE" 2>/dev/null || echo "Directive not found"
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify directive value meets STIG requirements"
    echo "Configuration file: $CONF_FILE"
    echo "Required directive: Listen"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Config check requires validation" "$CONF_FILE"
    exit 2  # Manual review required

}

# Run main check
main "$@"
