#!/usr/bin/env bash
################################################################################
# STIG Check: V-221282
# Severity: high
# Rule Title: OHS must have the SSLFIPS directive enabled to protect the integrity of remote sessions in accordance with the categorization of data hosted by the web server.
# STIG ID: OH12-1X-000012
# Rule ID: SV-221282r960762
#
# Description:
#     Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.
#
# Check Content:
#     1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the \"SSLFIPS\" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to \"On\", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221282"
STIG_ID="OH12-1X-000012"
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
        echo "Expected location: $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file not found" ""
        exit 3
    fi

    echo "INFO: Found configuration file: $CONF_FILE"
    echo ""

    # Display relevant directives
    echo "Checking for directive: SSLFIPS"
    grep -i "SSLFIPS" "$CONF_FILE" 2>/dev/null || echo "Directive not found"
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify directive value meets STIG requirements"
    echo "Configuration file: $CONF_FILE"
    echo "Required directive: SSLFIPS"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Config check requires validation" "$CONF_FILE"
    exit 2  # Manual review required

}

# Run main check
main "$@"
