#!/usr/bin/env bash
################################################################################
# STIG Check: V-221470
# Severity: low
# Rule Title: OHS hosted web sites must utilize ports, protocols, and services according to PPSM guidelines.
# STIG ID: OH12-1X-000233
# Rule ID: SV-221470r961863
#
# Description:
#     Failure to comply with DoD ports, protocols, and services (PPS) requirements can result in compromise of enclave boundary protections and/or functionality of the automated information system (AIS).

The ISSM will ensure web servers are configured to use only authorized PPS in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1, Ports, Protocols, and Services Management (PPSM), and the associated Ports, Protocols, and Services (PPS) Assurance Category Assignments List.
#
# Check Content:
#     1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the \"Listen\" directive at the OHS server configuration scope.

3. If the \"Listen\" directive port specified is not \"80\" or \"443\", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221470"
STIG_ID="OH12-1X-000233"
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
