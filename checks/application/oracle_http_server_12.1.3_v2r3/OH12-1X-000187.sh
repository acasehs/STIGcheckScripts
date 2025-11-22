#!/usr/bin/env bash
################################################################################
# STIG Check: V-221426
# Severity: medium
# Rule Title: The listen-address element defined within the config.xml of the OHS Standalone domain that supports OHS must be configured for secure communication.
# STIG ID: OH12-1X-000187
# Rule ID: SV-221426r961863
#
# Description:
#     Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

When starting an OHS instance, the WebLogic Scripting Tool reads the parameters within the config.xml file to setup the communication to the Node Manager.  If the IP address to be used for communication is not specified, the WebLogic Scripting tool will not be able to setup a secure connection to Node Manager.
#
# Check Content:
#     1. Open $DOMAIN_HOME/config/config.xml with an editor.

2. Search for the \"<listen-address>\" element within the \"<node-manager>\" element.

3. If the element does not exist or is not set to the CN of the Node Manager certificate, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221426"
STIG_ID="OH12-1X-000187"
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
    # Oracle HTTP Server - Generic Configuration Check

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

    echo "INFO: Oracle HTTP Server configuration check"
    echo "DOMAIN_HOME: $DOMAIN_HOME"
    echo ""

    # Check if OHS is configured
    OHS_DIR="$DOMAIN_HOME/config/fmwconfig/components/OHS"
    if [[ -d "$OHS_DIR" ]]; then
        echo "OHS directory found: $OHS_DIR"
        echo "Components:"
        ls -1 "$OHS_DIR" 2>/dev/null || echo "No components found"
    else
        echo "WARNING: OHS directory not found at expected location"
    fi
    echo ""

    echo "MANUAL REVIEW REQUIRED: Review Oracle HTTP Server configuration"
    echo "This check requires manual examination of OHS settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "OHS check requires validation" "$DOMAIN_HOME"
    exit 2  # Manual review required

}

# Run main check
main "$@"
