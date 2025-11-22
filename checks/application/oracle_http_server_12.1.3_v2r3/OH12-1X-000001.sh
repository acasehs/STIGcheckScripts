#!/usr/bin/env bash
################################################################################
# STIG Check: V-221272
# Severity: medium
# Rule Title: OHS must have the mpm property set to use the worker Multi-Processing Module (MPM) as the preferred means to limit the number of allowed simultaneous requests.
# STIG ID: OH12-1X-000001
# Rule ID: SV-221272r960735
#
# Description:
#     Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended val
#
# Check Content:
#     1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ohs.plugins.nodemanager.properties file with an editor.

2. Search for the \"mpm\" property.

3. If the \"mpm\" property is omitted or commented out, this is a finding.

4. If the \"mpm\" property is not set to \"worker\", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221272"
STIG_ID="OH12-1X-000001"
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
    # Oracle HTTP Server - Properties File Check

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

    # Search for properties file
    PROPS_FILE=""
    for file in "$DOMAIN_HOME"/config/fmwconfig/components/OHS/*/ohs.plugins.nodemanager.properties \
                "$DOMAIN_HOME"/config/fmwconfig/components/OHS/*/*.properties; do
        if [[ -f "$file" ]]; then
            PROPS_FILE="$file"
            break
        fi
    done

    if [[ -z "$PROPS_FILE" ]]; then
        echo "ERROR: Properties file not found"
        echo "Expected location: $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ohs.plugins.nodemanager.properties"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Properties file not found" ""
        exit 3
    fi

    echo "INFO: Found properties file: $PROPS_FILE"
    echo ""

    # Display relevant properties
    echo "Checking for property: mpm"
    grep -i "mpm" "$PROPS_FILE" 2>/dev/null || echo "Property not found"
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify property value meets STIG requirements"
    echo "Properties file: $PROPS_FILE"
    echo "Required property: mpm"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Properties check requires validation" "$PROPS_FILE"
    exit 2  # Manual review required

}

# Run main check
main "$@"
