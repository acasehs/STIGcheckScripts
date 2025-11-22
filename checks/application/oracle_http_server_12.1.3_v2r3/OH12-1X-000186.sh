#!/usr/bin/env bash
################################################################################
# STIG Check: V-221425
# Severity: medium
# Rule Title: The CustomIdentityPrivateKeyPassPhrase property of the Node Manager configured to support OHS must be configured for secure communication.
# STIG ID: OH12-1X-000186
# Rule ID: SV-221425r961863
#
# Description:
#     Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

The \"CustomIdentityPrivateKeyPassPhrase\" is the password that protects the private key when creating certificates.  If a password is not used, the private key is not protected and can be used by any user or attacker that can get access to the private key.
#
# Check Content:
#     1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the \"CustomIdentityPrivateKeyPassPhrase\" property.

3. If the property does not exist or is set improperly, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221425"
STIG_ID="OH12-1X-000186"
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
        echo "Expected location: $DOMAIN_HOME/nodemanager/nodemanager.properties"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Properties file not found" ""
        exit 3
    fi

    echo "INFO: Found properties file: $PROPS_FILE"
    echo ""

    # Display relevant properties
    echo "Checking for property: CustomIdentityPrivateKeyPassPhrase"
    grep -i "CustomIdentityPrivateKeyPassPhrase" "$PROPS_FILE" 2>/dev/null || echo "Property not found"
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify property value meets STIG requirements"
    echo "Properties file: $PROPS_FILE"
    echo "Required property: CustomIdentityPrivateKeyPassPhrase"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Properties check requires validation" "$PROPS_FILE"
    exit 2  # Manual review required

}

# Run main check
main "$@"
