#!/usr/bin/env bash
################################################################################
# STIG Check: V-221416
# Severity: medium
# Rule Title: The Node Manager account password associated with the installation of OHS must be in accordance with DoD guidance for length, complexity, etc.
# STIG ID: OH12-1X-000176
# Rule ID: SV-221416r961863
#
# Description:
#     During installation of the web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a login screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the login even easier. Once t
#
# Check Content:
#     1. If the password for Node Manager does not meet DoD requirements for password complexity, this is a finding.

2. Open $DOMAIN_HOME/config/nodemanager/nm_password.properties with an editor.

3. If the \"username\" property and value are still present, this is a finding.

4. If the \"password\" property and value are still present, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221416"
STIG_ID="OH12-1X-000176"
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
        echo "Expected location: $DOMAIN_HOME/config/nodemanager/nm_password.properties"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Properties file not found" ""
        exit 3
    fi

    echo "INFO: Found properties file: $PROPS_FILE"
    echo ""

    # Display relevant properties
    echo "Checking for property: username"
    grep -i "username" "$PROPS_FILE" 2>/dev/null || echo "Property not found"
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify property value meets STIG requirements"
    echo "Properties file: $PROPS_FILE"
    echo "Required property: username"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Properties check requires validation" "$PROPS_FILE"
    exit 2  # Manual review required

}

# Run main check
main "$@"
