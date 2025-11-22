#!/usr/bin/env bash
################################################################################
# STIG Check: V-221429
# Severity: medium
# Rule Title: The WLST_PROPERTIES environment variable defined for the Fusion Middleware WebLogic Scripting Tool must be updated to reference an appropriate trust store so that it can communicate with the Node Mana
# STIG ID: OH12-1X-000190
# Rule ID: SV-221429r961863
#
# Description:
#     Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

When starting an OHS instance, the \"Fusion Middleware\" WebLogic Scripting Tool needs to trust the certificate presented by the Node Manager in order to setup secure communication with it.  If the \"Fusion Middleware\" WLST does not trust the certificate presented by Node Manager, the \"Fusion Middleware\" WebLogic Scripting tool will not be able to setup a secure connection to it.
#
# Check Content:
#     1. Check for the existence of $ORACLE_HOME/oracle_common/common/bin/setWlstEnv.sh.

2a. If the setWlstEnv.sh does not exist or does not contain the \"WLST_PROPERTIES\" environment variable set to a valid trust keystore containing the Certificate Authority and Chain of the Node Manager identity, this is a finding.
2b. If the setWlstenv.sh file does not exist, this is a finding.
2c. If the setWlstenv.sh file has permissions more permissive than 750, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221429"
STIG_ID="OH12-1X-000190"
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
    # Oracle HTTP Server - Permission Check

    if [[ -z "$DOMAIN_HOME" ]]; then
        if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
            DOMAIN_HOME=$(grep -i "domain_home" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d ' "')
        fi
    fi

    if [[ -z "$DOMAIN_HOME" ]]; then
        echo "ERROR: DOMAIN_HOME not set"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "DOMAIN_HOME not set" ""
        exit 3
    fi

    OHS_DIR="$DOMAIN_HOME/config/fmwconfig/components/OHS"

    if [[ ! -d "$OHS_DIR" ]]; then
        echo "ERROR: OHS directory not found: $OHS_DIR"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Directory not found" "$OHS_DIR"
        exit 3
    fi

    echo "INFO: OHS directory: $OHS_DIR"
    echo ""
    echo "Directory permissions:"
    ls -ld "$OHS_DIR"
    echo ""
    echo "File permissions (sample):"
    ls -l "$OHS_DIR" 2>/dev/null | head -10
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify permissions meet STIG requirements"
    echo "Location: $OHS_DIR"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Permission check requires validation" "$OHS_DIR"
    exit 2  # Manual review required

}

# Run main check
main "$@"
