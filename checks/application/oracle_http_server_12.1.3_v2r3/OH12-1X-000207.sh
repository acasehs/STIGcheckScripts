#!/usr/bin/env bash
################################################################################
# STIG Check: V-221445
# Severity: medium
# Rule Title: All accounts installed with the web server software and tools must have passwords assigned and default passwords changed.
# STIG ID: OH12-1X-000207
# Rule ID: SV-221445r961863
#
# Description:
#     During installation of the web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a login screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the login even easier. Once t
#
# Check Content:
#     NOTE: Service accounts or system accounts that have no login capability do not need to have passwords set or changed.

Review the web server documentation and deployment configuration to determine what non-service/system accounts were installed by the web server installation process.

Verify the passwords for these accounts have been set and/or changed from the default passwords.

Verify the SA/Web manager are notified of the changed password.

If these accounts still have no password or have default passwords, this is a finding.

If the SA/web manager does not know the changed password, this is a finding.

#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221445"
STIG_ID="OH12-1X-000207"
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
    # Oracle HTTP Server - Log Review Check

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

    LOG_DIR="$DOMAIN_HOME/servers/*/logs"

    echo "INFO: Checking for OHS log files"
    echo "Expected location: $LOG_DIR"
    echo ""

    # Find log files
    found_logs=false
    for log_pattern in "$DOMAIN_HOME"/servers/*/logs/*.log \
                       "$DOMAIN_HOME"/diagnostics/logs/*/*.log; do
        if ls $log_pattern 2>/dev/null | head -1 >/dev/null; then
            echo "Found logs:"
            ls -lh $log_pattern 2>/dev/null | head -5
            found_logs=true
            break
        fi
    done

    if [[ "$found_logs" == "false" ]]; then
        echo "WARNING: No log files found"
    fi
    echo ""

    echo "MANUAL REVIEW REQUIRED: Review log files for STIG compliance"
    echo "This check requires manual examination of log content and format"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Log review requires validation" ""
    exit 2  # Manual review required

}

# Run main check
main "$@"
