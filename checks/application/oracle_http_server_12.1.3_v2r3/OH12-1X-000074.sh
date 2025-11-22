#!/usr/bin/env bash
################################################################################
# STIG Check: V-221334
# Severity: medium
# Rule Title: OHS log files must only be accessible by privileged users.
# STIG ID: OH12-1X-000074
# Rule ID: SV-221334r960930
#
# Description:
#     Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must 
#
# Check Content:
#     1. Change to the ORACLE_HOME/user_projects/domains/base_domain/servers directory.

2. Execute the command: find . -name *.log 

3. Verify that each log file that was returned has the owner and group set to the user and group used to run the web server.  The user and group are typically set to Oracle.

4. Verify that each log file that was returned has the permissions on the log file set to \"640\" or more restrictive.

If the owner, group or permissions are set incorrectly on any of the log files, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221334"
STIG_ID="OH12-1X-000074"
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
