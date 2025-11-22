#!/usr/bin/env bash
################################################################################
# STIG Check: V-270558
# Severity: medium
# Rule Title: Oracle Database must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Cat
# STIG ID: O19C-00-013500
# Rule ID: SV-270558r1065283
#
# Description:
#     To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Ad
#
# Check Content:
#     Review the database management system (DBMS) settings for unapproved functions, ports, protocols, and services.

If any are found, this is a finding.

For definitive information on PPSM, refer to https://cyber.mil/ppsm/.

- - - - -

In the Oracle database, the communications with the database and incoming requests are performed by the Oracle Listener. The Oracle Listener listens on a specific port or ports for connections to a specific database. The Oracle Listener has configuration files located in the $ORACLE_HOME/network/admin directory. To check the ports and protocols in use, go to that directory and review the SQLNET.ora, LISTENER.ora, and the TNSNAMES.ora. If protocols or ports are in use that are not authorized, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270558"
STIG_ID="O19C-00-013500"
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
    SVC="and"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi

}

# Run main check
main "$@"
