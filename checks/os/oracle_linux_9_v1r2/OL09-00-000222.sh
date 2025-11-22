#!/usr/bin/env bash
################################################################################
# STIG Check: V-271471
# Severity: medium
# Rule Title: OL 9 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (C
# STIG ID: OL09-00-000222
# Rule ID: SV-271471r1091125
#
# Description:
#     To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary ports, protocols, and services on information systems.
#
# Check Content:
#     Verify OL 9 is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited. 

Inspect the firewall configuration and running services to verify which services are currently active with the following command:

$ sudo firewall-cmd --list-all-zones
custom (active)
target: DROP
icmp-block-inversion: no
interfaces: ens33
sources: 
services: dhcpv6-client dns http https ldaps rpc-bind ssh
ports: 
masquerade: no
forward-ports: 
icmp-blocks: 
rich rules: 

Ask the system administrator for the site or program PPSM Component Local Service Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271471"
STIG_ID="OL09-00-000222"
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
    SVC="or"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "PASS: Service running and enabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Running" "$SVC"
        exit 0
    else
        echo "FAIL: Service not running/enabled"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not running" "$SVC"
        exit 1
    fi

}

# Run main check
main "$@"
