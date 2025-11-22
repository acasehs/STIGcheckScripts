#!/usr/bin/env bash
################################################################################
# STIG Check: V-207601
# Severity: medium
# Rule Title: The BIND 9.x server implementation must prohibit the forwarding of queries to servers controlled by organizations outside of the U.S. Government.
# STIG ID: BIND-9X-001702
# Rule ID: SV-207601r951092
#
# Description:
#     If remote servers to which DoD DNS servers send queries are controlled by entities outside of the U.S. Government the possibility of a DNS attack is increased. 

The Enterprise Recursive Service (ERS) provides the ability to apply enterprise-wide policy to all recursive DNS traffic that traverses the NIPRNet-to-Internet boundary. All recursive DNS servers on the NIPRNet must be configured to exclusively forward DNS traffic traversing NIPRNet-to-Internet boundary to the ERS anycast IPs.

Organiza
#
# Check Content:
#     If the server is not a caching server, this is Not Applicable.
This is Not Applicable to SIPR. 

Note: The use of the DREN Enterprise Recursive DNS (Domain Name System) servers, as mandated by the DoDIN service provider Defense Research and Engineering Network (DREN), meets the intent of this requirement. 

Verify that the server is configured to forward all DNS traffic to the DISA Enterprise Recursive Service (ERS) anycast IP addresses ( <IP_ADDRESS_LIST>; ):

Inspect the \"named.conf\" file for the following:

forward only;
forwarders { <IP_ADDRESS_LIST>; };

If the \"named.conf\" options are not set to forward queries only to the ERS anycast IPs, this is a finding.

Note: \"<IP_ADDRESS_LIST>\" should be replaced with the current ERS IP addresses.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207601"
STIG_ID="BIND-9X-001702"
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
    SVC="DoDIN"

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
