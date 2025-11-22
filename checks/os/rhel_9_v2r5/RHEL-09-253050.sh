#!/usr/bin/env bash
################################################################################
# STIG Check: V-257965
# Severity: medium
# Rule Title: RHEL 9 must use a reverse-path filter for IPv4 network traffic when possible by default.
# STIG ID: RHEL-09-253050
# Rule ID: SV-257965r1106333
#
# Description:
#     Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks, but is helpful for end hosts and routers serving small networks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of the directories in which 
#
# Check Content:
#     Verify RHEL 9 uses reverse path filtering on IPv4 interfaces with the following commands:

$ sudo sysctl net.ipv4.conf.default.rp_filter

net.ipv4.conf.default.rp_filter = 1

If the returned line does not have a value of \"1\", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.rp_filter /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:net.ipv4.conf.default.rp_filter = 1

If \"net.ipv4.conf.default.rp_filter\" is not set to \"1\" or is missing, this is a finding.

If conflicting results are returned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257965"
STIG_ID="RHEL-09-253050"
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
    PARAM="net.ipv"
    EXPECTED="1"

    actual=$(sysctl -n "$PARAM" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        echo "ERROR: Parameter not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not found" "$PARAM"
        exit 3
    fi

    if [[ "$actual" == "$EXPECTED" ]]; then
        echo "PASS: $PARAM = $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$PARAM=$actual"
        exit 0
    else
        echo "FAIL: $PARAM = $actual (expected: $EXPECTED)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Mismatch" "Expected: $EXPECTED"
        exit 1
    fi

}

# Run main check
main "$@"
