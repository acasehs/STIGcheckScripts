#!/usr/bin/env bash
################################################################################
# STIG Check: V-257967
# Severity: medium
# Rule Title: RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.
# STIG ID: RHEL-09-253060
# Rule ID: SV-257967r1106337
#
# Description:
#     Some routers will send responses to broadcast frames that violate RFC-1122, which fills up a log file system with many useless error messages. An attacker may take advantage of this and attempt to flood the logs with bogus error logs. Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regar
#
# Check Content:
#     The runtime status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter can be queried by running the following command:

$ sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses 

net.ipv4.icmp_ignore_bogus_error_responses = 1

If \"net.ipv4.icmp_ignore_bogus_error_responses\" is not set to \"1\", this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.icmp_ignore_bogus_error_response /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:net.ipv4.icmp_ignore_bogus_error_responses = 1

If \"net.ipv4.icmp_ignore_bogus_error_response\" is not set to \"1\" or is missing, this is a finding.

If conflicting results are returned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257967"
STIG_ID="RHEL-09-253060"
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
