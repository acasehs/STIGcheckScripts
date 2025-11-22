#!/usr/bin/env bash
################################################################################
# STIG Check: V-257958
# Severity: medium
# Rule Title: RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.
# STIG ID: RHEL-09-253015
# Rule ID: SV-257958r1106319
#
# Description:
#     ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host'\''s route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of the directories in which they reside. If multiple fil
#
# Check Content:
#     Verify RHEL 9 ignores IPv4 ICMP redirect messages.

Check the value of the \"accept_redirects\" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_redirects = 0

If \"net.ipv4.conf.all.accept_redirects\" is not set to \"0\", is missing, or commented out, this is a finding.

If conflicting results are returned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257958"
STIG_ID="RHEL-09-253015"
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
    EXPECTED="0"

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
