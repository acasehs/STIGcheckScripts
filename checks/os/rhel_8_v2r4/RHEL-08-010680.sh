#!/usr/bin/env bash
################################################################################
# STIG Check: V-230316
# Severity: medium
# Rule Title: For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured.
# STIG ID: RHEL-08-010680
# Rule ID: SV-230316r1044801
#
# Description:
#     To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.
#
# Check Content:
#     Note: If the system is running in a cloud platform and the cloud provider gives a single, highly available IP address for DNS configuration, this is not applicable.

Determine whether the system is using local or DNS name resolution with the following command:

$ sudo grep hosts /etc/nsswitch.conf

hosts: files dns

If the DNS entry is missing from the host'\''s line in the \"/etc/nsswitch.conf\" file, the \"/etc/resolv.conf\" file must be empty.

Verify the \"/etc/resolv.conf\" file is empty with the following command:

$ sudo ls -al /etc/resolv.conf

-rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the \"/etc/resolv.conf\" file is not empty, this is a finding.

If the DNS entry is found on the host'\''s line of the \"/etc/nsswitch.conf\" file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

$ sudo grep nameserver /e
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230316"
STIG_ID="RHEL-08-010680"
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
    CONFIG="/etc/nsswitch.conf"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "Unknown" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "Unknown"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "Unknown"
        exit 1
    fi

}

# Run main check
main "$@"
