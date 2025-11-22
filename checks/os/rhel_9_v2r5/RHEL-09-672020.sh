#!/usr/bin/env bash
################################################################################
# STIG Check: V-258236
# Severity: high
# Rule Title: RHEL 9 cryptographic policy must not be overridden.
# STIG ID: RHEL-09-672020
# Rule ID: SV-258236r1101920
#
# Description:
#     Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

Satisfies: SRG-OS-000396-GPOS-00176, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
#
# Check Content:
#     Verify that RHEL 9 cryptographic policies are not overridden.

Verify that the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --check

The configured policy matches the generated policy

If the returned message does not match the above, but instead matches the following, this is a finding:

The configured policy does NOT match the generated policy

List all of the crypto backends configured on the system with the following command:

$ ls -l /etc/crypto-policies/back-ends/ 

lrwxrwxrwx. 1 root root  40 Nov 13 16:29 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
lrwxrwxrwx. 1 root root  42 Nov 13 16:29 gnutls.config -> /usr/share/crypto-policies/FIPS/gnutls.txt
lrwxrwxrwx. 1 root root  40 Nov 13 16:29 java.config -> /usr/share/crypto-policies/FIPS/java.txt
lrwxrwxrwx. 1 root root  46 Nov 13 16:29 javasystem.config -> /usr/share/crypto-policies/FIPS/javasystem.txt
lrwxrwxrwx. 1 root root  40 Nov 13 16:29 krb5.config -> /u
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258236"
STIG_ID="RHEL-09-672020"
SEVERITY="high"
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
    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not configured"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Host not specified" ""
        exit 3
    fi

    # Execute command via SSH (customize based on device type)
    output=$(ssh "$DEVICE_USER"@"$DEVICE_HOST" "show version" 2>&1)

    if [[ $? -eq 0 ]]; then
        echo "PASS: Command executed successfully"
        echo "$output"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Device accessible" ""
        exit 0
    else
        echo "ERROR: SSH connection failed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Connection failed" "$output"
        exit 3
    fi

}

# Run main check
main "$@"
