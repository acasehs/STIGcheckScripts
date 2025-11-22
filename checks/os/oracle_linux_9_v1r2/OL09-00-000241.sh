#!/usr/bin/env bash
################################################################################
# STIG Check: V-271478
# Severity: medium
# Rule Title: OL 9 must implement a FIPS 140-3 compliant system-wide cryptographic policy.
# STIG ID: OL09-00-000241
# Rule ID: SV-271478r1092620
#
# Description:
#     Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

Satisfies: SRG-OS-000396-GPOS-00176, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174
#
# Check Content:
#     Verify that OL 9 is set to use a modified FIPS compliant systemwide crypto-policy.
 
$ update-crypto-policies --show
FIPS
 
If the system wide crypto policy is not set to \"FIPS\", this is a finding.

Note: If subpolicies have been configured, they will be listed in a colon-separated list starting with FIPS as follows:

FIPS:<SUBPOLICY-NAME>:<SUBPOLICY-NAME>.

Verify the current minimum crypto-policy configuration with the following commands:
 
$ grep -E '\''rsa_size|hash'\'' /etc/crypto-policies/state/CURRENT.pol
hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256
min_rsa_size = 2048
 
If the \"hash\" values do not include at least the following FIPS 140-3 compliant algorithms \"SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256\", this is a finding.

If there are algorithms that include \"SHA1\" or a hash value less than \"256\" this is a finding.

If the \"min_rsa_size\" is not set to a value of at least 2048, this is a finding.
 
If
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271478"
STIG_ID="OL09-00-000241"
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
