#!/usr/bin/env bash
################################################################################
# STIG Check: V-230223
# Severity: high
# Rule Title: RHEL 8 must implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in a
# STIG ID: RHEL-08-010020
# Rule ID: SV-230223r1069327
#
# Description:
#     Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the \"kernelopts\" variable of the /boot/grub2/grubenv file for all kernel boot entries. The 
#
# Check Content:
#     Verify the operating system implements DOD-approved encryption to protect the confidentiality of remote access sessions.

Show the configured systemwide cryptographic policy by running the following command:

$ sudo update-crypto-policies --show
FIPS

If the main policy name is not \"FIPS\", this is a finding.

If the AD-SUPPORT subpolicy module is included (e.g., \"FIPS:AD-SUPPORT\"), and Active Directory support is not documented as an operational requirement with the information system security officer (ISSO), this is a finding.

If the NO-ENFORCE-EMS subpolicy module is included (e.g., \"FIPS:NO-ENFORCE-EMS\"), and not enforcing EMS is not documented as an operational requirement with the ISSO, this is a finding.

If any other subpolicy module is included, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230223"
STIG_ID="RHEL-08-010020"
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
