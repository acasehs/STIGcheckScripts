#!/usr/bin/env bash
################################################################################
# STIG Check: V-271484
# Severity: medium
# Rule Title: The OL 9 SSH daemon must be configured to use systemwide cryptographic policies.
# STIG ID: OL09-00-000252
# Rule ID: SV-271484r1092624
#
# Description:
#     Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functi
#
# Check Content:
#     Verify that OL 9 is configured to implement systemwide cryptographic policies when the SSH daemon is invoked.

Verify that systemwide cryptographic policies are in effect with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*include'\''
/etc/ssh/sshd_config:Include /etc/ssh/sshd_config.d/*.conf
/etc/ssh/sshd_config.d/50-redhat.conf:Include /etc/crypto-policies/back-ends/opensshserver.config

If \"Include /etc/ssh/sshd_config.d/*.conf\" or \"Include /etc/crypto-policies/back-ends/opensshserver.config\" are not included in the system sshd config this is a finding. 

Additionally, if the file /etc/ssh/sshd_config.d/50-redhat.conf is missing, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271484"
STIG_ID="OL09-00-000252"
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
    SVC="SSH"

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
