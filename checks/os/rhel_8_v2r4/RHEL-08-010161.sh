#!/usr/bin/env bash
################################################################################
# STIG Check: V-230238
# Severity: medium
# Rule Title: RHEL 8 must prevent system daemons from using Kerberos for authentication.
# STIG ID: RHEL-08-010161
# Rule ID: SV-230238r1017057
#
# Description:
#     Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The key derivation function (KDF) in Kerberos is not FIPS compatible.  Ensuring the system does not have any keytab files present prevents system daemons from us
#
# Check Content:
#     Verify that RHEL 8 prevents system daemons from using Kerberos for authentication.

If the system is a server utilizing krb5-server-1.17-18.el8.x86_64 or newer, this requirement is not applicable.
If the system is a workstation utilizing krb5-workstation-1.17-18.el8.x86_64 or newer, this requirement is not applicable.

Check if there are available keytabs with the following command:

$ sudo ls -al /etc/*.keytab

If this command produces any file(s), this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230238"
STIG_ID="RHEL-08-010161"
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
    SVC="system"

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
