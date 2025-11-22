#!/usr/bin/env bash
################################################################################
# STIG Check: V-230255
# Severity: medium
# Rule Title: The RHEL 8 operating system must implement DoD-approved TLS encryption in the OpenSSL package.
# STIG ID: RHEL-08-010294
# Rule ID: SV-230255r1017075
#
# Description:
#     Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash funct
#
# Check Content:
#     Verify the OpenSSL library is configured to use only DoD-approved TLS encryption:

For versions prior to crypto-policies-20210617-1.gitc776d3e.el8.noarch:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

MinProtocol = TLSv1.2

If the \"MinProtocol\" is set to anything older than \"TLSv1.2\", this is a finding.

For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2

If the \"TLS.MinProtocol\" is set to anything older than \"TLSv1.2\" or the \"DTLS.MinProtocol\" is set to anything older than DTLSv1.2, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230255"
STIG_ID="RHEL-08-010294"
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
    CONFIG="/etc/crypto-policies/back-ends/opensslcnf.config"

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
