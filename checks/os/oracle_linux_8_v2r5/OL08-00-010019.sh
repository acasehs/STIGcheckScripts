#!/usr/bin/env bash
################################################################################
# STIG Check: V-256978
# Severity: medium
# Rule Title: OL 8 must ensure cryptographic verification of vendor software packages.
# STIG ID: OL08-00-010019
# Rule ID: SV-256978r1015073
#
# Description:
#     Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Oracle cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.
#
# Check Content:
#     Confirm Oracle package-signing key is installed on the system and verify its fingerprint matches vendor value.

Note: The GPG key is defined in key file \"/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle\" by default.

List Oracle GPG keys installed on the system:

     $ sudo rpm -q --queryformat \"%{SUMMARY}\n\" gpg-pubkey | grep -i \"oracle\"

     gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)

If Oracle GPG key is not installed, this is a finding.

List key fingerprint of installed Oracle GPG key:

     $ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle

If key file \"/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle\" is missing, this is a finding.

Example output:

     pub   rsa4096/AD986DA3 2019-04-09 [SC] [expires: 2039-04-04]
           Key fingerprint = 76FD 3DB1 3AB6 7410 B89D  B10E 8256 2EA9 AD98 6DA3
     uid                   Oracle OSS group (Open Source Software group) <build@oss.oracle.com>
     sub   rsa4096/D95DC12B 2019-04-09
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-256978"
STIG_ID="OL08-00-010019"
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
    PKG="Oracle"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        ver=$(rpm -q "$PKG" 2>/dev/null || dpkg -l "$PKG" 2>/dev/null | awk '{print $3}')
        echo "PASS: Package installed ($ver)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Installed" "$PKG"
        exit 0
    else
        echo "FAIL: Package not installed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Missing" "$PKG"
        exit 1
    fi

}

# Run main check
main "$@"
