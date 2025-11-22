#!/usr/bin/env bash
################################################################################
# STIG Check: V-256973
# Severity: medium
# Rule Title: RHEL 8 must ensure cryptographic verification of vendor software packages.
# STIG ID: RHEL-08-010019
# Rule ID: SV-256973r1017373
#
# Description:
#     Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Red Hat cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.
#
# Check Content:
#     Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For RHEL 8 software packages, Red Hat uses GPG keys labeled \"release key 2\" and \"auxiliary key 2\". The keys are defined in key file \"/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release\" by default.

List Red Hat GPG keys installed on the system:

     $ sudo rpm -q --queryformat \"%{SUMMARY}\n\" gpg-pubkey | grep -i \"red hat\"

     gpg(Red Hat, Inc. (release key 2) <security@redhat.com>)
     gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)

If Red Hat GPG keys \"release key 2\" and \"auxiliary key 2\" are not installed, this is a finding.

Note: The \"auxiliary key 2\" appears as \"auxiliary key\" on a RHEL 8 system.

List key fingerprints of installed Red Hat GPG keys:

     $ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

If key file \"/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release\" is missing, this is a fi
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-256973"
STIG_ID="RHEL-08-010019"
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
    PKG="Hat"

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
