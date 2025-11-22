#!/usr/bin/env bash
################################################################################
# STIG Check: V-257841
# Severity: medium
# Rule Title: RHEL 9 must have the rng-tools package installed.
# STIG ID: RHEL-09-215090
# Rule ID: SV-257841r1044914
#
# Description:
#     \"rng-tools\" provides hardware random number generator tools, such as those used in the formation of x509/PKI certificates.
#
# Check Content:
#     Verify that RHEL 9 has the rng-tools package installed with the following command:

$ dnf list --installed rng-tools

Example output:

rng-tools.x86_64          6.14-2.git.b2b7934e.el9

If the \"rng-tools\" package is not installed, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257841"
STIG_ID="RHEL-09-215090"
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
    PKG="tools"

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
