#!/usr/bin/env bash
################################################################################
# STIG Check: V-271481
# Severity: high
# Rule Title: OL 9 cryptographic policy files must match files shipped with the operating system.
# STIG ID: OL09-00-000244
# Rule ID: SV-271481r1091155
#
# Description:
#     The OL 9 package crypto-policies defines the cryptography policies for the system.

If the files are changed from those shipped with the operating system, it may be possible for OL 9 to use cryptographic functions that are not FIPS 140-3 approved.

Satisfies: SRG-OS-000478-GPOS-00223, SRG-OS-000396-GPOS-00176
#
# Check Content:
#     Verify that OL 9 crypto-policies package has not been modified with the following command:

$ rpm -V crypto-policies

If the command has any output, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271481"
STIG_ID="OL09-00-000244"
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
    PKG="policies"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL: Prohibited package present"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not be installed" "$PKG"
        exit 1
    else
        echo "PASS: Package not installed (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Not present" "$PKG"
        exit 0
    fi

}

# Run main check
main "$@"
