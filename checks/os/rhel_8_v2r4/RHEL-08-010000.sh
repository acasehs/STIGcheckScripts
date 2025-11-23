#!/usr/bin/env bash
################################################################################
# STIG Check: V-230221
# Severity: high
# Rule Title: RHEL 8 must be a vendor-supported release.
# STIG ID: RHEL-08-010000
# Rule ID: SV-230221r1017040
#
# Description:
#     An operating system release is considered \"supported\" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Red Hat offers the Extended Update Support (EUS) add-on to a Red Hat Enterprise Linux subscription, for a fee, for those customers who wish to standardize on a specific minor release for an extended period. The RHEL 8 minor releases eligible for EUS are 8.1, 
#
# Check Content:
#     Verify the version of the operating system is vendor supported.

Note: The lifecycle time spans and dates are subject to adjustment.

Check the version of the operating system with the following command:

$ sudo cat /etc/redhat-release

Red Hat Enterprise Linux Server release 8.6 (Ootpa)

Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.

Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.

Current End of Extended Update Support for RHEL 8.4 is 31 May 2023.

Current End of Maintenance Support for RHEL 8.5 is 31 May 2022.

Current End of Extended Update Support for RHEL 8.6 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.7 is 31 May 2023.

Current End of Extended Update Support for RHEL 8.8 is 31 May 2025.

Current End of Maintenance Support for RHEL 8.9 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.

If the release is not supported by the vendor, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230221"
STIG_ID="RHEL-08-010000"
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
    # STIG Check Implementation - Manual Review Required
    #
    # This check requires manual examination of system configuration.
    # Please review the STIG requirement in the header and verify:
    # - System configuration matches STIG requirements
    # - Security controls are properly configured
    # - Compliance status is documented

    echo "INFO: Manual review required for $STIG_ID"
    echo "Rule: Check the rule title in the header above"
    echo ""
    echo "MANUAL REVIEW REQUIRED"
    echo "This STIG check requires manual verification of system configuration."
    echo "Please consult the STIG documentation for specific compliance requirements."

    [[ -n "$OUTPUT_JSON" ]] && output_json "Not_Reviewed" "Manual review required" "Consult STIG documentation for compliance requirements"
    exit 2  # Manual review required

}

# Run main check
main "$@"
