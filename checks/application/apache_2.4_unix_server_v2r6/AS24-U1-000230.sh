#!/usr/bin/env bash
################################################################################
# STIG Check: V-214238
# Severity: medium
# Rule Title: Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.
# STIG ID: AS24-U1-000230
# Rule ID: SV-214238r1016509
#
# Description:
#     In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website. The process of developing on a functional production website entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and l
#
# Check Content:
#     Enter the following command:

\"httpd -M\"

This will provide a list of the loaded modules. Validate that all displayed modules are required for operations.

If any module is not required for operation, this is a finding.

Note: The following modules are needed for basic web function and do not need to be reviewed:

core_module
http_module
so_module
mpm_prefork_module

For a complete list of signed Apache Modules, review https://httpd.apache.org/docs/2.4/mod/.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214238"
STIG_ID="AS24-U1-000230"
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
    # Check Apache modules
    if ! command -v apachectl &>/dev/null; then
        echo "ERROR: apachectl command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not installed" ""
        exit 3
    fi

    # List loaded modules
    modules=$(apachectl -M 2>/dev/null || httpd -M 2>/dev/null)

    if [[ -z "$modules" ]]; then
        echo "ERROR: Unable to list Apache modules"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Cannot list modules" ""
        exit 3
    fi

    echo "MANUAL REVIEW REQUIRED: Verify required modules are loaded"
    echo "Loaded modules:"
    echo "$modules"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Module check requires validation" "$modules"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
