#!/usr/bin/env bash
################################################################################
# STIG Check: V-207570
# Severity: medium
# Rule Title: Permissions assigned to the DNSSEC keys used with the BIND 9.x implementation must enforce read-only access to the key owner and deny access to all other users.
# STIG ID: BIND-9X-001132
# Rule ID: SV-207570r879642
#
# Description:
#     Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiali
#
# Check Content:
#     If the server is in a classified network, this is Not Applicable.

Verify permissions assigned to the DNSSEC keys enforce read-only access to the key owner and deny access to group or system users:

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation:

# ls â€“al <DNSSEC_Key_Location>
-r--------. 1 named named 76 May 10 20:35 DNSSEC-example.key

If the key files are more permissive than 400, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-207570"
STIG_ID="BIND-9X-001132"
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
    # Locate BIND directories
    NAMED_DIRS=("/etc/named" "/var/named" "/etc/bind" "/var/named/chroot")

    found_dir=""
    for dir in "${NAMED_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            found_dir="$dir"
            break
        fi
    done

    if [[ -z "$found_dir" ]]; then
        echo "ERROR: BIND directory not found in standard locations"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Directory not found" ""
        exit 3
    fi

    echo "INFO: BIND directory found: $found_dir"
    echo ""
    echo "Directory permissions:"
    ls -ld "$found_dir"
    echo ""
    echo "File permissions:"
    ls -l "$found_dir" | head -10
    echo ""

    echo "MANUAL REVIEW REQUIRED: Verify permissions meet STIG requirements"
    echo "Location: $found_dir"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Permission check requires validation" "$found_dir"
    exit 2  # Manual review required

}

# Run main check
main "$@"
