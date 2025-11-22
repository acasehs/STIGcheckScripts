#!/usr/bin/env bash
################################################################################
# STIG Check: V-248843
# Severity: medium
# Rule Title: OL 8 Bluetooth must be disabled.
# STIG ID: OL08-00-040111
# Rule ID: SV-248843r991569
#
# Description:
#     Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and read, altered, or used to compromise the OL 8 operating system. 
 
This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with OL 8 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice, and pointing devices and Near Field Communications [NFC]) presen
#
# Check Content:
#     If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of Bluetooth is a local AO decision.

Determine if Bluetooth is disabled with the following command:

     $ sudo grep -r bluetooth /etc/modprobe.d
     /etc/modprobe.d/bluetooth.conf:install bluetooth /bin/false

If the command does not return any output or the line is commented out and the collaborative computing device has not been authorized for use, this is a finding.

Verify the operating system disables the ability to use Bluetooth with the following command:  
 
     $ sudo grep -r bluetooth /etc/modprobe.d | grep -i \"blacklist\" | grep -v \"^#\" 
     blacklist bluetooth 
 
If the command does not return any output or the output is not \"blacklist bluetooth\", and use of Bluetooth is not documented with the Information System Security Officer (ISSO) as an operational re
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248843"
STIG_ID="OL08-00-040111"
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
    CONFIG="/etc/modprobe.d"

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
