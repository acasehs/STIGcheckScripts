#!/usr/bin/env bash
################################################################################
# STIG Check: V-248836
# Severity: medium
# Rule Title: The OL 8 file system automounter must be disabled unless required.
# STIG ID: OL08-00-040070
# Rule ID: SV-248836r958498
#
# Description:
#     Verify the operating system disables the ability to automount devices. 
 
Determine if automounter service is active with the following command: 
 
$ sudo systemctl status autofs 
 
autofs.service - Automounts filesystems on demand 
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled) 
Active: inactive (dead) 
 
If the \"autofs\" status is set to \"active\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
#
# Check Content:
#     Verify the operating system disables the ability to automount devices. 
 
Determine if the automounter service is active with the following command: 
 
$ sudo systemctl status autofs 
 
autofs.service - Automounts filesystems on demand 
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled) 
Active: inactive (dead) 
 
If the \"autofs\" status is set to \"active\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248836"
STIG_ID="OL08-00-040070"
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
    SVC="automounter"

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
