#!/usr/bin/env bash
################################################################################
# STIG Check: V-257818
# Severity: medium
# Rule Title: The kdump service on RHEL 9 must be disabled.
# STIG ID: RHEL-09-213115
# Rule ID: SV-257818r1044876
#
# Description:
#     Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition. Unless the system is used for kernel development or testing, there is little need to run the kdump service.
#
# Check Content:
#     Verify that the kdump service is disabled in system boot configuration with the following command:

$ sudo systemctl is-enabled  kdump  

disabled 

Verify that the kdump service is not active (i.e., not running) through current runtime configuration with the following command:

$ sudo systemctl is-active kdump 

masked 

Verify that the kdump service is masked with the following command:

$ sudo systemctl show  kdump  | grep \"LoadState\|UnitFileState\" 

LoadState=masked 
UnitFileState=masked 

If the \"kdump\" service is loaded or active, and is not masked, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-257818"
STIG_ID="RHEL-09-213115"
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
    SVC="kdump"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "PASS: Service running and enabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Running" "$SVC"
        exit 0
    else
        echo "FAIL: Service not running/enabled"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not running" "$SVC"
        exit 1
    fi

}

# Run main check
main "$@"
