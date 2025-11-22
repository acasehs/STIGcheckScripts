#!/usr/bin/env bash
################################################################################
# STIG Check: V-258051
# Severity: medium
# Rule Title: All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file.
# STIG ID: RHEL-09-411060
# Rule ID: SV-258051r991589
#
# Description:
#     If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
#
# Check Content:
#     Verify that interactive users on the system have a home directory assigned with the following command:
 
$ sudo awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}'\'' /etc/passwd

smithk:x:1000:1000:smithk:/home/smithk:/bin/bash
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Inspect the output and verify that all interactive users (normally users with a user identifier (UID) greater that 1000) have a home directory defined.

If users home directory is not defined, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258051"
STIG_ID="RHEL-09-411060"
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
    # TODO: Implement actual STIG check logic
    # This placeholder will be replaced with actual implementation

    echo "TODO: Implement check logic for $STIG_ID"
    echo "Rule: All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file."

    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Requires implementation"
    exit 3
}

# Run main check
main "$@"
