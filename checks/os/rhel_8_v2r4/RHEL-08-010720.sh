#!/usr/bin/env bash
################################################################################
# STIG Check: V-230320
# Severity: medium
# Rule Title: All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file.
# STIG ID: RHEL-08-010720
# Rule ID: SV-230320r1017131
#
# Description:
#     If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
#
# Check Content:
#     Verify local interactive users on RHEL 8 have a home directory assigned with the following command:

$ sudo pwck -r

user '\''lp'\'': directory '\''/var/spool/lpd'\'' does not exist
user '\''news'\'': directory '\''/var/spool/news'\'' does not exist
user '\''uucp'\'': directory '\''/var/spool/uucp'\'' does not exist
user '\''www-data'\'': directory '\''/var/www'\'' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

$ sudo awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}'\'' /etc/passwd

If any interactive users do not have a home directory assigned, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-230320"
STIG_ID="RHEL-08-010720"
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
    echo "Rule: All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file."

    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Requires implementation"
    exit 3
}

# Run main check
main "$@"
