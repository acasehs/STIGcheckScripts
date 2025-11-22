#!/usr/bin/env bash
################################################################################
# STIG Check: V-258053
# Severity: medium
# Rule Title: All RHEL 9 local interactive user home directories must be group-owned by the home directory owner'\''s primary group.
# STIG ID: RHEL-09-411070
# Rule ID: SV-258053r991589
#
# Description:
#     If the Group Identifier (GID) of a local interactive users home directory is not the same as the primary GID of the user, this would allow unauthorized access to the users files, and users that share the same group may not be able to access files that they legitimately should.
#
# Check Content:
#     Verify the assigned home directory of all local interactive users is group-owned by that user'\''s primary GID with the following command:

Note: This may miss local interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory \"/home/wadea\" is used as an example.

$ sudo ls -ld $(awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $6}'\'' /etc/passwd)

drwxr-x--- 2 wadea admin 4096 Jun 5 12:41 wadea

Check the user'\''s primary group with the following command:

$ sudo grep $(grep wadea /etc/passwd | awk -F: â€˜{print $4}'\'') /etc/group

admin:x:250:wadea,jonesj,jacksons

If the user home directory referenced in \"/etc/passwd\" is not group-owned by that user'\''s primary GID, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-258053"
STIG_ID="RHEL-09-411070"
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
    echo "Rule: All RHEL 9 local interactive user home directories must be group-owned by the home directory owner'\''s primary group."

    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Requires implementation"
    exit 3
}

# Run main check
main "$@"
