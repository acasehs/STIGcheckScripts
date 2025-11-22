#!/usr/bin/env bash
################################################################################
# STIG Check: V-214274
# Severity: medium
# Rule Title: The Apache web server htpasswd files (if present) must reflect proper ownership and permissions.
# STIG ID: AS24-U1-000970
# Rule ID: SV-214274r961863
#
# Description:
#     In addition to OS restrictions, access rights to files and directories can be set on a website using the web server software. That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights. For example, users can be given read-only access rights to files to view the information but not change the files.

This check verifies that theÂ htpasswdÂ file is only accessible by System Administrators (SAs) or Web Managers, with the accou
#
# Check Content:
#     Locate the htpasswd file by entering the following command:

find / -name htpasswd

Navigate to that directory.

Run: ls -l htpasswd

Permissions should be: r-x r - x - - - (550)

If permissions on \"htpasswd\" are greater than \"550\", this is a finding.

Verify the owner is the SA or Web Manager account.

If another account has access to this file, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214274"
STIG_ID="AS24-U1-000970"
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
    # Locate Apache configuration directory
    HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i 'HTTPD_ROOT' | cut -d'"' -f2)

    if [[ -z "$HTTPD_ROOT" ]]; then
        echo "ERROR: Unable to locate Apache root directory"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not configured" ""
        exit 3
    fi

    if [[ ! -d "$HTTPD_ROOT" ]]; then
        echo "ERROR: Apache root directory not found: $HTTPD_ROOT"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Directory missing" "$HTTPD_ROOT"
        exit 3
    fi

    # Check permissions
    perms=$(ls -ld "$HTTPD_ROOT" 2>/dev/null)

    echo "INFO: Directory permissions:"
    echo "$perms"

    echo "MANUAL REVIEW REQUIRED: Verify permissions meet STIG requirements"
    echo "Location: $HTTPD_ROOT"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Permission check requires validation" "$perms"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
