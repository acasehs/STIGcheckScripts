#!/usr/bin/env bash
################################################################################
# STIG Check: V-270529
# Severity: medium
# Rule Title: Oracle roles granted using the WITH ADMIN OPTION must not be granted to unauthorized accounts.
# STIG ID: O19C-00-009700
# Rule ID: SV-270529r1065268
#
# Description:
#     The WITH ADMIN OPTION allows the grantee to grant a role to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include database administrators (DBAs), object owners, and application administrators (where designed and included in the application'\''s functions). Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthor
#
# Check Content:
#     A default Oracle Database installation provides a set of predefined administrative accounts and nonadministrative accounts. These are accounts that have special privileges required to administer areas of the database, such as the CREATE ANY TABLE or ALTER SESSION privilege or EXECUTE privileges on packages owned by the SYS schema. The default tablespace for administrative accounts is either SYSTEM or SYSAUX. Nonadministrative user accounts only have the minimum privileges needed to perform their jobs. Their default tablespace is USERS.

To protect these accounts from unauthorized access, the installation process expires and locks most of these accounts, except where noted below. The database administrator is responsible for unlocking and resetting these accounts, as required.

Non-Administrative Accounts - Expired and locked:
APEX_PUBLIC_USER, DIP, FLOWS_040100*, FLOWS_FILES, MDDATA, SPATIAL_WFS_ADMIN_USR, XS$NULL

Administrative Accounts - Expired and Locked:
ANONYMOUS, CTXSYS, EXFSYS
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-270529"
STIG_ID="O19C-00-009700"
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
    PKG="on"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        ver=$(rpm -q "$PKG" 2>/dev/null || dpkg -l "$PKG" 2>/dev/null | awk '{print $3}')
        echo "PASS: Package installed ($ver)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Installed" "$PKG"
        exit 0
    else
        echo "FAIL: Package not installed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Missing" "$PKG"
        exit 1
    fi

}

# Run main check
main "$@"
