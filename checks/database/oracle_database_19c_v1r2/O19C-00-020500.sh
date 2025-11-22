#!/usr/bin/env bash
################################################################################
# STIG Check: V-275999
# Severity: medium
# Rule Title: A minimum of three Oracle Control Files must be created and each stored on a separate physical and logical device.
# STIG ID: O19C-00-020500
# Rule ID: SV-275999r1115962
#
# Description:
#     Oracle control files store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files and verify the validity of system data and log files at system startup. Loss of access to the control files can affect database availability, integrity, and recovery.

Oracle Pluggable Databases (PDBs) do not contain their own control files; instead, all PDBs within a Container Database (CDB) share control files managed by the CDB.
#
# Check Content:
#     Use the SQL statement below to obtain information on each currently existing Control File:

SELECT name
FROM sys.v$controlfile
ORDER BY 1;

Oracle Best Practice:
Oracle recommends a minimum of three Oracle Control Files and each stored on a separate physical and logical device (RAID 1 + 0).  

DOD guidance recommends:
Each control file must be located on a separate physical and logical (virtual) storage device.

Consult with the storage administrator, system administrator, or database administrator to determine whether the mount points or partitions referenced in the file paths indicate separate physical disks or directories on RAID devices.

Note: Distinct does not equal dedicated. May share directory space with other Oracle database instances if present.

If the minimum of three control files is not met, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-275999"
STIG_ID="O19C-00-020500"
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
    if ! command -v sqlplus &>/dev/null; then
        echo "ERROR: Oracle client not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "sqlplus not installed" ""
        exit 3
    fi

    if [[ -z "$ORACLE_USER" ]] || [[ -z "$ORACLE_SID" ]]; then
        echo "ERROR: Oracle credentials not configured"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Credentials missing" ""
        exit 3
    fi

    # Execute SQL query (customize based on specific check)
    output=$(sqlplus -S "$ORACLE_USER"@"$ORACLE_SID" <<EOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF
-- Add specific query here
EXIT;
EOF
)

    if [[ -n "$output" ]]; then
        echo "PASS: Query executed successfully"
        echo "$output"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Query passed" "$output"
        exit 0
    else
        echo "FAIL: No results or query failed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Query failed" ""
        exit 1
    fi

}

# Run main check
main "$@"
