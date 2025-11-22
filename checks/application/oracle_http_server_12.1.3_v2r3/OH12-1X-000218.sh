#!/usr/bin/env bash
################################################################################
# STIG Check: V-221455
# Severity: low
# Rule Title: OHS content and configuration files must be part of a routine backup program.
# STIG ID: OH12-1X-000218
# Rule ID: SV-221455r961863
#
# Description:
#     Backing up web server data and web server application software after upgrades or maintenance ensures that recovery can be accomplished up to the current version.  It also provides a means to determine and recover from subsequent unauthorized changes to the software and data.

A tested and verifiable backup strategy will be implemented for web server software as well as all web server data files.  Backup and recovery procedures will be documented and the Web Manager or SA for the specific applica
#
# Check Content:
#     1. Check that the following files and directories are backed up on a regular basis:

a) /etc/oraInst.loc
b) Directory identified by inventory_loc parameter within /etc/oraInst.loc
c) /etc/cap.ora
d) $MW_HOME

2. Confirm the ability to restore the above files and directories successfully.

3. Confirm the successful operation of OHS upon a successful restoration of the files and directories.

4. If the files aren'\''t backed up on a regular schedule or the backups haven'\''t been tested, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-221455"
STIG_ID="OH12-1X-000218"
SEVERITY="low"
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
    # Oracle HTTP Server - Generic Configuration Check

    if [[ -z "$DOMAIN_HOME" ]]; then
        if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
            DOMAIN_HOME=$(grep -i "domain_home" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d ' "')
        fi
    fi

    if [[ -z "$DOMAIN_HOME" ]]; then
        echo "ERROR: DOMAIN_HOME not set"
        echo "Please set DOMAIN_HOME environment variable or provide via --config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "DOMAIN_HOME not set" ""
        exit 3
    fi

    echo "INFO: Oracle HTTP Server configuration check"
    echo "DOMAIN_HOME: $DOMAIN_HOME"
    echo ""

    # Check if OHS is configured
    OHS_DIR="$DOMAIN_HOME/config/fmwconfig/components/OHS"
    if [[ -d "$OHS_DIR" ]]; then
        echo "OHS directory found: $OHS_DIR"
        echo "Components:"
        ls -1 "$OHS_DIR" 2>/dev/null || echo "No components found"
    else
        echo "WARNING: OHS directory not found at expected location"
    fi
    echo ""

    echo "MANUAL REVIEW REQUIRED: Review Oracle HTTP Server configuration"
    echo "This check requires manual examination of OHS settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "OHS check requires validation" "$DOMAIN_HOME"
    exit 2  # Manual review required

}

# Run main check
main "$@"
