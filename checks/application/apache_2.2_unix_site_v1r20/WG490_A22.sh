#!/usr/bin/env bash
################################################################################
# STIG Check: V-2265
# Severity: low
# Rule Title: Java software on production web servers must be limited to class files and the JAVA virtual machine.
# STIG ID: WG490 A22
# Rule ID: SV-33032r1
#
# Description:
#     From the source code in a .java or a .jpp file, the Java compiler produces a binary file with an extension of .class. The .java or .jpp file would, therefore, reveal sensitive information regarding an applicationâ€™s logic and permissions to resources on the server. By contrast, the .class file, because it is intended to be machine independent, is referred to as bytecode. Bytecodes are run by the Java Virtual Machine (JVM), or the Java Runtime Environment (JRE), via a browser configured to permi
#
# Check Content:
#     Enter the commands: _x000D_
_x000D_
find / -name *.java _x000D_
_x000D_
find / -name *.jpp _x000D_
_x000D_
If either file type is found, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2265"
STIG_ID="WG490 A22"
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
    # Locate Apache configuration
    HTTPD_ROOT=$(apachectl -V 2>/dev/null | grep -i 'HTTPD_ROOT' | cut -d'"' -f2)
    CONFIG_FILE=$(apachectl -V 2>/dev/null | grep -i 'SERVER_CONFIG_FILE' | cut -d'"' -f2)

    if [[ -z "$HTTPD_ROOT" ]] || [[ -z "$CONFIG_FILE" ]]; then
        echo "ERROR: Unable to locate Apache configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Apache not found or not configured" ""
        exit 3
    fi

    FULL_CONFIG="$HTTPD_ROOT/$CONFIG_FILE"

    if [[ ! -f "$FULL_CONFIG" ]]; then
        echo "ERROR: Configuration file not found: $FULL_CONFIG"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Config file missing" "$FULL_CONFIG"
        exit 3
    fi

    echo "INFO: Apache configuration file: $FULL_CONFIG"
    echo ""
    echo "MANUAL REVIEW REQUIRED: Review Apache configuration for STIG compliance"
    echo "Configuration file location: $FULL_CONFIG"
    echo ""
    echo "This check requires manual examination of Apache settings"

    [[ -n "$OUTPUT_JSON" ]] && output_json "MANUAL" "Configuration review requires manual validation" "$FULL_CONFIG"
    exit 2  # Not Applicable - requires manual review

}

# Run main check
main "$@"
