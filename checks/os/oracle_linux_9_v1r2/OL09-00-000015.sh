#!/usr/bin/env bash
################################################################################
# STIG Check: V-271439
# Severity: medium
# Rule Title: OL 9 vendor packaged system security patches and updates must be installed and up to date.
# STIG ID: OL09-00-000015
# Rule ID: SV-271439r1091029
#
# Description:
#     Installing software updates is a fundamental mitigation against the exploitation of publicly known vulnerabilities. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.
#
# Check Content:
#     Verify that OL 9 security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by organizational policy.

Obtain the list of available package security updates from Oracle. The URL for updates is https://linux.oracle.com/errata/. It is important to note that updates provided by Oracle may not be present on the system if the underlying packages are not installed.

Check that the available package security updates have been installed on the system with the following command:

$ dnf history list | more

    ID | Command line | Date and time | Action(s) | Altered    
-------------------------------------------------------------------------------    
   70 | install aide | 2023-03-05 10:58 | Install | 1    
   69 | update -y | 2023-03-04 14:34 | Update | 18 EE    
   68 | install vlc | 2023-02-21 17:12 | Install | 21   
   67 | update -y | 2023-02-21 17:04 | Update | 7 EE 

Typical update frequency may be overridden by Information 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271439"
STIG_ID="OL09-00-000015"
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
    PKG="available"

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
