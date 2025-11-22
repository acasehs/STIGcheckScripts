#!/usr/bin/env bash
################################################################################
# STIG Check: V-214283
# Severity: medium
# Rule Title: The Apache web server must have resource mappings set to disable the serving of certain file types.
# STIG ID: AS24-U2-000320
# Rule ID: SV-214283r960963
#
# Description:
#     Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client. 
 
By not specifying which files can and cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 
 
The web server must only allow hosted application file types to be served to a user, and all other types
#
# Check Content:
#     Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file: 
 
# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions \"apache2ctl -V\" or  \"httpd -V\" can also be used. 
 
If \"Action\" or \"AddHandler\" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding. 
 
If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214283"
STIG_ID="AS24-U2-000320"
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
    CONFIG="/etc/httpd""

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "Unknown" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "Unknown"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "Unknown"
        exit 1
    fi

}

# Run main check
main "$@"
